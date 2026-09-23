#!/usr/bin/env bash
# Shared primitives for the UBS language modules (bead A1, library v1).
#
# Sourced by every modules/ubs-<lang>.sh:
#   UBS_MODULE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
#   source "$UBS_MODULE_DIR/lib/ubs-common.sh"
#
# Distributed and checksum-verified exactly like the helpers (HELPER_ASSETS /
# HELPER_CHECKSUMS in the meta-runner, key "lib/ubs-common.sh"), so a cached
# module always finds the library next to itself.
#
# Everything here used to exist in 4–7 drifted copies across the modules; the
# bugs those copies carried (LC_ALL assigned but never exported, json_escape
# bodies that break under `set -u` or skip control characters, silent text
# fallback for --format=toon/jsonl) are fixed once, here.

if [[ -n "${UBS_COMMON_LOADED:-}" ]]; then
  return 0 2>/dev/null || exit 0
fi
UBS_COMMON_LOADED=1
# Read by the modules and quality/test_ubs_common.py after sourcing.
# shellcheck disable=SC2034
UBS_COMMON_VERSION="1"

# ── Locale ──────────────────────────────────────────────────────────────────
# Child tools (sort, grep, awk, rg) must see the C locale for byte-stable
# ordering and matching; Python helpers keep UTF-8 I/O regardless.
ubs_export_locale(){
  export LC_ALL=C
  export LANG=C
  export PYTHONIOENCODING=utf-8
  export PYTHONUTF8=1
}

# ── Time / failure ──────────────────────────────────────────────────────────
ubs_now_ms(){
  if [[ -n "${EPOCHREALTIME:-}" ]]; then
    local s="${EPOCHREALTIME%.*}" us="${EPOCHREALTIME#*.}"
    printf '%s\n' $(( s * 1000 + 10#${us:0:3} ))
  else
    local ns; ns="$(date +%s%N 2>/dev/null || echo 0)"
    printf '%s\n' $(( ns / 1000000 ))
  fi
}

# ubs_die MESSAGE [EXIT_CODE=2]: environment/usage errors exit 2 by contract.
ubs_die(){
  printf '✗ %s\n' "$1" >&2
  exit "${2:-2}"
}

# ubs_deliver_file SRC DEST LABEL: copy SRC to DEST, or report why not.
#
# Issue #106: modules delivered their requested `--summary-json` /
# `--report-json` with `cp … 2>/dev/null || true`, so a missing or
# non-directory parent produced exit 0 with no artifact at all — a consumer
# gating on the exit status archived nothing while believing delivery
# succeeded. Analysis completion and artifact delivery are separate outcomes:
# this returns 1 on any delivery failure so the caller can fail the run.
#
# The write is staged beside the destination and renamed into place, so a
# failed write never truncates an artifact that was already there.
ubs_deliver_file(){
  local src="$1" dest="$2" label="${3:-artifact}" dir tmp
  dir="$(dirname -- "$dest")"
  if [[ ! -d "$dir" ]] && ! mkdir -p -- "$dir" 2>/dev/null; then
    printf '✗ cannot create the directory for the requested %s: %s\n' "$label" "$dir" >&2
    return 1
  fi
  if [[ ! -d "$dir" ]]; then
    printf '✗ cannot write the requested %s: %s is not a directory\n' "$label" "$dir" >&2
    return 1
  fi
  if ! tmp="$(mktemp "$dest.ubs-XXXXXX" 2>/dev/null)"; then
    printf '✗ cannot stage the requested %s in %s (not writable?)\n' "$label" "$dir" >&2
    return 1
  fi
  if ! cat -- "$src" >"$tmp" 2>/dev/null; then
    rm -f -- "$tmp" 2>/dev/null || true
    printf '✗ cannot write the requested %s: %s\n' "$label" "$dest" >&2
    return 1
  fi
  if ! mv -f -- "$tmp" "$dest" 2>/dev/null; then
    rm -f -- "$tmp" 2>/dev/null || true
    printf '✗ cannot replace the requested %s: %s\n' "$label" "$dest" >&2
    return 1
  fi
  return 0
}

# ubs_with_timeout SECONDS CMD...: run CMD under `timeout` when available
# (0 = no limit); exit status is the command's, or 124 on timeout.
ubs_with_timeout(){
  local secs="$1"; shift
  if [[ "$secs" =~ ^[0-9]+$ && "$secs" -gt 0 ]] && command -v timeout >/dev/null 2>&1; then
    timeout "$secs" "$@"
  else
    "$@"
  fi
}

# ── Asset integrity & helper resolution (bead E1) ────────────────────────────
# ubs_sha256_file FILE: compute sha256 digest of FILE (prints hex string).
# Returns 0 on success, 1 on missing file or unavailable hash tool, 3 when the
# hash tool ran and failed; a signal-like status (see below) passes through.
#
# Deliberately no pipeline: callers run this inside `x="$(...)"` after the
# module has set `shopt -s lastpipe`, and bash can segfault that subshell when
# SIGCHLD arrives while append_process() is linking the lastpipe entry into the
# job's process ring (observed on bash 5.3.15). See compute_sha256 in ubs.
# ubs_sha256_status_is_signal_like STATUS: bash reports a child killed by
# signal N as 128+N. A status in that range is only signal-like (a tool may
# exit with it too), so it earns a bounded retry, never a verdict.
ubs_sha256_status_is_signal_like(){ (( $1 > 128 && $1 <= 128 + 64 )); }

ubs_sha256_file(){
  local file="$1" out rc=0
  [[ -f "$file" ]] || return 1
  if command -v sha256sum >/dev/null 2>&1; then
    out="$(sha256sum "$file" 2>/dev/null)" || rc=$?
  elif command -v shasum >/dev/null 2>&1; then
    out="$(shasum -a 256 "$file" 2>/dev/null)" || rc=$?
  elif command -v openssl >/dev/null 2>&1; then
    out="$(openssl dgst -sha256 "$file" 2>/dev/null)" || rc=$?
    out="${out##* }"
  else
    return 1
  fi
  if (( rc != 0 )); then
    ubs_sha256_status_is_signal_like "$rc" && return "$rc"
    return 3
  fi
  printf '%s\n' "${out%% *}"
}

# ubs_sha256_or_die FILE LABEL: sets UBS_SHA256 to FILE's digest or exits
# via ubs_die with a message that names the real failure. A signal-like status
# (typically the command substitution killed by a signal) is retried a bounded
# number of times: it says nothing about the file, and reporting it as a
# missing tool sent users to install sha256sum while it was present.
ubs_sha256_or_die(){
  local file="$1" label="$2" rc=0 attempt
  UBS_SHA256=""
  for attempt in 1 2 3; do
    rc=0
    UBS_SHA256="$(ubs_sha256_file "$file")" || rc=$?
    ubs_sha256_status_is_signal_like "$rc" || break
  done
  (( rc == 0 )) && return 0
  if (( rc == 1 )); then
    ubs_die "unable to compute checksum for $label (install sha256sum, shasum, or openssl)" 2
  elif ubs_sha256_status_is_signal_like "$rc"; then
    ubs_die "checksum subprocess for $label ended with status $rc on all $attempt attempts (how bash reports death by signal $((rc - 128))); the file was not judged" 2
  fi
  ubs_die "checksum command failed for $label (status $rc)" 2
}

# Pinned helper and asset checksums for standalone module execution (bead E1).
# Auto-generated by scripts/update_checksums.py.
if ! declare -p UBS_HELPER_CHECKSUMS >/dev/null 2>&1; then
  declare -g -A UBS_HELPER_CHECKSUMS=()
fi
declare -g -A UBS_COMMON_HELPER_CHECKSUMS=(
  ['contract.json']='93cd47cd7142c954c4d6a34a62e6786d1512762b9352098000c8415c86912203'
  ['helpers/async_task_handles_csharp.py']='d5b029f8fe9452fafba22a9bd6a26db9952b8072fdee224d976f140c824af93d'
  ['helpers/cfg_test_only_modules_rust.py']='27dbd7f843d546c07743bf642f4dfa9912f0c205007c583c5e18d6b52fa39e68'
  ['helpers/resource_lifecycle_cpp.py']='886611236e8230551ad302bc2b91894935adb29f427dff92c5e0e18370e9f582'
  ['helpers/resource_lifecycle_csharp.py']='e268a5472ddbf3039186ce640c0d5c816727c9599dd644cab08ad53c19962426'
  ['helpers/resource_lifecycle_go.go']='53d441968ed81b7947adde9838d0cc09d04effa84784d33e52bcdd60a78eec0d'
  ['helpers/resource_lifecycle_java.py']='99ee1a5d4cf28ec0ad4907308fe494cb71501957e17cae056a36095783db1892'
  ['helpers/resource_lifecycle_py.py']='f736488bdd243fa0b142dc07193d43739bd69f819e5276eeaa81e6c7cb5e6813'
  ['helpers/resource_lifecycle_ruby.py']='9756c313b2718337cf3ac35aadc29e5bf0077f4474c8c01e01a7de0bf864b185'
  ['helpers/resource_lifecycle_swift.py']='c88e2611d532915bc59c7169d70c7b1585fdfdb7127ca5eda5214310821bbc9d'
  ['helpers/type_narrowing_csharp.py']='58fc5048b3851664876859a16e807600b0ec5c2300bdefed39d674f9b07b1ee1'
  ['helpers/type_narrowing_kotlin.py']='a50e5060d1784b53e27cfc4dba745011fb2e3b7bd15176f91f0477eced54d321'
  ['helpers/type_narrowing_rust.py']='155095a92a5a90ef88d668a88236f7d8611ec6f94aad42615eacdbe92b21e163'
  ['helpers/type_narrowing_swift.py']='d83d064db4418d4c245e6bcf7a386280e27c0ebdc57a7c4f6c32443887d6eeea'
  ['helpers/type_narrowing_ts.js']='67bb540f1b85993336f06d712a5c1e6f28ee2201d4404a8e00279d01b9859637'
  ['helpers/ubs_core/__init__.py']='b75e6b0fd574ac97252fe667280d5807ce1fc6726b1a92980796e46e8de3592f'
  ['helpers/ubs_core/__main__.py']='4aed5b835f04ba3a51b13a650b15dc05e2e43436e9e8be19000551999172639e'
  ['helpers/ubs_core/analyzers/__init__.py']='090badfe6b8be4c60de495a74b362acff5a4d9f8461dbb56d5b6718783e39b86'
  ['helpers/ubs_core/analyzers/async_event_emitter.py']='eaa22abf72e33569b102b9b6425082e409f8191b8e4e0dc30a16c64d3e5edbfd'
  ['helpers/ubs_core/analyzers/async_event_listener.py']='fe7c29dd3d98efdb88bb7c07176598e9f496c21fbee69d9c41049058bf83fa1b'
  ['helpers/ubs_core/analyzers/async_flatmap.py']='b00df497f866c746c6e58f7c9119e49e680e6ff4bafbe2ad7df5319ba58de317'
  ['helpers/ubs_core/analyzers/async_foreach.py']='f60bb98a5d767c83704b2539b7bdcb77d2dc95d4d8f48175e98714742092fc7a'
  ['helpers/ubs_core/analyzers/async_handles_csharp.py']='830d3853356dd3f631bc3ec2b949dc51f46ac8e71cb812948713bede783c898a'
  ['helpers/ubs_core/analyzers/async_jsx_handler.py']='e1bd2c9e970304c43caabbad44271319e9769873e3ae032bb6de657302bcfc20'
  ['helpers/ubs_core/analyzers/async_map_awaited.py']='fddab57e2d78a9a588196446b4cfe89009398b3058eebc0ad7a3ee607ca87c30'
  ['helpers/ubs_core/analyzers/async_map_ignored.py']='c16348c729732d37143729167a128304102d69919de725ee5a3d6bd5388b6168'
  ['helpers/ubs_core/analyzers/async_predicates.py']='8a68cfcc012b6220e5472222979537f0c6016874de0cd6c72ee626ffdc907628'
  ['helpers/ubs_core/analyzers/async_promise_all_foreach.py']='bc2e00a5781a8ea5c395c1249f9404cc00b38119ea70bc21e1e7fc4f7395c008'
  ['helpers/ubs_core/analyzers/async_promise_all_map.py']='da1f6024e29eba09b84536d9d5046ae9b627b24d67027d89382915b19393e5c8'
  ['helpers/ubs_core/analyzers/async_promise_executor.py']='093cbd0bc705b696e8a222e9bc9307ab450e5fb180276cd73f835a6e79dece4a'
  ['helpers/ubs_core/analyzers/async_react_effect.py']='1b8a90800d1f9cad2e934940103123f67eba054ebe530a148089d64801b88c44'
  ['helpers/ubs_core/analyzers/async_reduce.py']='82721540acae9350f433fb7502af2e863d8ac7a749649532e01081cc6774fe3e'
  ['helpers/ubs_core/analyzers/async_sort_comparator.py']='7410aaa138a3a9204a0e47fc81ed9942f14031728edd21a991373df5d17c225b'
  ['helpers/ubs_core/analyzers/async_timer.py']='b24c3462cfc469c330ecfc63ff63e2d20cc2b92165f627dc148ac76bbf105ea4'
  ['helpers/ubs_core/analyzers/cfg_test_only_rust.py']='5269b88dd078cae71d1a3c2e23523032507ac49265560dd0c27273c41c38c5aa'
  ['helpers/ubs_core/analyzers/ctcompare_go.py']='67b66f44a697628c36dc5499aa40e9bfd737391d72f6940a623ef427d7a4e64d'
  ['helpers/ubs_core/analyzers/ctcompare_js.py']='462e601e16b1359711b50c241fab8911157f5efa341eba533c4519a2464ce04f'
  ['helpers/ubs_core/analyzers/ctcompare_py.py']='720fcd492c865ac3b947a7917037207907b79c99e752bed5da21435a0e375c50'
  ['helpers/ubs_core/analyzers/ctcompare_rust.py']='64e19bbfabeff7ee4f0d08f58a5540da78236e32654a188af7b5a5138f09a7d9'
  ['helpers/ubs_core/analyzers/guards_generic.py']='61ef81e6255aa3c09ed175648f8cbd99ee2bff9a98ed3c968781533beb91b4a5'
  ['helpers/ubs_core/analyzers/guards_js.py']='4a27ccb62965a474c40de644f15cf2e4018642f42971501c480d7015c399eafa'
  ['helpers/ubs_core/analyzers/guards_py.py']='beb7d42b8b34a27b28107b7f557e206aed6a6ad26454c8b0dfe6b7271dd4d1de'
  ['helpers/ubs_core/analyzers/guards_ruby.py']='7446bbbb5e43643f761bf4b2efccbb9acf46a47afc2a7db69d2fc784482d71db'
  ['helpers/ubs_core/analyzers/lifecycle_cpp.py']='245804579718f5c4beb3bb7e3522a628e7338d41127ca03febfdbaad064bb55b'
  ['helpers/ubs_core/analyzers/lifecycle_csharp.py']='2bdfed38db8c8a5cd7327b45ac3edeaa15e6740563abdd3054e0b4fb9426b425'
  ['helpers/ubs_core/analyzers/lifecycle_java.py']='5b1d60fbe75a0b3f1ae25cc2c11210e5899ddbca0afd4047e3624789b561ebe2'
  ['helpers/ubs_core/analyzers/lifecycle_py.py']='84b4fb6371c00d9b787e26feeface5cd1fd99c142d9ad840f96d81ce33647c15'
  ['helpers/ubs_core/analyzers/lifecycle_ruby.py']='b5d928e4dc9f504c3c427f51463e5ad6bfe69f86e9cc6f591ca8757d5ce053cd'
  ['helpers/ubs_core/analyzers/lifecycle_swift.py']='51b065554c6b5310ad66f0fd862f113d81cb6822faf23f57215cbf953e0b2c34'
  ['helpers/ubs_core/analyzers/narrowing_cpp.py']='5681c018729ec37129d808d9f65ec51e368c060e0b0ce4d363b461afcd4d9345'
  ['helpers/ubs_core/analyzers/narrowing_csharp.py']='436ce2e1f5a5e1384915b54d67fcfaae7156d607331bbaa1f27680610a6ccd17'
  ['helpers/ubs_core/analyzers/narrowing_elixir.py']='40af9808f556825b6ce81397c37d5ed5100ce34cbf2a7ea291be4c7f280ff7ee'
  ['helpers/ubs_core/analyzers/narrowing_go.py']='123895581adf37f5670b8e8f3b21bc2bf75f3495e82077a80039718324be5771'
  ['helpers/ubs_core/analyzers/narrowing_kotlin.py']='d84c7099d32ccefbef2bdc253b3473ccbfa2f4532f55139ebff46de01c81ee5e'
  ['helpers/ubs_core/analyzers/narrowing_py.py']='60a2381463f1e7e8ff66e9a6a8564baa2aff1d10c2f107e3d24b23a4341bde9a'
  ['helpers/ubs_core/analyzers/narrowing_ruby.py']='4af90a09f6336c242dd5eb58efec6df8ab12a0a3dbe2e282a34e55d7723d2555'
  ['helpers/ubs_core/analyzers/narrowing_rust.py']='54ec29f4297cbe37aec4cdaab276a6880bb16fd93377ed060e90c5de98261b12'
  ['helpers/ubs_core/analyzers/narrowing_swift.py']='2a7971f6f6a858eb73d1f898a6fdd039a56be405222877eae3890a6343a52a73'
  ['helpers/ubs_core/analyzers/regex_swift.py']='5b9deaf28d737938576007d17cd3a9e7c99f21d4fed597aefb0e0173f3507bd4'
  ['helpers/ubs_core/analyzers/sec_archive_entry.py']='a5f6994b29bb6b86f40c4d2d9d5b30c3049f38b2c99af764aacddbb4c86048c4'
  ['helpers/ubs_core/analyzers/sec_cookies.py']='46292c8cb942b419151251dc219c2f8cdbf442894a11734d3d799180f1f05046'
  ['helpers/ubs_core/analyzers/sec_cors.py']='a09a66a22ca6bc31c299875c8a489f5ae678bbc7ea3e1f91d38a86d9416a85e0'
  ['helpers/ubs_core/analyzers/sec_dangerous_html.py']='c0cca37214580953dce23d6789837002faea3162e5e0d52a822b134f40165d1d'
  ['helpers/ubs_core/analyzers/sec_fetch_abort.py']='fec59eeab6a1093584b48c7c24ea096632aeac50dfae73e1635fad4d06e75d13'
  ['helpers/ubs_core/analyzers/sec_hardcoded_secrets.py']='6536a51672f5dbac9d39bb1c7339246a7e98a263fa7ebc2d3b680c673110b9b6'
  ['helpers/ubs_core/analyzers/sec_header_injection.py']='c88097ebd1a353035a6034f2c9e0a10ecd103a4de3a3d40c3472257d6c2cf2ae'
  ['helpers/ubs_core/analyzers/sec_host_header.py']='7c57990166b207b58f622badac27765a58e456620f46350b36b3d60e2192f2ff'
  ['helpers/ubs_core/analyzers/sec_jsx_target_blank.py']='0c03978f8974c41b1cae846989b4a97c584c4de3f5f8e935089ba10fa47f6d42'
  ['helpers/ubs_core/analyzers/sec_jwt.py']='fbbbbc4362d81e2dc7b9e5af990deea5e8d075b22022533b1cb0e726bc79a57c'
  ['helpers/ubs_core/analyzers/sec_message_origin.py']='ebee1c0218a398462d2ee6c037c0dd892ed9f7ca907aa7b9290cc2d1fb3c78cf'
  ['helpers/ubs_core/analyzers/sec_open_redirect.py']='6696e059909727214bd5eaa4536ab9efb297469d9cea6d14eb193bbd2756a761'
  ['helpers/ubs_core/analyzers/sec_path_traversal.py']='0ae9dbcba9fbf75a5ac96bf93ee14cf39adbdf833d5d2b9640b2089b66c16a65'
  ['helpers/ubs_core/analyzers/sec_post_message.py']='1de92720892adf9efebbb593bc90c0733aefbcfd19bd9cfd23450ae4b4ca0ab2'
  ['helpers/ubs_core/analyzers/sec_prototype_pollution.py']='e21ed1bf684a39dd2e26f6211d3802032187b31da216f22fb4b43e7a78e57679'
  ['helpers/ubs_core/analyzers/sec_request_body.py']='50ac1d60373be71c6a715a09498289d98985e665f6e9b57ac498eecf8dbc67cb'
  ['helpers/ubs_core/analyzers/sec_request_regex.py']='2eb6bdf1f79b2f4eaa5a458e6bf22bbbfffd91dcb1b61bd85e38cd2957b4bade'
  ['helpers/ubs_core/analyzers/sec_reverse_proxy.py']='8ab593955cbaf09ffe9fe31b41e93525d67a6171c467661fc19a359a79755d99'
  ['helpers/ubs_core/analyzers/sec_sql_injection.py']='a584db1cbdb7f462e624b8b6626de5d7e5af4412faa07232932c940b7332d473'
  ['helpers/ubs_core/analyzers/sec_ssrf_fetch.py']='3313c31cf725e3886a3176b3da37511bba366da874d3aa75d1872bdd70523659'
  ['helpers/ubs_core/analyzers/sec_tls.py']='6a139ff4413ebcc972a6cadd13942b8b3e4c7b8e0d66b375da2949bd41a98c88'
  ['helpers/ubs_core/analyzers/sec_weak_random.py']='0bd64b6935d6d8c7766e588ec61fbf3ef642114262cc9abcd73f871c014bb918'
  ['helpers/ubs_core/analyzers/spec_block_function.py']='5158fb1a4e5f0f55b1013da2704a0c8187dd0074c14ef1d99224f4a85ec57762'
  ['helpers/ubs_core/analyzers/spec_division.py']='9c7f13c5ce54f04a20bfdb93d75b95c859c258da3d57a420d6a8dc948974a8ab'
  ['helpers/ubs_core/analyzers/spec_hooks.py']='e5310726b95ba96348309b759a4766727fb44f2832cff78c7c73aefab918198d'
  ['helpers/ubs_core/analyzers/spec_switch_fallthrough.py']='7bfcdfb49cd0d290d0fa09d360b04512db0b657b344b9891c031e68736b57dd5'
  ['helpers/ubs_core/analyzers/spec_typeof.py']='5569be74cdadf83d6a1fda466ad304247d3fd8259919c086343cae0971547a17'
  ['helpers/ubs_core/analyzers/taint_cpp_redirect.py']='4a854c5d2338d661a7a42deee94e32081f9bd28e442574ab0b427e927c397ce0'
  ['helpers/ubs_core/analyzers/taint_cpp_traversal.py']='561f29f975299f48e1c97634810621ee96f94e7db5a324eec6b2e2928b123640'
  ['helpers/ubs_core/analyzers/taint_csharp_redirect.py']='fc8cfe379e8748b2205b6abacfd4128c9940898f1e105ab51d5d953b8e2b819d'
  ['helpers/ubs_core/analyzers/taint_csharp_request.py']='8f7417712afe5399d18918b2b4ddb2f46ac4120ee53dabb2c0cf29f03806ee61'
  ['helpers/ubs_core/analyzers/taint_elixir_redirect.py']='428bb81ded78221690e9e9f5fe0419104cc611dc7c4b9d6f852098d8591ee22c'
  ['helpers/ubs_core/analyzers/taint_elixir_traversal.py']='e67b32b56c0526125b5ffecbe8ba1de6b209b0a1378a341b5a4fd31a8a353d63'
  ['helpers/ubs_core/analyzers/taint_go.py']='e212408bcca3a46a86a1ec8890303c8d103caf8d0b577b91646d1d4f87ac4901'
  ['helpers/ubs_core/analyzers/taint_java_redirect.py']='39fb0763494056f30a450f8c9296b02effc9a18a06d6560b8beeefa67310dc90'
  ['helpers/ubs_core/analyzers/taint_java_traversal.py']='c73cbe618a30944ca491dac09aa667f3e2599b1c54f95a8a9747bdad9135dcfd'
  ['helpers/ubs_core/analyzers/taint_js.py']='e1c4c8fd6a016ddeebb038d7e943331d9b9fa90ed1cb334acc46356c2a5b5989'
  ['helpers/ubs_core/analyzers/taint_py.py']='ac12def7a0ec38207cc6f37ddf5c0ee2892b12cad13211d50d652b1fdc068910'
  ['helpers/ubs_core/analyzers/taint_ruby_traversal.py']='ecff0b7c2607695048741f48551209464e80db385415490d1ebd92227a9813e0'
  ['helpers/ubs_core/analyzers/taint_ruby_url.py']='4453f0434f95879880777748ab7d6041fa81588bf281c9ec9a2183c2cc706c63'
  ['helpers/ubs_core/analyzers/taint_rust.py']='d7b70068d53f76e78f3bdded9a6eda734987c6e2de59ea9739682ca99deb30fa'
  ['helpers/ubs_core/analyzers/taint_swift_redirect.py']='6ab6fc656880e2f8fb61ec563d3b7811e128601417d7b7ba7477fcb24197babd'
  ['helpers/ubs_core/analyzers/taint_swift_traversal.py']='4fc6e54f7f55ea1006ecf77c60df301cc29d9cd450a821bf0e3de7436a3519f4'
  ['helpers/ubs_core/bash_rules.py']='17eda47be732993bb1f636cf0375823042c1701646cd656cf9735ae8dc298882'
  ['helpers/ubs_core/bash_scan.py']='a2c65de4e90a4c1aad47068b83a030ff2abd42214f1e1c6dc30f3a01f4cc04d4'
  ['helpers/ubs_core/cache.py']='121008fdd270030ea2ab8108bd16bbb82598750baa1b6e5d40ab48442afe2458'
  ['helpers/ubs_core/cli.py']='e51b45718093dd0c03b4e85756365ec821619ee0dce38e416be44244fb555151'
  ['helpers/ubs_core/cpp_detectors/__init__.py']='b74840d5af31f44ac13703f3c66f6968af4207c9ce08f3c0ae1010cd62c4fabd'
  ['helpers/ubs_core/cpp_detectors/archive_entry.py']='adb8693a5ac0370aa0bc9f7aabbb05eb63da64fac792e1451f15b352f870a114'
  ['helpers/ubs_core/cpp_detectors/async_errors.py']='e3c03636656ec7477e940520806c8080326ec7700b0e0cb6d702c8ef0a0ed713'
  ['helpers/ubs_core/cpp_detectors/header_hygiene.py']='5b894ce2805204600acab3cd43dc33844ee11fbed70bb59b3f3dac10c46b0978'
  ['helpers/ubs_core/cpp_detectors/header_injection.py']='afa0e95af70582917593aa1d88270265348a7a92d8f7d99394a3c6ce6cfc61e3'
  ['helpers/ubs_core/cpp_detectors/outbound_url.py']='a6d73557c0176facc93f79b761ffb7d87479d0cf1331a981d4e7aeb784ff9347'
  ['helpers/ubs_core/cpp_detectors/perf_io.py']='ce1652f1df907eef5045dd3bf7fce90e1cc9b914d34a8ad1297c19b14827b26e'
  ['helpers/ubs_core/cpp_detectors/quality_markers.py']='576cc873818cd5c4a5c5492715486adc90f20a91b2d3f1cdb59f73e5730e0a24'
  ['helpers/ubs_core/cpp_detectors/weak_random.py']='829b33bba2b0045b7a52b6ee205caf0c649f6defdcdabb531954e855938cc82d'
  ['helpers/ubs_core/cpp_patterns/__init__.py']='e2837237df1ae19ebac33c1ad27943315d86d0986972909cc79830b7cf11b94c'
  ['helpers/ubs_core/cpp_patterns/concurrency.py']='8a46b04930ab6a9185807f48071a6cfddf18ffb5a41dd593c3f635e8c7c08243'
  ['helpers/ubs_core/cpp_patterns/debug.py']='4ec4eb9b8b27d6bfd32c91290cd65470d5ad9c7bbd3b466d2816ba706deb50f4'
  ['helpers/ubs_core/cpp_patterns/exceptions.py']='827703aad5a34a8fb9cbddc01a6284a96f7f8369f87cfe4259f1cff43bec7884'
  ['helpers/ubs_core/cpp_patterns/headers_stl_io.py']='cf774ff009fc2c22b66c14be52955b652f5d24cfcd8e9bfff64ff90e25499b9c'
  ['helpers/ubs_core/cpp_patterns/macros_cmake.py']='aad071a77c7f4a27387d06acc7d62880e0b4de8bf4c28d0f84d46a08e61dc500'
  ['helpers/ubs_core/cpp_patterns/memory_raii.py']='ec6bc9af91847e7c059b04cbcfd4a0298577c9a043ad63b220ce82b5a4302be7'
  ['helpers/ubs_core/cpp_patterns/modernization_pointer.py']='5d01f475b034b26e4d193c8b176f51b9cd5de8df0a874dee8f59b7751a74ab06'
  ['helpers/ubs_core/cpp_patterns/numeric.py']='fc04ecf9b703ab8f5aadd435fa5a137c7541028b1c92e74b6d2dc5448fb58444'
  ['helpers/ubs_core/cpp_patterns/ub_zone.py']='61b92efa13a0c9876ef657d9e56c600ef15f8e3486ad0b64ff4f4ad4c26327aa'
  ['helpers/ubs_core/cpp_rules.py']='c624f73f3ddab13aafb6026875fd9211d2fef4efe71b866e46c1dc6023049255'
  ['helpers/ubs_core/cpp_scan.py']='80ed4d85824f0ef27ac9393124183864b3c877938aa9f6315f0b823b66596fa9'
  ['helpers/ubs_core/csharp_ast.py']='0a581c0d1c80edb60bb867b1177371060d25f98c4da80fb3d0afba67435b72ce'
  ['helpers/ubs_core/csharp_detectors/__init__.py']='bf8a8383f6143a5e585e78fec84580e86c40ee180f05a7bbce386c496d420063'
  ['helpers/ubs_core/csharp_detectors/_common.py']='19c996f1744588d23085e986e50a461089af0c8d350fdd4e950d6f71074e4dac'
  ['helpers/ubs_core/csharp_detectors/archive_extraction.py']='a231403de45648699d14169d97a12eb671551ee4dada8de30fcb5c3d8525793f'
  ['helpers/ubs_core/csharp_detectors/header_injection.py']='d44c5fb535094e7801ee60ad048b6970e976fed088b34d5893bf42d8dabc7e46'
  ['helpers/ubs_core/csharp_detectors/outbound_url.py']='964ed09a07bbc5a00034c975086da7ec1315fc61267ff1bb4a1b26eb8440f64e'
  ['helpers/ubs_core/csharp_detectors/security_randomness.py']='ad7caed715df15c6fe0e9a4cc95c40081df663af0a5134275a71c265844b0dc4'
  ['helpers/ubs_core/csharp_patterns/__init__.py']='1dfc28708bd9a28b904a2665f0532439f4b83c6ef3a16ea8cbdfa2083240bc57'
  ['helpers/ubs_core/csharp_patterns/_table.py']='bb656efe1ad9c4546ebcafefd23128e1e3f14f4ef9fe1f60e9491ffe2c516ef1'
  ['helpers/ubs_core/csharp_patterns/async_locks.py']='e5e8bd55f6ba99af0db0fb4ae2cc111e2d93094fa83bb27a3934511c474da400'
  ['helpers/ubs_core/csharp_patterns/concurrency.py']='de4834bc244b0337d3428554ff2613eb297657ae2ebc55659095afb138934f71'
  ['helpers/ubs_core/csharp_patterns/correctness.py']='927a55db74451ee875d9db082d6cfb2caafc9587e7e60685a7eeae6d8772a9c7'
  ['helpers/ubs_core/csharp_patterns/foundations.py']='9c581ac68509fe2f8f708788d80bb38f1b24266350fa30eb3b48d27a09b6cb9f'
  ['helpers/ubs_core/csharp_patterns/quality.py']='eac32fcf8ce9ce593f19c2089abf89916b72cbd6ea1005ac056d23a178bb69cc'
  ['helpers/ubs_core/csharp_patterns/security_rg.py']='456a7b2ad7855b36376dfa8daa34c1d6449eb7b07d86a2b5b654180307665ec1'
  ['helpers/ubs_core/csharp_rules.py']='a18537e24ade02da86fcae82e8f92d1e7e702ea63a0c77b6fd2ea865cbb27a9e'
  ['helpers/ubs_core/csharp_scan.py']='8ca538011653da946629a275dc3cf046e25d373d572ec7882bd9549384bbe2ed'
  ['helpers/ubs_core/elixir_ast.py']='273ef92c9cdd7b1a6deb905d7ce63d0a36225646670e28f0390b27f3f6a31e4c'
  ['helpers/ubs_core/elixir_detectors/__init__.py']='9e08cda01f060bb0e804ad7276b680e12f8f7451158b2ba443bc001d2f086faa'
  ['helpers/ubs_core/elixir_detectors/_common.py']='ffedf7e7db651bb0738e999fa2cb6f175cd97b52fa3bc857a809be54ac887eee'
  ['helpers/ubs_core/elixir_detectors/archive_extraction.py']='90acf3bc6a1c96577ae43f10309326e67699b18475011fec01cda4d49529a9ea'
  ['helpers/ubs_core/elixir_detectors/config_runtime_exs.py']='015a6946ce0ae56280e14bcbbdc756a78f1aca1cd3410193dd84edfd7b48dcb1'
  ['helpers/ubs_core/elixir_detectors/hardcoded_secrets.py']='be97a18a6bfd572b9f0c0e6a031331be0ccdc85c06409dedd09a8c67b8fd698f'
  ['helpers/ubs_core/elixir_detectors/mix_lockfile.py']='68fda905182218603ad78cfa65910d9b219cc9bcea34c8fadd6c1a749106b5ed'
  ['helpers/ubs_core/elixir_detectors/outbound_url.py']='851158fd493d2a7a60a64bc8242fb58e069d538b21f28a7f4c06d36254e44dbe'
  ['helpers/ubs_core/elixir_detectors/response_header_injection.py']='4de3985f930862239fdacecef0854c76514926d2a1d7e90b659c0b72a25ac3d6'
  ['helpers/ubs_core/elixir_detectors/security_randomness.py']='8826d5378ba5c50de0ab8b392da8dbfe29197e43843cf76072e5562bfe424a93'
  ['helpers/ubs_core/elixir_patterns/__init__.py']='7148f31ca91d7ec307a64dbcc99bb9ee241580143719b48c05aba2fa53ef8641'
  ['helpers/ubs_core/elixir_patterns/debug_quality.py']='a1c59c62bf985511f25388c83d8e2d69fd0cb9dfdc49931a93a972e556553c9e'
  ['helpers/ubs_core/elixir_patterns/ecto_concurrency.py']='5b62edda642fde35481d24c9fbe1e3af10bf4892019eb68be8d88f7f2970e410'
  ['helpers/ubs_core/elixir_patterns/foundations.py']='5d82afa7c982924d3df36a1702158dc4e59ff7721ad396826fbb60dab6d02c66'
  ['helpers/ubs_core/elixir_patterns/mix_deps.py']='bbf8f009f9d25873c918e9fcb4b23b185d9f9a7e467bd36d1638a53576d42127'
  ['helpers/ubs_core/elixir_patterns/perf_misc.py']='5248f2e9c2b845736a9d95cf301d791f474f1d82fd063f170c4c702f54960f7a'
  ['helpers/ubs_core/elixir_patterns/phoenix.py']='533afcfc1a90e24ad2ce002a76d2433ef2203f7034de9047a84c7a67eb0f36a4'
  ['helpers/ubs_core/elixir_patterns/security_rg.py']='551c5357954168766253ec46bf2095b7497d500c01d2a71fbbb77849461c51c9'
  ['helpers/ubs_core/elixir_rules.py']='3f8ca9a8d1cd898588005bb925b5b931d8d3947d41e7c235c48b9d8033ed65e4'
  ['helpers/ubs_core/elixir_scan.py']='d61aa7f4f865e18858a5cb43c4a51b671345e9505bafc10896c0cec598877ead'
  ['helpers/ubs_core/explain.py']='c2c440b5ef72c8f5cc87342d3ed6f8eee530bdf71eb425e7f4f771b4df4dc6ba'
  ['helpers/ubs_core/external_tools.py']='8aed8e93c5ab5260647b86f9439a0b9443c93d3a53e99a6e963045c68a1b44ba'
  ['helpers/ubs_core/findings_merge.py']='a5b718082d9a67f586388273eafa589db653c8497801d96be3a4d168a32a35a6'
  ['helpers/ubs_core/go_ast.py']='7cb83f089c6fa8b562483c4d84bafa22bb4273c8b5d3dab5079825f74385527b'
  ['helpers/ubs_core/go_detectors/__init__.py']='70cc7219036b6d704d9a9e9414c623b4d0eb65ef26e12aac19c8ba6aa055ba41'
  ['helpers/ubs_core/go_detectors/archive_extraction.py']='f57f33494fed091791358f3ccfa1040df43a8a0c39801fc533b2beebcfcd8181'
  ['helpers/ubs_core/go_detectors/cookie_security.py']='c2d6d4e0708c972b71c52627a3211525bc17ab448e68de9b556d3090585997f4'
  ['helpers/ubs_core/go_detectors/cors_credentials.py']='9af32be5bcae4bc051229d835bf21fdce20973746a2669ccb00dffc1261df401'
  ['helpers/ubs_core/go_detectors/hardcoded_secrets.py']='be700a8f5043b050895327a664696886baeb728e969a56ca820e8f5c1c9cb623'
  ['helpers/ubs_core/go_detectors/header_injection.py']='5eb25e3cde4ed4ec62e929eb03640640d5a691765c92c674c43fde10a35969c1'
  ['helpers/ubs_core/go_detectors/host_header.py']='9c0f3a41a0350fc5c77df2dcdba0a21792a8e4f56ce7ceddb2adecaf7f8b01a0'
  ['helpers/ubs_core/go_detectors/jwt_verification.py']='5d992745b5a2f1936b1f2f4fab904d977d2f0f981e37cbd29b3a43f4b349a9a9'
  ['helpers/ubs_core/go_detectors/open_redirect.py']='36ad1fd5cdcd4511d9714e32caafe41d32ccd589593208a37eae5cb748a3d08d'
  ['helpers/ubs_core/go_detectors/outbound_url.py']='eaac8bb45a47889dbd015cdd84f7cc16049a6898cecdab62e01a5a469582e100'
  ['helpers/ubs_core/go_detectors/path_traversal.py']='bd81b3c7cccd0a08a36478e6615ecf93eb07ae586926b0968012955836530af8'
  ['helpers/ubs_core/go_detectors/request_body_limit.py']='865d1b5534117160d0718a562748e17d735cc6236078ea5e6af0e681a14cb819'
  ['helpers/ubs_core/go_detectors/request_regex.py']='c7e99ecc7456be7d9a271860d80180ce3e73f814b4db92f7958226d0e3510a59'
  ['helpers/ubs_core/go_detectors/reverse_proxy_ssrf.py']='7fb8d18e9d5afdc3c9503cf30b9e4545fc7818dd963f8873f06f17ff729380bd'
  ['helpers/ubs_core/go_detectors/security_randomness.py']='869d4f62ce4418e6430ab6791facf3aa0cfda26674eb4697aa50a74b1450e17d'
  ['helpers/ubs_core/go_patterns/__init__.py']='30709d223fdb4167cbfa35569eb0ee2d2d3cbbc5fcf4803a2721f8ab41499cc5'
  ['helpers/ubs_core/go_patterns/concurrency_channels.py']='d7a5925f2cdc8aac511f9c5e9ee975b707beb1dee2802563058f32aa10266290'
  ['helpers/ubs_core/go_patterns/errors.py']='5cdca8346078b8d8e9923cb0294575a90049f14b9169bc5025de9123cd8e0c26'
  ['helpers/ubs_core/go_patterns/json_fs.py']='e561c18ac8d49ca7d3a0644381b5624d3d0e5f975c43a3056e4ad177538a7b6b'
  ['helpers/ubs_core/go_patterns/misc.py']='d23874e0fd10bc3538fd0c9b4eae998dbcb3076dd66020a6c764c7bb297506bd'
  ['helpers/ubs_core/go_rules.py']='a11e1036d06d313c102fda792f9842af7af69ad6250ec9dcb0c21ceaddc00ce1'
  ['helpers/ubs_core/go_scan.py']='dbfe5ba618dee8b7a7ce7adbecd0db9f200686db313a5549f6408bcf1f362339'
  ['helpers/ubs_core/io.py']='3f0415f899245019ae6cdecbd8a0558c6e5d16ca43f8856e960fa3ca26d7d320'
  ['helpers/ubs_core/java_ast.py']='32a7c928810eced7c09ec3fcae874fffcf56e0c70360a58cae08a78ed8501c49'
  ['helpers/ubs_core/java_detectors/__init__.py']='ef52ffa7d353633e7bb1d1caa697c3b3bf83c6d7dc1ec111a3a4b71e2aa2d8f0'
  ['helpers/ubs_core/java_detectors/_common.py']='658ef921d7248ee9e95e3dff0887092e1133debe67c2b2b62aa21b7447584c73'
  ['helpers/ubs_core/java_detectors/archive_extraction.py']='d55d79ba241f0ba037c0033b5f18bef7a06cc71865f899508004655091c926ab'
  ['helpers/ubs_core/java_detectors/collections_foreach.py']='eea7650f153c3dc644047cfea0009dfab620a46c75c596900a94111146b2a94c'
  ['helpers/ubs_core/java_detectors/control_flow.py']='7c22d242c21e56fd23b01093bd40cbca00a5f8a9511a3dc3d19d8d8cc9d69e0c'
  ['helpers/ubs_core/java_detectors/equals_hashcode.py']='6647624ef4111703b3bd66e67ec2140efc493508eba1eefa6f72ca43caf15db1'
  ['helpers/ubs_core/java_detectors/header_injection.py']='65a4c8a006759204beed63b62ceedbbc1ae91713f764132005ba7e7232f79112'
  ['helpers/ubs_core/java_detectors/io_loops.py']='9a0c38817e7cc38e59bb36f6248270d3aae8064965804f2694143c05481a42f0'
  ['helpers/ubs_core/java_detectors/optional_get.py']='62ca39904c0af60817dcf946a8766064c6f16c802f18c9bea12f14460e75165a'
  ['helpers/ubs_core/java_detectors/resource_leaks.py']='a4247b9c04b4856b318baaff7f9c7d42512ab24808ff92ca71cfb6079e9551e0'
  ['helpers/ubs_core/java_detectors/runtime_exec.py']='60318317472be27b99923970a007d2899af77e8fb409b70adeb4aab9211fa5e8'
  ['helpers/ubs_core/java_detectors/security_randomness.py']='e63f482539d47b65ec49b4d022145d74ca08ef53e458b0d9cccf7165bcde9939'
  ['helpers/ubs_core/java_detectors/sql_concat_fallback.py']='f9f8de97db4b96d7fb6e9869d2213958203574d454f2e55283bd0b18540c7fc6'
  ['helpers/ubs_core/java_detectors/ssrf_outbound_url.py']='f3419263e405533a15bff4f73751ce0695dc3569dcb51490ab7ecd8cf952e1f8'
  ['helpers/ubs_core/java_detectors/streams_concat.py']='4c76d552db8a001b8647f42c6ec20e90e8128e854bf0bcf030eac993b106db4d'
  ['helpers/ubs_core/java_detectors/tech_debt.py']='6fa5702a073d08656b72f9673ba5299770f8f56277d0f942ab7cbc99bcabc873'
  ['helpers/ubs_core/java_patterns/__init__.py']='8b7de6cca7d1b61a2884216d2756adabf3ad7d2a08bea8defe3e8d305452e9c2'
  ['helpers/ubs_core/java_patterns/concurrency_io.py']='9bee9f2911a23993806d3e367339b99af70eaf4946cc979b21d18bc8a35e383d'
  ['helpers/ubs_core/java_patterns/foundations.py']='64b5f87535eaadf3be0ba10e3f7ac8b05e8c114f17ac1bf25596d71c1078b1b5'
  ['helpers/ubs_core/java_patterns/quality.py']='2e037fbc04bd6d9e0896357612fd6e195ca9aecc1b0ab38934335b297eba0475'
  ['helpers/ubs_core/java_patterns/resource_lifecycle.py']='0a8f38417321c16bbcae6bdf42aa68c15d6f6e3ca6d70a84e3aa29c6f6ac5d1c'
  ['helpers/ubs_core/java_patterns/security_rg.py']='d1ddb0626ec8729133b915dd27401ea2823df452acd18920c2efd919119864fa'
  ['helpers/ubs_core/java_rules.py']='25646798a89ca69b7a101901456ab0970ad28abdffef5fab33458ff8b900a9cf'
  ['helpers/ubs_core/java_scan.py']='e1d39a3790f943feca57062ff77be558ae766a87fffbffd374f98fe50fbb4997'
  ['helpers/ubs_core/js_ast.py']='cc0ee3b63512bb043ac5167dfbb8b67b7c2cbdbe5ae8e9d11d6828c62451da5f'
  ['helpers/ubs_core/js_patterns/__init__.py']='0529d2e73e888d4ff04bea182fb241f259eee345d04ef3bb19478b74e5353851'
  ['helpers/ubs_core/js_patterns/debug_quality.py']='de6e0c36dfb9e06691b65ec5e8fd7739ec22840ebf5c487801f998218bb78172'
  ['helpers/ubs_core/js_patterns/eq_regex_dom.py']='d2513ecc6d6311612e0ccd02293d25a5373ef60cf4d689f96ec30c4c12cf4d8a'
  ['helpers/ubs_core/js_patterns/fn_parse_perf.py']='1cd06fa7c281e2a26d1979b01008dbea8b900bf6a2444ddc4b016e02362ed89a'
  ['helpers/ubs_core/js_patterns/null_coercion.py']='7dba576e4d910d0a8fd8671b0562c68a558c8aa9205d4301b4c3aa91444d887d'
  ['helpers/ubs_core/js_patterns/proto_vars.py']='b4fdf0f9ccfa5b4133f12f53dc2813fcd618530756c9a299ed16e1d0c0388b31'
  ['helpers/ubs_core/js_patterns/security_node.py']='7ceb9d14a629fb7bb89fce5c702a7ccc769260be10feab937a843b473efcf81e'
  ['helpers/ubs_core/js_rules.py']='e038f6d8a7ad177e7cce78aa236580c3d2f8cb6dae65bfad172f3961465ebc4a'
  ['helpers/ubs_core/js_scan.py']='aaa78c5a59b6208e615cb436a547a54d99ac3558d165d4be116b9caad2f30903'
  ['helpers/ubs_core/kotlin_rules.py']='6dd77c16cd9fbba0e555162e2a8f378858ce70b4d70668f64ec8142983ba3c35'
  ['helpers/ubs_core/kotlin_scan.py']='2ea25fa756000235c64be1b02dad721d5e5d57284522648de73dcec36be14fde'
  ['helpers/ubs_core/lexer.py']='12c6db052e94728b110b2cd551311ba88ef815a3839eb565a4d6f2eb1256bfa5'
  ['helpers/ubs_core/prefilter.py']='c8a3cf0c8706953e84577166ed9bb659cd5ddf907d0d499af27b1c0e081ad2af'
  ['helpers/ubs_core/py_ast.py']='8dcc78151e3e4242e0b58b1628041ec77b2ce90ad58dc9ad89e3fdeb1c7ee762'
  ['helpers/ubs_core/py_detectors/__init__.py']='7ff850f4cf568398d6d1791d8ed932271ae685d789083683ae11917e24fd8504'
  ['helpers/ubs_core/py_detectors/_pathlike.py']='90b1b71bce5606f1a5684c9122fc14ac27bbbf5ba4ebf455343e29145a0b2e1c'
  ['helpers/ubs_core/py_detectors/archive_extraction.py']='bde3f4b466aa25d5845467df6795fb3a1d15597846ae8440be8ee8fd170b316c'
  ['helpers/ubs_core/py_detectors/command_injection.py']='68db16769a53a677cf0e885f8b04b9596b10a2168b0f7fd1e52c1be256a4e941'
  ['helpers/ubs_core/py_detectors/cookie_security.py']='fba1be4149be8f0de38118fc822114cd7fd016e58b016301cad699d18b24e243'
  ['helpers/ubs_core/py_detectors/cors_misconfig.py']='ddbdd8315a1fd640e8e3e7c0cae8a6d1de01e2a6f279484a269628845540c29c'
  ['helpers/ubs_core/py_detectors/crypto_misuse.py']='cc25433b614058f57c9ec672c05f5d87e63538c3fcc65851ed3abfdb5f7fe2c6'
  ['helpers/ubs_core/py_detectors/csrf_disable.py']='7e79d19bd519d945d4a4df9e21d89f864e29ad2cd98b1bb0594970984345f938'
  ['helpers/ubs_core/py_detectors/debug_host_config.py']='9542f55192935adabf1999506d5db13e11effee156ecb660cf888a207c9b8d12'
  ['helpers/ubs_core/py_detectors/division.py']='5a2c07c7ad21dfa37f50a4bb7d1e4f93d2168ac1c492047a6fe127228894b79c'
  ['helpers/ubs_core/py_detectors/email_header_injection.py']='74a24a0777cecb6adc7e1e6b5b42c03cc1a38b4296293466cf217cf0251d1fe0'
  ['helpers/ubs_core/py_detectors/file_permissions.py']='9bb0fd672c9fd3b92071bbb208e11219840e2abf2956ecf83e3185ff1b9199b2'
  ['helpers/ubs_core/py_detectors/hardcoded_secrets.py']='9b04520774cc9646861a04e833ed6a24ea408df24f62c902e0a1c6808dba6995'
  ['helpers/ubs_core/py_detectors/header_injection.py']='c5aaff8ab91018f4df3c048a89b19f6a0b9b4a36c4535f3ae45ae5dbbd2499cd'
  ['helpers/ubs_core/py_detectors/host_header_poisoning.py']='ac14f4db4f35387d5b3fe94bfc15596840cd0dca22f96ef52bbe33400b2e67e5'
  ['helpers/ubs_core/py_detectors/http_timeout.py']='d528642d6aac30103e3f2d3317b0d416921ce065a94b531ad594f459169595a2'
  ['helpers/ubs_core/py_detectors/index_arithmetic.py']='8610ce7ba98491b06ecdf68628e0c163283eb252cacbe29b434ed69e3af6b279'
  ['helpers/ubs_core/py_detectors/insecure_random.py']='ccf7b2b917dce383e7d5cb60082f0101203e76cc3976aadfe73d0b9d1a038ade'
  ['helpers/ubs_core/py_detectors/io_open_checks.py']='fa364a1da59c28dc34b3deaf37ef2407e2ed06f9bb7251f25ed97b5be0f46bdb'
  ['helpers/ubs_core/py_detectors/is_literal.py']='0d78c216108815c1aaba817fe3041f882909fb19596d3c0893f3a2d087a7bca8'
  ['helpers/ubs_core/py_detectors/json_loads.py']='897356058eb93ca6a5855a0ad8bf3327174e3b7cb1884360038b2d858275d1d5'
  ['helpers/ubs_core/py_detectors/jwt_verification.py']='f384d77bd82df1bea21037b7c47fca4be4d1cff9b41185a1b2746513dbf16e19'
  ['helpers/ubs_core/py_detectors/ldap_injection.py']='31cd80955c932680e5d71e89a3f8d83cfa4de0ef6eb5311b5d4aa7a287d2097f'
  ['helpers/ubs_core/py_detectors/mass_assignment.py']='ad2d9926f406a461fc16591e6f2d9731bdd48f5d0d3a69f4d355a2ddd410469c'
  ['helpers/ubs_core/py_detectors/missing_returns.py']='fd2f71d6a23f8441c2edd3a076f441dd520e18d91628b673c4619a29ef892570'
  ['helpers/ubs_core/py_detectors/mutation_during_iteration.py']='50831c50c1536773aeb27481beb2d632e9ce3f906379f592e22e8d27a44a73bd'
  ['helpers/ubs_core/py_detectors/nosql_injection.py']='5117d571e16db684b8dd6d582ac19a9c811baf889d7ed1cc32eece2a35f2197a'
  ['helpers/ubs_core/py_detectors/open_redirect.py']='e8286bdc691f56c657011c66ba3af4a98e5c5709f8e74617b0d63d639c3f6f64'
  ['helpers/ubs_core/py_detectors/password_hashing.py']='191f24ba2fbd5acefa45a70301b83eccb222cbf6d6a77817e4fa04bcb9f50d94'
  ['helpers/ubs_core/py_detectors/path_traversal.py']='b3451c827df549ccff16511433bb3a88f37eff20bf6c1a14be3a9b8bb86bac34'
  ['helpers/ubs_core/py_detectors/redos_regex.py']='b096ec343b96451757fe906c7d14254bf8500c1cc27e7c243013af6677a74aad'
  ['helpers/ubs_core/py_detectors/safe_html_xss.py']='e36f35f8b1ec02e8625a2e7848d67e26d103494501062721548a67d19df9087e'
  ['helpers/ubs_core/py_detectors/security_assert.py']='13b97f54ff9472312b0c0f831256c8f73d699ec743fee1659d127b031f1e0009'
  ['helpers/ubs_core/py_detectors/sql_injection.py']='f6ac17231af0e7fa5738c8c397b1409a755176c8156d3fcb84df04143aaa3022'
  ['helpers/ubs_core/py_detectors/ssrf.py']='b6bdbb8d03549146081e61e2c9fd1b28c94276edbf184fa3b67d1d1349e6ba67'
  ['helpers/ubs_core/py_detectors/subprocess_timeout.py']='b102cdc52d47e1ee2de73c3b78660ddec540d77865b2164b6c6f414b7f29a8f4'
  ['helpers/ubs_core/py_detectors/template_autoescape.py']='373544e3181dfaf40c09b0002612951e018d599b395c6fbdb55b8317c1533640'
  ['helpers/ubs_core/py_detectors/template_injection.py']='0fafe6cc4b6944f5c754ac7df3a44810d9a23100e3de1954033b8c42558cd807'
  ['helpers/ubs_core/py_detectors/tls_verification.py']='54d90e5d758bdc27517f05ddbdc9fdf65a0ff1ba5c9941bfac046b5291d3bfa5'
  ['helpers/ubs_core/py_detectors/unsafe_deserialization.py']='576ccf4696fb30ebc289b6bb9fabef84c7b18d53ba7b2a727e5164d3be5fa814'
  ['helpers/ubs_core/py_detectors/xml_parser_security.py']='c57d0423e3ab7a27d7c7d2262cf0d67d15d8d888ac258c952123eb12f4a032c8'
  ['helpers/ubs_core/py_patterns/__init__.py']='7b9b471217121aa96668386d623d9be7ce5ce25e4866c548c3ac2d135faf768d'
  ['helpers/ubs_core/py_patterns/debug_typing.py']='8fd42b6759ed759ff5c2b17959b43e33bffde3e0fa75a3748fa40034a19a7626'
  ['helpers/ubs_core/py_patterns/flow.py']='2ab85fdcf68060fe7311b7280c5c4641acbf4e948b24d57e80c328ee5e0f16d1'
  ['helpers/ubs_core/py_patterns/foundations.py']='84a769666d76751ef97faccfb8c14141fbeb684578a53b12ea262d0f0a14a90c'
  ['helpers/ubs_core/py_patterns/io_files.py']='cfc4ff45b29fc5e6391024475238113970d828e2d16fb21a10d384d5477c6f41'
  ['helpers/ubs_core/py_patterns/quality.py']='3b5a137fa381424e2d01eefcc2622985063d810fab2898ac198c722226ff5887'
  ['helpers/ubs_core/py_patterns/security_rg.py']='6b1651db78b6190bfff6a54c8663daba3a80a274a5ad113dfe69955de61d341a'
  ['helpers/ubs_core/py_rules.py']='a8eba45f15817c24aa4e6cbae427fb5703fa2b98c5e66c4aa850e51f6debcfcb'
  ['helpers/ubs_core/py_scan.py']='f438729263a2de865657fcad384f45d468943fd181e73d5ece517515490af608'
  ['helpers/ubs_core/registry.py']='45f598b29e9108dec30bb7340cc3d76952274e8c3c33389f1a3615b9523b2c07'
  ['helpers/ubs_core/ruby_ast.py']='1db038deb6c7501a0420252b613d6abdeba0b49b7bc673050debb50c81a30758'
  ['helpers/ubs_core/ruby_detectors/__init__.py']='7b5ef3809ebd50136d741ade03d1c56b4b16053753dd79a8d90dd9021ebb0db7'
  ['helpers/ubs_core/ruby_detectors/_common.py']='5229306bddc9653d6aba535903fc2a738ccc7b3b4f2bea548aa5cc4bde3a1864'
  ['helpers/ubs_core/ruby_detectors/archive_extraction.py']='f18248f8821304ae8efa409491af9fa5d067b8285127c8d00e22da8ba43816c3'
  ['helpers/ubs_core/ruby_detectors/frozen_string_literal.py']='8cef7c3646681b746ade6748d66d4e3dc137b01c5005d5797950953a40a31bc7'
  ['helpers/ubs_core/ruby_detectors/json_parse_no_rescue.py']='da8046ad2faba8d291cfac3b6a968d558959b8d0854b07b76b04b56c8baf3a06'
  ['helpers/ubs_core/ruby_detectors/open_redirect.py']='9e9cd1b69ee7b08fdbd567584639899f41e96f8e84f29c2368e5a771ce719e11'
  ['helpers/ubs_core/ruby_detectors/response_header_injection.py']='14b88e2a44a9735d4c0c417381b1fa17c6a0a059a5146dce2be48aea2fab6224'
  ['helpers/ubs_core/ruby_detectors/security_randomness.py']='e77e2b4fb84718b7f7af15f55b15edd485af4bd814d2c6a76a3045d5f373c11f'
  ['helpers/ubs_core/ruby_patterns/__init__.py']='ed3371e10794baa474b5270b57db2f40862a5477ecea49165198b65b3636dc3c'
  ['helpers/ubs_core/ruby_patterns/collections_cmp.py']='745cb22be141e72e2166464108d8bcd9637cde067b45a85737c90ffa15c7a310'
  ['helpers/ubs_core/ruby_patterns/debug_perf.py']='c09e2727a08c0cdaa1e36e930758876339bba5e26c358e05b9d45f427ef45a05'
  ['helpers/ubs_core/ruby_patterns/exceptions.py']='5ba25ef751016ad5c8c1000f2a035decafa59d1159b63f01584fb5ecce79d4f1'
  ['helpers/ubs_core/ruby_patterns/foundations.py']='47bd8dc284c68ec930568c1f4ebeb7a263b5b951ced363abe72ba19cb069ce0c'
  ['helpers/ubs_core/ruby_patterns/parsing_flow.py']='2e5af6d69db7d78adc07b7a0679c23d78124b2a2166a29f0da319d2a5cfe173e'
  ['helpers/ubs_core/ruby_patterns/regex_conc.py']='aba17193a68429bc144c50fd28819b10521c0f50702d65d5ffb9b1f252750b6c'
  ['helpers/ubs_core/ruby_patterns/security_rg.py']='e5258618d34c8d648f0e6e60063e7762e00e0f68765c92096ff9430e5d849d53'
  ['helpers/ubs_core/ruby_patterns/shell_io.py']='65b858569d34639c6e7e7edb59374f9dbd37eef9b0460c588de082af88349b8a'
  ['helpers/ubs_core/ruby_patterns/vars_quality.py']='f68007ffbde60d8e11b574d45815f1f0d8ca6e70eccfa748ce9dc4eb3d6dfd1d'
  ['helpers/ubs_core/ruby_rules.py']='e8445052f9492794411bd0ab1a816d8927997313ff046a4d22771af13b924f79'
  ['helpers/ubs_core/ruby_scan.py']='cd78b54a68f06de87989e7a1249bc84f8be9bf71bf5bf167359b0184077d069e'
  ['helpers/ubs_core/rust_ast.py']='e1c5440116ca4fff3b12a238284ef05be38ad799baece2fac556aa83fc56e94e'
  ['helpers/ubs_core/rust_detectors/__init__.py']='b238f38c0768683ea44b5bfd8e4e4c8a94e2bbbe98ddd77de32230a47bdd7799'
  ['helpers/ubs_core/rust_detectors/archive_entry_path.py']='fcedd0f3194b08ee4fc09ed71d81a97fa289d3399feeef71a19f4235945f014d'
  ['helpers/ubs_core/rust_detectors/async_context.py']='d093a071c2a8c3b6603b4abec38d8e5bb8dd3f8f6aa0840386b9d0b39b3dd380'
  ['helpers/ubs_core/rust_detectors/command_executable.py']='8016691d5600ff52e2a1310b2238e3a88cf49ce98ed0ff147a43d86944b95357'
  ['helpers/ubs_core/rust_detectors/cors_credential.py']='ab31c4dd1cde153bd72e22e30bdcbcbd23156e4d6f8e7c9138b6c84b52ac1031'
  ['helpers/ubs_core/rust_detectors/drop_panic.py']='c9ee9b6455b6a034bb968ef572a4d63973a58458f7b7344226e95bd4bb53cf35'
  ['helpers/ubs_core/rust_detectors/format_literal.py']='3f4aaa7d3edf18bcbaf285bbca8adfd37f7e3cad1678e3353070a932df05ca5a'
  ['helpers/ubs_core/rust_detectors/hardcoded_secrets.py']='383cdd1bbe69fc0df3d0477bf839315662c1e3553235ae78414e8bd69253e851'
  ['helpers/ubs_core/rust_detectors/host_header_url.py']='846b528eb628403247a028d80534214f6fa006cb7551d73150ff737f126f529c'
  ['helpers/ubs_core/rust_detectors/jwt_verification.py']='8f0594d0834ef09053db428b5da84bb048f4ce654569ae165e9dd5b0d44855e4'
  ['helpers/ubs_core/rust_detectors/loop_context.py']='c78aed29e2eca7487ba5d1176c7af7d2e7edaeb15283291b2b13cb806b0915b1'
  ['helpers/ubs_core/rust_detectors/open_redirect.py']='b0f332c77ef07ecc3bfe8e01cddeaa8da5bd14a61e62aff60ec22e6e0b03789d'
  ['helpers/ubs_core/rust_detectors/path_traversal.py']='349f549442c72df06cbac9f1bf7815c7ca72bdc92803a0479827a4c04422c32e'
  ['helpers/ubs_core/rust_detectors/request_regex.py']='01b1ee7756d78a0f079cb785b69ac34ad655dc966fb9797ff9b13aa4962295e9'
  ['helpers/ubs_core/rust_detectors/request_url.py']='ec7351e3c5d4a1657a31bb1940f0ca4f4d6d785ae32f358b0462d73e1419a3b1'
  ['helpers/ubs_core/rust_detectors/response_header.py']='15ff23c265c318c0bd2b782c4b48e15332e07ffffbb1688955bac0700db6104f'
  ['helpers/ubs_core/rust_detectors/security_randomness.py']='cfd219ed421fc4211e30e77e2789e40ffc0e44ea80ae274e1c9ead013dcfe581'
  ['helpers/ubs_core/rust_detectors/sql_injection.py']='1b43a7cf3c766468ce2f99093b0561ed11f569137ea6f01dab9244429d9f1f18'
  ['helpers/ubs_core/rust_detectors/temp_file_race.py']='1138d832a284bd37151eb81fd01aff7f81e987bf9710eb7bfd5409046a5536bf'
  ['helpers/ubs_core/rust_detectors/tls_indirect.py']='120501344abdcddf96e6a40c7b4b38617dd0649b83cfc81a0863f38027b0a755'
  ['helpers/ubs_core/rust_detectors/unbounded_request_body.py']='72eaedc5e99846eadaab246cb6398dc189f541ca14ae62e8a305a316bde69f5f'
  ['helpers/ubs_core/rust_rules.py']='d35a4d6cb061f0eb7ff70a799b415414016a3ce8e10c8331e8a9ee4b484be211'
  ['helpers/ubs_core/rust_scan.py']='ed646a24756848373110f4126531f187815609b71b8b4edf2975a7071febbc76'
  ['helpers/ubs_core/scheduler.py']='9d4d936984f308c82d80d108b006a65ccd2eeb1d41e07325b621fc39147a94ed'
  ['helpers/ubs_core/selftest.py']='6ca3dd5e5534edc0b8a10e9aac1f80834f0d79b661c50c28bd00b33eb85bff08'
  ['helpers/ubs_core/shards.py']='cdc6ecab42bd962e65bb1ac1dc5e3f20b87c4d68632617286a2991274c0c98f7'
  ['helpers/ubs_core/suppression.py']='10c9827d17ab590cfa7bbc13bbdc4b8466262e7f0ae90bc7f9ccf4bc049b9595'
  ['helpers/ubs_core/swift_ast.py']='53b2d380aeca310005241d1c43756dbf00d730163c2abbba4f8b1dbfadf799d3'
  ['helpers/ubs_core/swift_detectors/__init__.py']='e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
  ['helpers/ubs_core/swift_detectors/_common.py']='601e0f4ef42f5d007e26068f206c3dc8258de7939e642a84da248b26715ffe91'
  ['helpers/ubs_core/swift_detectors/archive_extraction.py']='2e3fa0b1977e25813a79ccc59796cbb3b7abe0c4073f2d93f2b165889bd885a7'
  ['helpers/ubs_core/swift_detectors/header_injection.py']='76549ac77bd1ad0a54197dd8288db0b75445ee28cd70f63ab4a5bfe54bf22b4f'
  ['helpers/ubs_core/swift_detectors/outbound_url.py']='a5580a0cb3dc4682cb8b542bd684a64a5e5a1f631a8eac6c7ee77f427e4b88bd'
  ['helpers/ubs_core/swift_detectors/plist_checks.py']='a6561b6a48b3703a38ce66cb0ef1abd21cb84cc755e4a8f52d6241e2fd986b25'
  ['helpers/ubs_core/swift_detectors/security_randomness.py']='9f3042fff59eac5194b238fa4bd5f469ff9b51087267b884019ee9e89dc401e6'
  ['helpers/ubs_core/swift_detectors/shell_execution.py']='f5d3481393cbc29a9f0cd6732a7b09c0c46497e29103a7af9d4a1e5d95be330d'
  ['helpers/ubs_core/swift_detectors/urlsession_correlation.py']='b43454593fe727bcc9c460656864dd89a4d77d3eb9577067fedbf8df5ad8b835'
  ['helpers/ubs_core/swift_patterns/__init__.py']='e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
  ['helpers/ubs_core/swift_patterns/closures_networking.py']='e9a53395a2ebcce3a6fa6b2271efdd67db47d489eee0457802ca1e874a27db7d'
  ['helpers/ubs_core/swift_patterns/debug_quality.py']='467066b5d51d8e0a523b6271407d36e9c44e2cfa5f15d597159011c81eb3137f'
  ['helpers/ubs_core/swift_patterns/errors_security.py']='37a306981cbb5c60c502f84e24a3ff60b3803eed958d1fe0561270a7ea0d5f69'
  ['helpers/ubs_core/swift_patterns/foundations.py']='c04908fa89c5bec54d1f88fd55c00da87114d7526b2f3a5e80aec288e52e125f'
  ['helpers/ubs_core/swift_patterns/misc_cats.py']='6be76fa36414b6de28a0414a122549eade5a84f16686440e58d94079d1293d99'
  ['helpers/ubs_core/swift_patterns/threading_perf.py']='168a59a4414cfe39bb8e9032174bbe1a1ef264ec2c5251c4bb47ac9049c5719b'
  ['helpers/ubs_core/swift_rules.py']='a832cfbaa194d08944d2cc18b4683eb0ddc78b845da8de77163cb6882d605826'
  ['helpers/ubs_core/swift_scan.py']='8f67ae710db981bb77947b4db2cfbc4bb266c5df2232c3344467e89692136803'
)

# ubs_resolve_helper [OUT_VAR] REL_PATH
# Resolves a helper asset (e.g. "helpers/resource_lifecycle_py.py").
# - If UBS_VERIFIED_ASSET_DIR is set (by the ubs meta-runner), the helper is
#   resolved from that directory. Falling back to an unverified location is
#   refused (exit 2) unless UBS_ALLOW_UNVERIFIED_HELPERS=1.
# - If UBS_VERIFIED_ASSET_DIR is unset (standalone module execution), the
#   helper is resolved from the module directory and verified against
#   UBS_COMMON_HELPER_CHECKSUMS before execution. A checksum mismatch exits 2
#   with remediation unless UBS_ALLOW_UNVERIFIED_HELPERS=1.
# - Returns 1 if the helper does not exist (optional helper skipped).
ubs_resolve_helper(){
  local _out_var="" _rel=""
  if [[ $# -ge 2 ]]; then
    _out_var="$1"
    _rel="$2"
  else
    _rel="$1"
  fi

  local target=""

  if [[ -n "${UBS_VERIFIED_ASSET_DIR:-}" ]]; then
    if [[ -f "${UBS_VERIFIED_ASSET_DIR}/${_rel}" ]]; then
      target="${UBS_VERIFIED_ASSET_DIR}/${_rel}"
      if [[ -n "$_out_var" ]]; then
        printf -v "$_out_var" '%s' "$target"
      else
        printf '%s\n' "$target"
      fi
      return 0
    fi
    local fallback="${UBS_MODULE_LIB_DIR:-${SCRIPT_DIR:-}}/${_rel}"
    if [[ -f "$fallback" ]]; then
      if [[ "${UBS_ALLOW_UNVERIFIED_HELPERS:-0}" == "1" ]]; then
        printf 'warning: UBS_ALLOW_UNVERIFIED_HELPERS=1: using unverified helper %s at %s\n' "$_rel" "$fallback" >&2
        target="$fallback"
        if [[ -n "$_out_var" ]]; then
          printf -v "$_out_var" '%s' "$target"
        else
          printf '%s\n' "$target"
        fi
        return 0
      fi
      ubs_die "helper '$_rel' found at unverified location ($fallback); refusing to execute (set UBS_ALLOW_UNVERIFIED_HELPERS=1 to override)" 2
    fi
    return 1
  fi

  # Standalone mode: UBS_VERIFIED_ASSET_DIR is unset.
  local base_dir="${UBS_MODULE_LIB_DIR:-${SCRIPT_DIR:-}}"
  if [[ -z "$base_dir" ]]; then
    base_dir="$(cd -- "$(dirname "${BASH_SOURCE[1]}")" 2>/dev/null && pwd)"
  fi
  target="${base_dir}/${_rel}"

  if [[ ! -f "$target" ]]; then
    return 1
  fi

  if [[ "${UBS_ALLOW_UNVERIFIED_HELPERS:-0}" == "1" ]]; then
    printf 'warning: UBS_ALLOW_UNVERIFIED_HELPERS=1: using unverified helper %s\n' "$_rel" >&2
    if [[ -n "$_out_var" ]]; then
      printf -v "$_out_var" '%s' "$target"
    else
      printf '%s\n' "$target"
    fi
    return 0
  fi

  local expected="${UBS_COMMON_HELPER_CHECKSUMS[$_rel]:-${UBS_HELPER_CHECKSUMS[$_rel]:-}}"
  if [[ -z "$expected" ]]; then
    ubs_die "helper '$_rel' has no pinned checksum in verification table; refusing to execute" 2
  fi

  ubs_sha256_or_die "$target" "helper '$target'"
  local actual="$UBS_SHA256"

  if [[ "$actual" != "$expected" ]]; then
    ubs_die "helper '$_rel' failed checksum verification (expected $expected, got $actual); refusing to execute (run 'ubs doctor --fix' or set UBS_ALLOW_UNVERIFIED_HELPERS=1 to override)" 2
  fi

  if [[ -n "$_out_var" ]]; then
    printf -v "$_out_var" '%s' "$target"
  else
    printf '%s\n' "$target"
  fi
  return 0
}

# ubs_resolve_helpers_dir [OUT_VAR]
# Resolves the helpers directory (for ubs_core / PYTHONPATH).
ubs_resolve_helpers_dir(){
  local _out_var="${1:-}"
  local target=""

  if [[ -n "${UBS_VERIFIED_ASSET_DIR:-}" ]]; then
    if [[ -d "${UBS_VERIFIED_ASSET_DIR}/helpers" ]]; then
      target="${UBS_VERIFIED_ASSET_DIR}/helpers"
      if [[ -n "$_out_var" ]]; then
        printf -v "$_out_var" '%s' "$target"
      else
        printf '%s\n' "$target"
      fi
      return 0
    fi
    local fallback="${UBS_MODULE_LIB_DIR:-${SCRIPT_DIR:-}}/helpers"
    if [[ -d "$fallback" ]]; then
      if [[ "${UBS_ALLOW_UNVERIFIED_HELPERS:-0}" == "1" ]]; then
        printf 'warning: UBS_ALLOW_UNVERIFIED_HELPERS=1: using unverified helpers dir at %s\n' "$fallback" >&2
        target="$fallback"
        if [[ -n "$_out_var" ]]; then
          printf -v "$_out_var" '%s' "$target"
        else
          printf '%s\n' "$target"
        fi
        return 0
      fi
      ubs_die "helpers directory found at unverified location ($fallback); refusing to execute (set UBS_ALLOW_UNVERIFIED_HELPERS=1 to override)" 2
    fi
    return 1
  fi

  local base_dir="${UBS_MODULE_LIB_DIR:-${SCRIPT_DIR:-}}"
  if [[ -z "$base_dir" ]]; then
    base_dir="$(cd -- "$(dirname "${BASH_SOURCE[1]}")" 2>/dev/null && pwd)"
  fi
  target="${base_dir}/helpers"
  if [[ ! -d "$target" ]]; then
    return 1
  fi

  if [[ "${UBS_ALLOW_UNVERIFIED_HELPERS:-0}" == "1" ]]; then
    printf 'warning: UBS_ALLOW_UNVERIFIED_HELPERS=1: using unverified helpers dir at %s\n' "$target" >&2
  elif [[ -d "${target}/ubs_core" ]]; then
    local _core_rel _core_actual _core_expected
    for _core_rel in "${!UBS_COMMON_HELPER_CHECKSUMS[@]}"; do
      if [[ "$_core_rel" == helpers/ubs_core/* && -f "${base_dir}/${_core_rel}" ]]; then
        _core_expected="${UBS_COMMON_HELPER_CHECKSUMS[$_core_rel]}"
        ubs_sha256_or_die "${base_dir}/${_core_rel}" "'${base_dir}/${_core_rel}'"
        _core_actual="$UBS_SHA256"
        if [[ "$_core_actual" != "$_core_expected" ]]; then
          ubs_die "helper file '$_core_rel' failed checksum verification (expected $_core_expected, got $_core_actual); refusing to execute (run 'ubs doctor --fix' or set UBS_ALLOW_UNVERIFIED_HELPERS=1 to override)" 2
        fi
      fi
    done
  fi

  if [[ -n "$_out_var" ]]; then
    printf -v "$_out_var" '%s' "$target"
  else
    printf '%s\n' "$target"
  fi
  return 0
}

# ── JSON ────────────────────────────────────────────────────────────────────
# json_escape [STRING]: escape for a JSON string body (no surrounding quotes).
# Missing argument and empty string are both fine under `set -u`; with no
# argument stdin is used. Every control character U+0000–U+001F is escaped
# (\n \r \t \b \f by name, the rest as \u00XX); non-ASCII passes through.
json_escape(){
  local s=""
  if [[ $# -gt 0 ]]; then s="${1-}"; else s="$(cat 2>/dev/null || true)"; fi
  s=${s//\\/\\\\}
  s=${s//\"/\\\"}
  s=${s//$'\n'/\\n}
  s=${s//$'\r'/\\r}
  s=${s//$'\t'/\\t}
  s=${s//$'\b'/\\b}
  s=${s//$'\f'/\\f}
  if [[ "$s" == *[$'\x01'-$'\x1f']* ]]; then
    local out="" ch code
    local i
    for (( i = 0; i < ${#s}; i++ )); do
      ch="${s:i:1}"
      printf -v code '%d' "'$ch"
      if (( code > 0 && code < 32 )); then
        printf -v ch '\\u%04x' "$code"
      fi
      out+="$ch"
    done
    s="$out"
  fi
  printf '%s' "$s"
}

# ── Severity ────────────────────────────────────────────────────────────────
# ubs_normalize_severity NAME: the four severities every module reports.
ubs_normalize_severity(){
  case "${1,,}" in
    critical|crit|error|err|high|fatal|blocker) printf 'critical' ;;
    warning|warn|medium|moderate|important) printf 'warning' ;;
    info|information|note|notice|low|minor|hint|style) printf 'info' ;;
    good|ok|pass|clean|none) printf 'good' ;;
    *) printf 'info' ;;
  esac
}

# ── Output format contract ──────────────────────────────────────────────────
# Modules render text, json and sarif. jsonl and toon are produced by the
# meta-runner from the module's json, so asking a module for them directly is
# a usage error (exit 2) — never a silent fallback to text.
ubs_validate_format(){
  case "${1:-text}" in
    text|json|sarif) return 0 ;;
    jsonl|toon)
      ubs_die "--format=$1 is produced by the meta-runner from this module's json; run 'ubs --format=$1' instead (module formats: text|json|sarif)" 2 ;;
    *)
      ubs_die "unknown --format value: $1 (expected text|json|sarif)" 2 ;;
  esac
}

# ── File listing ────────────────────────────────────────────────────────────
# ubs_list_files DIR [--ext CSV] [--exclude CSV] [--files-from FILE]
# Prints NUL-separated paths (safe for names with spaces or newlines).
#   --ext       comma-separated extensions without dots (js,ts); default: all
#   --exclude   comma-separated directory names or globs to skip
#   --files-from  a file with one path per line (or NUL-separated): only those
#                 that exist under DIR are listed (meta-runner file lists)
# Uses `rg --files -0` (respects .gitignore, skips hidden and binary files
# the way the modules already do) and falls back to `find -print0`.
ubs_list_files(){
  local dir="$1"; shift
  local exts="" excludes="" files_from=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --ext) exts="$2"; shift 2 ;;
      --ext=*) exts="${1#*=}"; shift ;;
      --exclude) excludes="$2"; shift 2 ;;
      --exclude=*) excludes="${1#*=}"; shift ;;
      --files-from) files_from="$2"; shift 2 ;;
      --files-from=*) files_from="${1#*=}"; shift ;;
      *) ubs_die "ubs_list_files: unknown option $1" 2 ;;
    esac
  done
  [[ -d "$dir" ]] || return 0
  if [[ -n "$files_from" && -f "$files_from" ]]; then
    local f
    while IFS= read -r -d '' f || [[ -n "$f" ]]; do
      f="${f%$'\n'}"
      [[ -z "$f" ]] && continue
      if [[ "$f" == /* ]]; then
        [[ -f "$f" ]] && printf '%s\0' "$f"
      elif [[ -f "$dir/$f" ]]; then
        printf '%s\0' "$dir/$f"
      fi
    done < <(tr '\n' '\0' < "$files_from"; printf '\0')
    return 0
  fi
  local -a rg_args=(--files -0 --no-messages)
  local -a find_args=()
  local item
  if [[ -n "$exts" ]]; then
    local -a ext_list
    IFS=',' read -r -a ext_list <<<"$exts"
    for item in "${ext_list[@]}"; do
      item="${item#.}"
      [[ -z "$item" ]] && continue
      rg_args+=(-g "*.${item}")
      if [[ ${#find_args[@]} -eq 0 ]]; then find_args+=( '(' -name "*.${item}" ); else find_args+=( -o -name "*.${item}" ); fi
    done
    [[ ${#find_args[@]} -gt 0 ]] && find_args+=( ')' )
  fi
  local -a prune_args=()
  if [[ -n "$excludes" ]]; then
    local -a ex_list
    IFS=',' read -r -a ex_list <<<"$excludes"
    for item in "${ex_list[@]}"; do
      [[ -z "$item" ]] && continue
      rg_args+=(-g "!${item}")
      prune_args+=( -path "*/${item}" -prune -o -path "*/${item}/*" -prune -o )
    done
  fi
  if command -v rg >/dev/null 2>&1; then
    rg "${rg_args[@]}" -- "$dir" 2>/dev/null
  else
    find "$dir" -xdev "${prune_args[@]}" -type f "${find_args[@]}" -print0 2>/dev/null
  fi
}

# ubs_count_files DIR [options...]: number of files ubs_list_files would list.
ubs_count_files(){
  ubs_list_files "$@" | tr -cd '\0' | wc -c | awk '{print $1+0}'
}
