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
  # Executing this file directly makes return fail, so the exit fallback is live.
  # shellcheck disable=SC2317
  return 0 2>/dev/null || exit 0
fi
# Read by the modules and quality/test_ubs_common.py after sourcing.
# shellcheck disable=SC2034
UBS_COMMON_VERSION="1"

if [[ "${UBS_KEEP_TEMP:-0}" == "1" ]]; then
  if (( BASH_VERSINFO[0] < 5 || (BASH_VERSINFO[0] == 5 && BASH_VERSINFO[1] < 1) )); then
    echo 'ERROR: UBS_KEEP_TEMP=1 requires Bash >= 5.1 for pipe-backed heredocs.' >&2
    if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then exit 2; else return 2; fi
  fi
  case "${BASH_COMPAT:-}" in
    [0-4]*|50*|5.0*)
      echo 'ERROR: UBS_KEEP_TEMP=1 requires modern Bash compatibility (BASH_COMPAT >= 5.1).' >&2
      if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then exit 2; else return 2; fi ;;
  esac
  for _ubs_common_compat in 31 32 40 41 42 43 44; do
    if shopt -q "compat$_ubs_common_compat"; then
      echo 'ERROR: UBS_KEEP_TEMP=1 requires modern Bash compatibility (BASH_COMPAT >= 5.1).' >&2
      if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then exit 2; else return 2; fi
    fi
  done
  unset _ubs_common_compat
fi
UBS_COMMON_LOADED=1

# Preserve scanner-owned scratch when callers explicitly request retention.
# Keep normal rm flags/status and leave detector and publication logic alone.
ubs_remove_temp(){
  [[ "${UBS_KEEP_TEMP:-0}" == "1" ]] && return 0
  command rm "$@"
}

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
# Milliseconds since the epoch from an EPOCHREALTIME value. Bash prints EPOCHREALTIME with the
# LC_NUMERIC decimal separator ("1791357093,406751" under ru_RU or de_DE), so split at the first
# and last non-digit rather than at a literal "." (#160).
ubs_epoch_ms(){
  local t="$1" s us
  s="${t%%[!0-9]*}"
  us="${t##*[!0-9]}"
  printf '%s\n' $(( 10#$s * 1000 + 10#${us:0:3} ))
}

ubs_now_ms(){
  if [[ -n "${EPOCHREALTIME:-}" ]]; then
    ubs_epoch_ms "$EPOCHREALTIME"
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
    ubs_remove_temp -f -- "$tmp" 2>/dev/null || true
    printf '✗ cannot write the requested %s: %s\n' "$label" "$dest" >&2
    return 1
  fi
  if ! mv -f -- "$tmp" "$dest" 2>/dev/null; then
    ubs_remove_temp -f -- "$tmp" 2>/dev/null || true
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
# ubs_sha256_file FILE: compute sha256 digest of FILE (prints lowercase hex).
# Returns 0 on success, 1 on missing file or unavailable hash tool, 3 when the
# tool ran but failed or printed no digest; a status above 128 (how bash
# reports a child killed by signal N) passes through unchanged.
#
# Deliberately pipeline-free: callers run this inside `x="$(...)"` in modules
# that set `shopt -s lastpipe`, and bash's lastpipe job bookkeeping has a
# SIGCHLD race that can crash that subshell. Cutting the digest in-shell also
# stops a failing tool from yielding "success" with an empty digest.
ubs_sha256_file(){
  local file="$1" out="" rc=0 field=first
  [[ -f "$file" ]] || return 1
  if command -v sha256sum >/dev/null 2>&1; then
    out="$(sha256sum "$file" 2>/dev/null)" || rc=$?
  elif command -v shasum >/dev/null 2>&1; then
    out="$(shasum -a 256 "$file" 2>/dev/null)" || rc=$?
  elif command -v openssl >/dev/null 2>&1; then
    out="$(openssl dgst -sha256 "$file" 2>/dev/null)" || rc=$?
    field=last
  else
    return 1
  fi
  if (( rc != 0 )); then
    (( rc > 128 )) && return "$rc"
    return 3
  fi
  # GNU tools prefix the line with a backslash when the file name needed escaping.
  if [[ "$field" == first ]]; then out="${out#\\}"; out="${out%%[[:space:]]*}"; else out="${out##*[[:space:]]}"; fi
  [[ "$out" =~ ^[0-9a-fA-F]{64}$ ]] || return 3
  printf '%s\n' "${out,,}"
}

# ubs_sha256_into VAR FILE: store FILE's digest in VAR in the caller's shell.
# A status above 128 means the hashing subshell was killed by a signal (or a
# tool exited with such a code); that says nothing about FILE, so it is
# retried a bounded number of times. On failure UBS_SHA256_ERR holds an
# accurate reason and ubs_sha256_file's status is returned; VAR is untouched.
UBS_SHA256_ERR=""
ubs_sha256_into(){
  local __ubs_sha_var="$1" __ubs_sha_file="$2" __ubs_sha_out="" __ubs_sha_rc=0 __ubs_sha_try
  UBS_SHA256_ERR=""
  for __ubs_sha_try in 1 2 3; do
    __ubs_sha_rc=0
    __ubs_sha_out="$(ubs_sha256_file "$__ubs_sha_file")" || __ubs_sha_rc=$?
    if (( __ubs_sha_rc == 0 )); then
      printf -v "$__ubs_sha_var" '%s' "$__ubs_sha_out"
      return 0
    fi
    (( __ubs_sha_rc > 128 )) || break
  done
  case "$__ubs_sha_rc" in
    1)
      if [[ -f "$__ubs_sha_file" ]]; then
        UBS_SHA256_ERR="unable to compute checksum for '$__ubs_sha_file' (install sha256sum, shasum, or openssl)"
      else
        UBS_SHA256_ERR="unable to compute checksum: '$__ubs_sha_file' is not a regular file"
      fi
      ;;
    3) UBS_SHA256_ERR="checksum tool failed on '$__ubs_sha_file'" ;;
    *) UBS_SHA256_ERR="checksum of '$__ubs_sha_file' could not be computed: the hashing subprocess ended with status $__ubs_sha_rc (signal $((__ubs_sha_rc - 128))) on all $__ubs_sha_try attempts; the file was not judged" ;;
  esac
  return "$__ubs_sha_rc"
}

# Pinned helper and asset checksums for standalone module execution (bead E1).
# Auto-generated by scripts/update_checksums.py.
if ! declare -p UBS_HELPER_CHECKSUMS >/dev/null 2>&1; then
  declare -g -A UBS_HELPER_CHECKSUMS=()
fi
declare -g -A UBS_COMMON_HELPER_CHECKSUMS=(
  ['contract.json']='90b82afcc916b8f4608f1561be59fc874228028c40e957b42fba2791991ba970'
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
  ['helpers/type_narrowing_ts.js']='988cc579899f1104832c1d5693a92a038b7ad3d036289a854667c5c1b0441793'
  ['helpers/ubs_core/__init__.py']='b75e6b0fd574ac97252fe667280d5807ce1fc6726b1a92980796e46e8de3592f'
  ['helpers/ubs_core/__main__.py']='4aed5b835f04ba3a51b13a650b15dc05e2e43436e9e8be19000551999172639e'
  ['helpers/ubs_core/analyzers/__init__.py']='db07f3c0d284bbcb953447d3be545eea17a9924f9c688d82b06cbeb9f6dcb352'
  ['helpers/ubs_core/analyzers/async_event_emitter.py']='b1121c6632c65fab24fe99124c411d054cfe3fea78dc7a5971c722b98d5feb64'
  ['helpers/ubs_core/analyzers/async_event_listener.py']='8bea74e8b10cd2d37cfacdc693f15ffd9068ba4b1551ee48bf55d15e9bb0337c'
  ['helpers/ubs_core/analyzers/async_flatmap.py']='a847c3c1d9f0df0ccd76377391af71f6d4116ee2c6d351575ea31f65939ace0e'
  ['helpers/ubs_core/analyzers/async_foreach.py']='75bb07bc2f2a6680a7be111de3be192e6d8c3845ef6163f35151b45970812a42'
  ['helpers/ubs_core/analyzers/async_handles_csharp.py']='830d3853356dd3f631bc3ec2b949dc51f46ac8e71cb812948713bede783c898a'
  ['helpers/ubs_core/analyzers/async_jsx_handler.py']='b1b92b6f19e531bb49284c25d501aab1a5e6fa1435e6e48ea9b176028c542589'
  ['helpers/ubs_core/analyzers/async_map_awaited.py']='6a562a8f68d77a72b6e394545450063d3ec4912713771287cd8ab02d78590166'
  ['helpers/ubs_core/analyzers/async_map_ignored.py']='8c964ad8ccf94eed2384c759b41b5cbe6dc7845df29b26d22bbdc92f8f0eb197'
  ['helpers/ubs_core/analyzers/async_predicates.py']='a0491c3881f01509e8ad9655f2bf03121629694957c231c982b31cb882cb21b3'
  ['helpers/ubs_core/analyzers/async_promise_all_foreach.py']='b3fb755d7f3bb18dd89ee9c9964f890528248ad24b656636d75e9676c1ba8665'
  ['helpers/ubs_core/analyzers/async_promise_all_map.py']='8d6076c659f78bc06f165c8e1a71b38f01ddcd8acb864cd3325d6aa3474affe6'
  ['helpers/ubs_core/analyzers/async_promise_executor.py']='7fabfacd2295c5d792b2e91d871220dd6be1f0c06c98045fed1b7e4a9c07a98e'
  ['helpers/ubs_core/analyzers/async_react_effect.py']='d028f09d2ddb2e625f7be9c891f5c387047dd5d053882a2b6e49eeec4a054df8'
  ['helpers/ubs_core/analyzers/async_reduce.py']='a2dacc9be4331af6de172fc7887f201049e7320a7b392bae78cd006f9c131fdd'
  ['helpers/ubs_core/analyzers/async_sort_comparator.py']='08c8b492b0c56ae4e2856ad5c9c3050fd492b97198d1a8195abc076117278338'
  ['helpers/ubs_core/analyzers/async_timer.py']='c05499eaa0473572c9a84974426cc8a7e58ea94cc26acf8e9ccced665fcf0144'
  ['helpers/ubs_core/analyzers/cfg_test_only_rust.py']='9ce5fbb35121074409b3951eec97f7fd2714a05acd4c78d6f86932872acd5205'
  ['helpers/ubs_core/analyzers/coroutines_kotlin.py']='a0c339eec751780472e975b2eb885ec166c0c4a90d3ecf7a07fe5982269ca32a'
  ['helpers/ubs_core/analyzers/ctcompare_go.py']='a46dfb62750d28394179c86cc9f1571f7f921bceb6e7dccd37bb141f88b3a790'
  ['helpers/ubs_core/analyzers/ctcompare_js.py']='a1d420efd044e4c20a67b00058497004bad8c44b1b2122d0db029c5403e13059'
  ['helpers/ubs_core/analyzers/ctcompare_py.py']='f4662351955c8ac681753d02e4049c0cd143fbc88de568202df433fa59481b10'
  ['helpers/ubs_core/analyzers/ctcompare_rust.py']='5790f299b3e7446f605f3180e5f1940c8f373b32d743c55642cba1e4c593a084'
  ['helpers/ubs_core/analyzers/guards_generic.py']='61ef81e6255aa3c09ed175648f8cbd99ee2bff9a98ed3c968781533beb91b4a5'
  ['helpers/ubs_core/analyzers/guards_js.py']='4a27ccb62965a474c40de644f15cf2e4018642f42971501c480d7015c399eafa'
  ['helpers/ubs_core/analyzers/guards_py.py']='beb7d42b8b34a27b28107b7f557e206aed6a6ad26454c8b0dfe6b7271dd4d1de'
  ['helpers/ubs_core/analyzers/guards_ruby.py']='7446bbbb5e43643f761bf4b2efccbb9acf46a47afc2a7db69d2fc784482d71db'
  ['helpers/ubs_core/analyzers/lifecycle_cpp.py']='245804579718f5c4beb3bb7e3522a628e7338d41127ca03febfdbaad064bb55b'
  ['helpers/ubs_core/analyzers/lifecycle_csharp.py']='2bdfed38db8c8a5cd7327b45ac3edeaa15e6740563abdd3054e0b4fb9426b425'
  ['helpers/ubs_core/analyzers/lifecycle_elixir.py']='6b580b2c2d4569e8bf7ccf44d31a00314f4dbdd6c6c5a9087f402e5cddcd85b6'
  ['helpers/ubs_core/analyzers/lifecycle_java.py']='5b1d60fbe75a0b3f1ae25cc2c11210e5899ddbca0afd4047e3624789b561ebe2'
  ['helpers/ubs_core/analyzers/lifecycle_kotlin.py']='d0b180cb90181db688518992521d431dd344a1d9da990b5c72bdee78b2abe0e2'
  ['helpers/ubs_core/analyzers/lifecycle_py.py']='55f78618cb8672daf263c50c42081813251a1b7b5ce6f2de72b223c390e624ef'
  ['helpers/ubs_core/analyzers/lifecycle_ruby.py']='5f5c67bbfd71d3c09c1be6d8cd105fefb5a8d055508472f4153c30236b4e7dd7'
  ['helpers/ubs_core/analyzers/lifecycle_swift.py']='02e645a197eef30b54d869da4c5abc2a150fafa4d4b4f9f65b5204219ea89c58'
  ['helpers/ubs_core/analyzers/narrowing_cpp.py']='5681c018729ec37129d808d9f65ec51e368c060e0b0ce4d363b461afcd4d9345'
  ['helpers/ubs_core/analyzers/narrowing_csharp.py']='39fa318ca6557eb3f41ea721745b61a27fa3f6d4fbb0a51b6afe19f148abf988'
  ['helpers/ubs_core/analyzers/narrowing_elixir.py']='40af9808f556825b6ce81397c37d5ed5100ce34cbf2a7ea291be4c7f280ff7ee'
  ['helpers/ubs_core/analyzers/narrowing_go.py']='123895581adf37f5670b8e8f3b21bc2bf75f3495e82077a80039718324be5771'
  ['helpers/ubs_core/analyzers/narrowing_kotlin.py']='a66cafccabaf374337852d459772f15719d09267af3d69074af7d02f368b7e88'
  ['helpers/ubs_core/analyzers/narrowing_py.py']='60a2381463f1e7e8ff66e9a6a8564baa2aff1d10c2f107e3d24b23a4341bde9a'
  ['helpers/ubs_core/analyzers/narrowing_ruby.py']='acfb2167d8fb402c91033309484a75f321f34e71be613a348244b74ddf4c0deb'
  ['helpers/ubs_core/analyzers/narrowing_rust.py']='54ec29f4297cbe37aec4cdaab276a6880bb16fd93377ed060e90c5de98261b12'
  ['helpers/ubs_core/analyzers/narrowing_swift.py']='2a7971f6f6a858eb73d1f898a6fdd039a56be405222877eae3890a6343a52a73'
  ['helpers/ubs_core/analyzers/regex_swift.py']='5b9deaf28d737938576007d17cd3a9e7c99f21d4fed597aefb0e0173f3507bd4'
  ['helpers/ubs_core/analyzers/sec_archive_entry.py']='b700a9fbc7cf6fedfc08a0ac672c1ff67af4de9bc5d2e8abf03bf7dbf7d4b8fd'
  ['helpers/ubs_core/analyzers/sec_cookies.py']='5cbec1b832c1b04c668c0f38545854733e2d20819bba9ab7063dc692063208bc'
  ['helpers/ubs_core/analyzers/sec_cors.py']='efc532eb61761398d59e33319a40dafbdb5ed16774be3c93eb5193ced5bbe210'
  ['helpers/ubs_core/analyzers/sec_dangerous_html.py']='f80aae62390f26946fdbc64f40bdbecdc967d5433b2e8dd79245c1901c9c7c22'
  ['helpers/ubs_core/analyzers/sec_fetch_abort.py']='37ea371df2a5943e2cf13b8070ae2c4083cf6c11f4cbd8aade5d5a11fc180fc3'
  ['helpers/ubs_core/analyzers/sec_hardcoded_secrets.py']='5e38aeb82cb5e75e544e009cd8fbf4ef7e2661e620e417e8a357edba809a7673'
  ['helpers/ubs_core/analyzers/sec_header_injection.py']='3008207e72535bba946255e6789ef4003aa7c9ed2090997092167a2007675f4b'
  ['helpers/ubs_core/analyzers/sec_host_header.py']='e0bfe3a85dbd544e29d1705244a2cb7264976a7e470133be546c484142da0a89'
  ['helpers/ubs_core/analyzers/sec_jsx_target_blank.py']='c87dda288f0540c0697a879d15e3ca9ee0e18319f6b3d8baca531442eec73633'
  ['helpers/ubs_core/analyzers/sec_jwt.py']='a4d070ff992b35f00d21e43eff08a2d45d26e21ba5644b56717ebae618bb4fae'
  ['helpers/ubs_core/analyzers/sec_message_origin.py']='0ace26ac79615904e0a6ba682b211d9983a0612a3b8397151b801169e04c8d90'
  ['helpers/ubs_core/analyzers/sec_open_redirect.py']='a027382c8c31454ac7a7ec2e28673113b430393317597f605d199594e08d8b40'
  ['helpers/ubs_core/analyzers/sec_path_traversal.py']='d2f507fbd342d1183d049d059692ca59b04f97fba4c915a2e9a692afe5854927'
  ['helpers/ubs_core/analyzers/sec_post_message.py']='040689e7ab991f482833169993e36f79cd44679a1fd228393f843649b15476be'
  ['helpers/ubs_core/analyzers/sec_prototype_pollution.py']='349b4ad00658de88c6e5469a40b481579060161086d8c3514102d4f139912cd8'
  ['helpers/ubs_core/analyzers/sec_request_body.py']='73a29cd0594845e288933e05374ae95f227f608c43094fc28f8b88059aed8314'
  ['helpers/ubs_core/analyzers/sec_request_regex.py']='4186b6954e5f53fce271da4a3454d40f89371608e731d77e4e3f26aae85b53ad'
  ['helpers/ubs_core/analyzers/sec_reverse_proxy.py']='0b37cf050e439c023732068eefefcfe66bde8e0865c18b5c1ad1b3c141862c11'
  ['helpers/ubs_core/analyzers/sec_sql_injection.py']='0244a19a60d696852fef4505647adc622c3519b9f28583ebb105112fc2faaefa'
  ['helpers/ubs_core/analyzers/sec_ssrf_fetch.py']='3c024e7c686ec96424088b5d1c9fd49994df17cc3aab16064e03c99e19a5ad97'
  ['helpers/ubs_core/analyzers/sec_tls.py']='71a07fe8df3f3d1fbb2a3a891d0ad8b25fd64b62cc95de01f3095ff702b12f10'
  ['helpers/ubs_core/analyzers/sec_weak_random.py']='0f9d154a13c4ade1be85688eab6836349e3d2a5c18e69908167f51d4fa0d23b9'
  ['helpers/ubs_core/analyzers/spec_block_function.py']='03d55f819d880b390ddfcd2eaf387a8d01b33ebe66574c6d46ab55066862b91d'
  ['helpers/ubs_core/analyzers/spec_division.py']='9faa40500c7f39e19d34d2bfb13e10bbe73e353aed7c827b56bda37b40d8147a'
  ['helpers/ubs_core/analyzers/spec_hooks.py']='1a21236556c0af2b517da2dde5ea7a568c390ccc6a250ea80676d537b34e75d5'
  ['helpers/ubs_core/analyzers/spec_switch_fallthrough.py']='da5f6acc062f3ce383700dbd14cb7b80c64ada9d42f10a27975f5ae65a592e94'
  ['helpers/ubs_core/analyzers/spec_typeof.py']='caf8afb8901bec9b100c0880bbbe0dded58a08f15fcef94816b12dcec5b03293'
  ['helpers/ubs_core/analyzers/taint_cpp_redirect.py']='194ac747250b1dd3057e0c45ffd3b9469a5086a9fefd6d5f029dcfcf0136efb1'
  ['helpers/ubs_core/analyzers/taint_cpp_traversal.py']='cc6b1cd0ac6eef27698549259367e5a9634b51f57778b58d755b486351460dfb'
  ['helpers/ubs_core/analyzers/taint_csharp_redirect.py']='4591294ab7eb34f4311d85632089309b8209669d6b24ad78440e2498322946bf'
  ['helpers/ubs_core/analyzers/taint_csharp_request.py']='335991ef7305778f026f87cbc9760e8f117f7cd0994edd4265728d2c129d8fbb'
  ['helpers/ubs_core/analyzers/taint_csharp_sql.py']='8ac70c583e8c2bf3f2a3d9de02166dd1d90409dd79527ef387954dcf08e2c90d'
  ['helpers/ubs_core/analyzers/taint_elixir_redirect.py']='e79bcfc31754ce3485c2e3c398133eca890c3023ec135d410f72b3adfefe7da8'
  ['helpers/ubs_core/analyzers/taint_elixir_traversal.py']='e1c225beb83902d020e03fa80de18ca6978c1c90ec2637320eac00cbc9f52f99'
  ['helpers/ubs_core/analyzers/taint_go.py']='a0491b85cb21fc0d221b4b70b9ee9e311e722998f3e77ec01f9e51e1c38ff40a'
  ['helpers/ubs_core/analyzers/taint_java_redirect.py']='3d4a9cd1b16a84509828e845774c89968d753beda46ff4b388fd438c4304e0ed'
  ['helpers/ubs_core/analyzers/taint_java_sql.py']='efc35e1164de70a576519a96513be11b0fd051d4c344c51d76c86e7e6c655514'
  ['helpers/ubs_core/analyzers/taint_java_traversal.py']='e248075f7c473de74412c2ef8c0a55fe6c482a4b95a93d016195be40a710da21'
  ['helpers/ubs_core/analyzers/taint_js.py']='0f7fc894713d40e7401240adfc5f8ea66aef37a0bb7388ca0fa34f7a7c53d2e6'
  ['helpers/ubs_core/analyzers/taint_kotlin_sql.py']='3a18da9e4dd7bf0469ee0119a87866c1f33502ca59ca78456e2aff8e6ac7dfda'
  ['helpers/ubs_core/analyzers/taint_php.py']='203035813900408c7d44f7244ab7e771225aeaa7c5e78a838049f031639411ed'
  ['helpers/ubs_core/analyzers/taint_py.py']='27aa4b162187f0190cf8c4fb0782cf5105f8fe59bbe5216d21f3d33f31546b17'
  ['helpers/ubs_core/analyzers/taint_ruby_traversal.py']='9f0607890770751d4821bb92319780f87c5632145d284967a0771cf352a6832d'
  ['helpers/ubs_core/analyzers/taint_ruby_url.py']='c7e98db31c900d364f427aa65bc2ff3bb62a8a28f05b7dd78357b6f6a51a7a84'
  ['helpers/ubs_core/analyzers/taint_rust.py']='920988d1dd05014915d79e22127535735db0dee0ae25448f57cab89451fb4987'
  ['helpers/ubs_core/analyzers/taint_swift_redirect.py']='a0503c0be9ed06e4e68b9f4dc76748d6149bfcda12959a350c874a663ef23eda'
  ['helpers/ubs_core/analyzers/taint_swift_traversal.py']='1b60ad4b6d15f5d6025d0d0febcdc159ffda68d2e1b5db569deb8082696cd51f'
  ['helpers/ubs_core/bash_rules.py']='21fb455e701160e12575b478819d8f52254bca2d672d6962992a93d8c186a20c'
  ['helpers/ubs_core/bash_scan.py']='aa224e5c69fb20539d1868f42a95b46c11eedf1b7c0ff6727d459acbe80c08ef'
  ['helpers/ubs_core/cache.py']='6fd060c27570c178c46015005fcc429b36518f1de77aa4abf3718165af53ce1e'
  ['helpers/ubs_core/cli.py']='34a5c324970f1d2391fcada7de2ec7e0dedf11e0242b3ede0913a55645226237'
  ['helpers/ubs_core/cpp_detectors/__init__.py']='b74840d5af31f44ac13703f3c66f6968af4207c9ce08f3c0ae1010cd62c4fabd'
  ['helpers/ubs_core/cpp_detectors/archive_entry.py']='dd83df898f3c856fa769aaa754e172afc2607b22202a9984dd11802bb429b44e'
  ['helpers/ubs_core/cpp_detectors/async_errors.py']='e3c03636656ec7477e940520806c8080326ec7700b0e0cb6d702c8ef0a0ed713'
  ['helpers/ubs_core/cpp_detectors/header_hygiene.py']='5b894ce2805204600acab3cd43dc33844ee11fbed70bb59b3f3dac10c46b0978'
  ['helpers/ubs_core/cpp_detectors/header_injection.py']='f6e4253eb6cafa79a1b48266e270a4991a7f3f3c2cbe5a3c38b1004594f65982'
  ['helpers/ubs_core/cpp_detectors/outbound_url.py']='a0b44a85ac5d4db4b2b71f9c28ce2a849216ca6bae5fdd7b33b144f81fbd4b61'
  ['helpers/ubs_core/cpp_detectors/perf_io.py']='ce1652f1df907eef5045dd3bf7fce90e1cc9b914d34a8ad1297c19b14827b26e'
  ['helpers/ubs_core/cpp_detectors/quality_markers.py']='576cc873818cd5c4a5c5492715486adc90f20a91b2d3f1cdb59f73e5730e0a24'
  ['helpers/ubs_core/cpp_detectors/weak_random.py']='a627ef2a9c7095527b3d3b679263d2de58380754e81f69bfd04c0387ff4062ef'
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
  ['helpers/ubs_core/cpp_scan.py']='9cd1b02c203f813168a758f599d1354af9b5b6c3af7b5f4566188b4ba0eaade8'
  ['helpers/ubs_core/csharp_ast.py']='d32188bf0f4eb1cf3e03ba0ff9d4697e96d4c381ac008f2f78d026ad49964597'
  ['helpers/ubs_core/csharp_detectors/__init__.py']='bf8a8383f6143a5e585e78fec84580e86c40ee180f05a7bbce386c496d420063'
  ['helpers/ubs_core/csharp_detectors/_common.py']='19c996f1744588d23085e986e50a461089af0c8d350fdd4e950d6f71074e4dac'
  ['helpers/ubs_core/csharp_detectors/archive_extraction.py']='5ff1a5e13d7a5dfc861f8fea629c5771f3a21b5c8d8a7f6dabadb897d91c7f5b'
  ['helpers/ubs_core/csharp_detectors/header_injection.py']='e99fda135d238e6b3bb22dbd18b7fb6cf080ffe7ed6312c4ce80cde361030421'
  ['helpers/ubs_core/csharp_detectors/outbound_url.py']='f399d71499d429cd3e0366d086bc92276a4e44900734bf994d4f0288381ed282'
  ['helpers/ubs_core/csharp_detectors/security_randomness.py']='504ae2cf71ab4fc75c5ee1a785878f67c605d15b52815d364d0642d844e6defe'
  ['helpers/ubs_core/csharp_patterns/__init__.py']='1dfc28708bd9a28b904a2665f0532439f4b83c6ef3a16ea8cbdfa2083240bc57'
  ['helpers/ubs_core/csharp_patterns/_result.py']='4d3a991a8cf883274559fc9aef62b23a50ef964da32b3165a8088eea33571a40'
  ['helpers/ubs_core/csharp_patterns/_table.py']='23510fb14062fc9b9f1dda68a123d1149a16e8ecb869d246f74fd0e5247ccfc2'
  ['helpers/ubs_core/csharp_patterns/async_locks.py']='e5e8bd55f6ba99af0db0fb4ae2cc111e2d93094fa83bb27a3934511c474da400'
  ['helpers/ubs_core/csharp_patterns/concurrency.py']='38fa02b6645436087b1d193c07b5f5d5b4b960573bebd0e821f9c2f1d764190d'
  ['helpers/ubs_core/csharp_patterns/correctness.py']='927a55db74451ee875d9db082d6cfb2caafc9587e7e60685a7eeae6d8772a9c7'
  ['helpers/ubs_core/csharp_patterns/foundations.py']='9c581ac68509fe2f8f708788d80bb38f1b24266350fa30eb3b48d27a09b6cb9f'
  ['helpers/ubs_core/csharp_patterns/quality.py']='eac32fcf8ce9ce593f19c2089abf89916b72cbd6ea1005ac056d23a178bb69cc'
  ['helpers/ubs_core/csharp_patterns/security_rg.py']='456a7b2ad7855b36376dfa8daa34c1d6449eb7b07d86a2b5b654180307665ec1'
  ['helpers/ubs_core/csharp_rules.py']='9bb25fb10282e3afe1b20a707b6888a2a769024f1f8c71860af5b31dc245ecc4'
  ['helpers/ubs_core/csharp_scan.py']='592310afe78f7ce36faaa6c6c9f1468a2497a99c9c271ab0d409241be0c625a6'
  ['helpers/ubs_core/elixir_ast.py']='2baaf4c16579a7f795b180a455b655bee52d3817dbc6fa228d6e6573f5b0f161'
  ['helpers/ubs_core/elixir_detectors/__init__.py']='9e08cda01f060bb0e804ad7276b680e12f8f7451158b2ba443bc001d2f086faa'
  ['helpers/ubs_core/elixir_detectors/_common.py']='ffedf7e7db651bb0738e999fa2cb6f175cd97b52fa3bc857a809be54ac887eee'
  ['helpers/ubs_core/elixir_detectors/archive_extraction.py']='697d4e657aed76d3192d20ed29d679386c932b79893cd7e0e53241f44a28a72c'
  ['helpers/ubs_core/elixir_detectors/config_runtime_exs.py']='015a6946ce0ae56280e14bcbbdc756a78f1aca1cd3410193dd84edfd7b48dcb1'
  ['helpers/ubs_core/elixir_detectors/file_result.py']='7b372cd2af0c72b792a2567bb1c79b9529a8484a812b7a6d5aca3e8e2fe3136e'
  ['helpers/ubs_core/elixir_detectors/hardcoded_secrets.py']='c7dd4284a1f478da2adc133c4fdbeb9d8517b4c4a741858304553394b254179a'
  ['helpers/ubs_core/elixir_detectors/mix_lockfile.py']='68fda905182218603ad78cfa65910d9b219cc9bcea34c8fadd6c1a749106b5ed'
  ['helpers/ubs_core/elixir_detectors/outbound_url.py']='13cc62e617f4e7bf2094f8bef3f24879f11551b4923fabe42cac05b643066b1b'
  ['helpers/ubs_core/elixir_detectors/response_header_injection.py']='ad4560572ab7e0f89e82b028822d9f4e2a7cbb4a8ef43525aca4df53e0003a6a'
  ['helpers/ubs_core/elixir_detectors/security_randomness.py']='d03cc13a5172c594767b763cb19f5bcefb58e34043c9b612233455454c81310b'
  ['helpers/ubs_core/elixir_patterns/__init__.py']='7148f31ca91d7ec307a64dbcc99bb9ee241580143719b48c05aba2fa53ef8641'
  ['helpers/ubs_core/elixir_patterns/debug_quality.py']='a1c59c62bf985511f25388c83d8e2d69fd0cb9dfdc49931a93a972e556553c9e'
  ['helpers/ubs_core/elixir_patterns/ecto_concurrency.py']='5b62edda642fde35481d24c9fbe1e3af10bf4892019eb68be8d88f7f2970e410'
  ['helpers/ubs_core/elixir_patterns/foundations.py']='5d82afa7c982924d3df36a1702158dc4e59ff7721ad396826fbb60dab6d02c66'
  ['helpers/ubs_core/elixir_patterns/mix_deps.py']='bbf8f009f9d25873c918e9fcb4b23b185d9f9a7e467bd36d1638a53576d42127'
  ['helpers/ubs_core/elixir_patterns/perf_misc.py']='5248f2e9c2b845736a9d95cf301d791f474f1d82fd063f170c4c702f54960f7a'
  ['helpers/ubs_core/elixir_patterns/phoenix.py']='533afcfc1a90e24ad2ce002a76d2433ef2203f7034de9047a84c7a67eb0f36a4'
  ['helpers/ubs_core/elixir_patterns/security_rg.py']='3e6987c5e596800f719506f50d5a203eb70942097ff98aa71321f63e53c186f7'
  ['helpers/ubs_core/elixir_rules.py']='3f8ca9a8d1cd898588005bb925b5b931d8d3947d41e7c235c48b9d8033ed65e4'
  ['helpers/ubs_core/elixir_scan.py']='6b9ef4f97ad0457bcc0e3dd0766d5ed6e7edb3c518da17ce5d1be782555bed64'
  ['helpers/ubs_core/explain.py']='8e4546ee32e0d9ce06314b233e76033cea3078c5f5c8ecab69117e1ab3434cc0'
  ['helpers/ubs_core/external_tools.py']='4a66691cffa87c4c4b8191ac7355fee395d3b0369a288e381a11522accc69a48'
  ['helpers/ubs_core/findings_merge.py']='a592789f727296e332a1b79f441a20234f8f7686ed738de5152fc4981781b6fa'
  ['helpers/ubs_core/go_ast.py']='f459406b41a7aa4b5fd0af7cce5a961811d0bffd499fb99825ed631ec96d0f0d'
  ['helpers/ubs_core/go_detectors/__init__.py']='70cc7219036b6d704d9a9e9414c623b4d0eb65ef26e12aac19c8ba6aa055ba41'
  ['helpers/ubs_core/go_detectors/archive_extraction.py']='f0b25a44ccf1b0f374feb9e8fc7486b618eccf817348151d1a0583b7496fe6a7'
  ['helpers/ubs_core/go_detectors/cookie_security.py']='01a2a52f673b873a498f1148dff0db0942b66fc8b5efe6f59b40f9441705dff3'
  ['helpers/ubs_core/go_detectors/cors_credentials.py']='0c208dc7d28afb1f30738458d569ef3ef31dca80956dcd6f1b90cf4d7eba94b6'
  ['helpers/ubs_core/go_detectors/hardcoded_secrets.py']='4c35daff98f3f69ca988cd9f5b67cf0274824b74039ed40850422fba95e0152c'
  ['helpers/ubs_core/go_detectors/header_injection.py']='673dd83e7f58272b5e5c62200eedc55deef0e4b211e027372eefdcb65a1b3f87'
  ['helpers/ubs_core/go_detectors/host_header.py']='b011f795490f09175b668afac86ed5c8c5b327e9042fff66a0c4bbbc3edf57dd'
  ['helpers/ubs_core/go_detectors/jwt_verification.py']='a19f74711f77049390fbaf7c59df16b99cd7711e3acede4b3ec32bddf5a5c74a'
  ['helpers/ubs_core/go_detectors/open_redirect.py']='ebf5bedf0c9066c81fcd65db58ac28b5249a0cf6cb8fbd4e9b894ec230a20891'
  ['helpers/ubs_core/go_detectors/outbound_url.py']='2ef5c3d08cb73744b7b34570499de14c1d40fc15e0a953461d55f8c8a3a8b8a4'
  ['helpers/ubs_core/go_detectors/path_traversal.py']='cdeef91768902a057959c1bf92cde3e7f94f84c37c6c4f18bd4bb1e3425f1ae6'
  ['helpers/ubs_core/go_detectors/request_body_limit.py']='32b3db6d9b6f31774175e5cea4ce11a76f939980e0f8151a6bf3087f9cbc7f7f'
  ['helpers/ubs_core/go_detectors/request_regex.py']='cc17497bac9d2838631e45fa85e7f6c9b6387bce874d0a9b394e2e8bb7f925ac'
  ['helpers/ubs_core/go_detectors/reverse_proxy_ssrf.py']='68665a94cf692f07389473d0abe811df37189fd2d86cd6128c97e45d3a46a5fd'
  ['helpers/ubs_core/go_detectors/security_randomness.py']='8f4c8ea857311b90c889f72288e413f7f30030c34ef9dba33d6f54968280693f'
  ['helpers/ubs_core/go_patterns/__init__.py']='30709d223fdb4167cbfa35569eb0ee2d2d3cbbc5fcf4803a2721f8ab41499cc5'
  ['helpers/ubs_core/go_patterns/concurrency_channels.py']='d7a5925f2cdc8aac511f9c5e9ee975b707beb1dee2802563058f32aa10266290'
  ['helpers/ubs_core/go_patterns/errors.py']='5cdca8346078b8d8e9923cb0294575a90049f14b9169bc5025de9123cd8e0c26'
  ['helpers/ubs_core/go_patterns/json_fs.py']='e561c18ac8d49ca7d3a0644381b5624d3d0e5f975c43a3056e4ad177538a7b6b'
  ['helpers/ubs_core/go_patterns/misc.py']='d23874e0fd10bc3538fd0c9b4eae998dbcb3076dd66020a6c764c7bb297506bd'
  ['helpers/ubs_core/go_rules.py']='a11e1036d06d313c102fda792f9842af7af69ad6250ec9dcb0c21ceaddc00ce1'
  ['helpers/ubs_core/go_scan.py']='56be3c22a3fe325ba24087b2c8e37c9da9959df9b2a8930d508e9605ffb085b1'
  ['helpers/ubs_core/io.py']='98b33056e732a07ecc5b5b38afa5d889cdb8bdbbba20c3ae73d165219706a3fd'
  ['helpers/ubs_core/java_ast.py']='50091504b3eed28240dea483b631b9bf47c45993ca1f2f9ff6daec6744eaecef'
  ['helpers/ubs_core/java_detectors/__init__.py']='ef52ffa7d353633e7bb1d1caa697c3b3bf83c6d7dc1ec111a3a4b71e2aa2d8f0'
  ['helpers/ubs_core/java_detectors/_common.py']='658ef921d7248ee9e95e3dff0887092e1133debe67c2b2b62aa21b7447584c73'
  ['helpers/ubs_core/java_detectors/archive_extraction.py']='3baedfebd06dda3484f9037f9992247822783b9f95f91b83bacd150377f394c9'
  ['helpers/ubs_core/java_detectors/collections_foreach.py']='624b5e7d9e786505c3684d405678ef1038301521ad022a7cfddf6562f3b1ddc1'
  ['helpers/ubs_core/java_detectors/control_flow.py']='e1516a6640d98f17a6d4cd01a143a01750538c0d846778773c82bcdec8e8a213'
  ['helpers/ubs_core/java_detectors/equals_hashcode.py']='6d3b0a2ead940158573c0b420e19f9032d9c82974731889647b552bb9280b546'
  ['helpers/ubs_core/java_detectors/header_injection.py']='9f765648e8bda0879f90c2e899a22967246d5baf593583dda5f3f63797a96660'
  ['helpers/ubs_core/java_detectors/io_loops.py']='6558da8527423e18ba583c186834b84bc49f016437a758b3e648ff58c7cda3c4'
  ['helpers/ubs_core/java_detectors/jwt_verification.py']='6817ed977565ab3071b0ad06f42eb6eb731ccaeeb704601f568b07d7b9072a95'
  ['helpers/ubs_core/java_detectors/optional_get.py']='329711a0236c748781ffc5c752373702129f4b5bdfe61b1777bde90c9868e2e1'
  ['helpers/ubs_core/java_detectors/resource_leaks.py']='968ae0ef4fd12311029544a00eb4cea5330ac0860f8217b729fb9d1798641282'
  ['helpers/ubs_core/java_detectors/runtime_exec.py']='3666a49e433faf20612cffdf410bfaa95b677ac38116ed9f3629a3c308b11c21'
  ['helpers/ubs_core/java_detectors/security_randomness.py']='441e2fd035994c0bb871fb4878825eb14cebbdf7e71effe08374503089dca56f'
  ['helpers/ubs_core/java_detectors/sql_concat_fallback.py']='0c1e8b43f15761e3e2e3ea50e951588ff1bf64ba846e2d8735e1250595f71a88'
  ['helpers/ubs_core/java_detectors/ssrf_outbound_url.py']='6b579099437189b1cacc79233bf8a1aa7fb2bd3be7520533be88770b052448e0'
  ['helpers/ubs_core/java_detectors/streams_concat.py']='399937037d6709a368e1b0784d82e0d51204775303a38f23dadef447c04d8208'
  ['helpers/ubs_core/java_detectors/tech_debt.py']='7859fbefd0dc7f35518572e16e45a2b2e54756324a852a34fce0dd9f066e4b19'
  ['helpers/ubs_core/java_detectors/tls_verification.py']='714c193377e7989280f5566573b9641ac8b1e46d600268091eb45f0eabb32b14'
  ['helpers/ubs_core/java_detectors/trust_manager.py']='9bc3e4216355fab16be40c2f4780d29437e04ac5f53a7a1c14baa6ddfeef3e6d'
  ['helpers/ubs_core/java_patterns/__init__.py']='8b7de6cca7d1b61a2884216d2756adabf3ad7d2a08bea8defe3e8d305452e9c2'
  ['helpers/ubs_core/java_patterns/concurrency_io.py']='9bee9f2911a23993806d3e367339b99af70eaf4946cc979b21d18bc8a35e383d'
  ['helpers/ubs_core/java_patterns/foundations.py']='64b5f87535eaadf3be0ba10e3f7ac8b05e8c114f17ac1bf25596d71c1078b1b5'
  ['helpers/ubs_core/java_patterns/quality.py']='2e037fbc04bd6d9e0896357612fd6e195ca9aecc1b0ab38934335b297eba0475'
  ['helpers/ubs_core/java_patterns/resource_lifecycle.py']='0a8f38417321c16bbcae6bdf42aa68c15d6f6e3ca6d70a84e3aa29c6f6ac5d1c'
  ['helpers/ubs_core/java_patterns/security_rg.py']='74fa31c87ae8fe8f51e17c60899c1349a10675fd8ad2d87a666c4df4dc39740f'
  ['helpers/ubs_core/java_rules.py']='262f879a44ab577e08bbfd6d450ddf5cee9154aa3db8b162b9cc1be2e80b7b82'
  ['helpers/ubs_core/java_scan.py']='9a88e18d33da42838c5f9affc2f2a1ae9be6944d311c7b1dafcbbcbae1614361'
  ['helpers/ubs_core/js_ast.py']='110771cb6c4fbfd50ccb860b5b85757955147b372d7677f4d98409a586463963'
  ['helpers/ubs_core/js_modules.py']='644c2b23476fce27f353596a715cc035b036290d8fa7ec8f3648a3fe6ab2beb2'
  ['helpers/ubs_core/js_patterns/__init__.py']='0529d2e73e888d4ff04bea182fb241f259eee345d04ef3bb19478b74e5353851'
  ['helpers/ubs_core/js_patterns/debug_quality.py']='de6e0c36dfb9e06691b65ec5e8fd7739ec22840ebf5c487801f998218bb78172'
  ['helpers/ubs_core/js_patterns/eq_regex_dom.py']='0376a1d01052df36111b4619bb7befecd265693a03fb4dcfc1011a77e6f88b33'
  ['helpers/ubs_core/js_patterns/fn_parse_perf.py']='1cd06fa7c281e2a26d1979b01008dbea8b900bf6a2444ddc4b016e02362ed89a'
  ['helpers/ubs_core/js_patterns/null_coercion.py']='0d0f961cf993c6cacf6b2d873f960ed00e713a8a5ad3d4d21f93ef410b6c45e7'
  ['helpers/ubs_core/js_patterns/proto_vars.py']='b4fdf0f9ccfa5b4133f12f53dc2813fcd618530756c9a299ed16e1d0c0388b31'
  ['helpers/ubs_core/js_patterns/security_node.py']='077defd8829eeb7bf2dc9ceee5e801c7fa3622c3386fb01c36b44447d650037f'
  ['helpers/ubs_core/js_rules.py']='96ac1be076c6019e2d7cbf18c780f918417c4c62b16e77481c0ee3a47e61222e'
  ['helpers/ubs_core/js_scan.py']='88b1ce717d67a4a815c957e00b03884ee4dbfb5f6c2d8fd84d4d90bb94a3d7e6'
  ['helpers/ubs_core/kotlin_rules.py']='6dd77c16cd9fbba0e555162e2a8f378858ce70b4d70668f64ec8142983ba3c35'
  ['helpers/ubs_core/kotlin_scan.py']='df870233b07e656cba3c82b146f8f7cac10679ee6011d0f70fd95d230b7338e5'
  ['helpers/ubs_core/lexer.py']='8ad2f1ebf45306e74042efa330052a765b345568194570dff5480af215531023'
  ['helpers/ubs_core/occurrences.py']='ba83124bd2bbcda620b532b76e24caf6c5c603cdddc800b338d67a1bf4a800e9'
  ['helpers/ubs_core/php_frontend.py']='301b810b4addcc0c6c055cce15c2e0fdbf505cbd9ecd159d9a3975f3a77c8658'
  ['helpers/ubs_core/php_scan.py']='92349ae54795e4d1dbbc6ffd5846273ad11b33ed9cb006432ccea9f5efe57724'
  ['helpers/ubs_core/prefilter.py']='adda4a20eab6cf84bcb9691b9767af76bf46d0eba90bf0e4c000fd97a8996d6f'
  ['helpers/ubs_core/py_ast.py']='e5da8b583cfd381b89b8ed64c17058c1c2c06030cb1b826e61a9ceed3f644765'
  ['helpers/ubs_core/py_detectors/__init__.py']='15eb6a55a8b3c0f2df0336576e593a7ce9af5e0685800262cba9b54b7d8c22f4'
  ['helpers/ubs_core/py_detectors/_pathlike.py']='90b1b71bce5606f1a5684c9122fc14ac27bbbf5ba4ebf455343e29145a0b2e1c'
  ['helpers/ubs_core/py_detectors/archive_extraction.py']='5c6503eff475e6a733cbb5fabf4de9a3c6241e3a318f8f501f6baa2e3f1c73d7'
  ['helpers/ubs_core/py_detectors/command_injection.py']='f7da68d7d37c027782b4a43ff6fd34127fdb5f09e78bf346af70222caaf1191e'
  ['helpers/ubs_core/py_detectors/cookie_security.py']='1bb8a14090c233ddb7eda5f5d3ae084ef8af50f803849e55c062a41ce6be4a7f'
  ['helpers/ubs_core/py_detectors/cors_misconfig.py']='0597fa5eba8297b7783e105d031b751dbeab4485e848de2f4525c57ad81adfb5'
  ['helpers/ubs_core/py_detectors/crypto_misuse.py']='bda7474dfca2f70779dff829ef3712a2e7057f9a98f9e55740b8aea947150e24'
  ['helpers/ubs_core/py_detectors/csrf_disable.py']='e9d8f3978ceb95526e202574ec2f0cd5d9b7e03b85d154beb9cabe5401a1f799'
  ['helpers/ubs_core/py_detectors/debug_host_config.py']='96e242d18a3bd9c0c2de2838986b3884a66bde710dd1c4ba7a5aa7a136be3cf0'
  ['helpers/ubs_core/py_detectors/division.py']='b92a22ab7a84ddd54666b0a38f838e159885d02c97f2e2cc4fbf7d505b0859a8'
  ['helpers/ubs_core/py_detectors/email_header_injection.py']='7b3aa1d79cc7befed07499acf0c2cc8bcfee8d861b606c107c07558b5ecb1e26'
  ['helpers/ubs_core/py_detectors/file_permissions.py']='2b6b1dbef7e63d8532e26b1b65682371b730776a38c17bd2fbae8b93cad25b9e'
  ['helpers/ubs_core/py_detectors/hardcoded_secrets.py']='73ad17109ea000b7ddd607338fc1236ddef7cb285b4abd242832fa18efb8b81f'
  ['helpers/ubs_core/py_detectors/header_injection.py']='cdae9ddf69c4991b30e391158bc229ce1b78b0608de70773c28a847c246159a8'
  ['helpers/ubs_core/py_detectors/host_header_poisoning.py']='03f9669424e8c2f0d9b8047f139b77dd4f9687c088a6f5ff6498dc1249f62ac4'
  ['helpers/ubs_core/py_detectors/http_timeout.py']='6e1caa48aeec3b8d7ad9180a5aa1b0e06800cefc791ea719b1d500ade6688a3a'
  ['helpers/ubs_core/py_detectors/index_arithmetic.py']='01430c582dcd112cb7949abfd185f15a783be01b046908cf1a685c6fc1614120'
  ['helpers/ubs_core/py_detectors/insecure_random.py']='894d52d6ea789334e4b0646725431e2cbba73670b957b317d6d58be8821223cb'
  ['helpers/ubs_core/py_detectors/io_open_checks.py']='3e46d3364dabcb286242792c3bdb96e920adbcc707ef378a57f400cb8baf91eb'
  ['helpers/ubs_core/py_detectors/is_literal.py']='6d4d6c4c4df8816e561759e251d2c412e7b81a9c690a814b4c05a90f719bf4f8'
  ['helpers/ubs_core/py_detectors/json_loads.py']='4194a9f5a0704e0dfa3d30acc8c0553a46b4c02ab5f4408cf6851ff84e8ce5f7'
  ['helpers/ubs_core/py_detectors/jwt_verification.py']='d96ea02bb64da7dd9e5f5e6edb1c15f9c147f47c4628758d8e878693ee4d7284'
  ['helpers/ubs_core/py_detectors/ldap_injection.py']='74e982dcf612dd27d7abe7587e4cfaa7b7cb49651b6d21f40a4a772f1b79c91f'
  ['helpers/ubs_core/py_detectors/mass_assignment.py']='b60fe05d739f80b061cbd3e4f2d564ea59d0b4049b4ed6fd0d93109716ec07f8'
  ['helpers/ubs_core/py_detectors/missing_returns.py']='f8766918f1f408b5ee4fae8a5c2df8e300ca203a3ec5ca200c04558365795cb5'
  ['helpers/ubs_core/py_detectors/mutation_during_iteration.py']='3857f060cbc9c627581875decb38e88ec64c879e8301bbc218accda1d67cde81'
  ['helpers/ubs_core/py_detectors/nosql_injection.py']='f825bb5935bc9c46df77f600e821013ad90a13c78787030ed87add37a2c31848'
  ['helpers/ubs_core/py_detectors/open_redirect.py']='14709874901b1ff86786e808e68b82056629740a52fe0db69cf15ead82c9124f'
  ['helpers/ubs_core/py_detectors/password_hashing.py']='709eb4e74cce9f5fcbb6fb10e9719dd364d2cb2c88559cd71830210d1e6b138f'
  ['helpers/ubs_core/py_detectors/path_traversal.py']='03c0d835713a2d6846159d86b0f1afd687005adaf4d95beb2f91619e47d209e4'
  ['helpers/ubs_core/py_detectors/redos_regex.py']='0e737e99523445cbb9f207b411bc5e4770beb98ebcb69b74a5f4e0f5c03d7a44'
  ['helpers/ubs_core/py_detectors/safe_html_xss.py']='36fa16d15f40cea00b83222f8bb48d9b4df7ca5a1da53b93e7ea7d7e39bd5796'
  ['helpers/ubs_core/py_detectors/security_assert.py']='dd64618f914f4ed22eecf4398a491773c21409f9cf8eab3d2b68ce20c38382e9'
  ['helpers/ubs_core/py_detectors/sql_injection.py']='9740007bd2f536758cf855a7e8806c6886a21b78768f4c6d077ecfc59ee8724d'
  ['helpers/ubs_core/py_detectors/ssrf.py']='308d99bbd50c4dc84d9b963a29a5f9668fbf0634a1a994c250f48965e4615f46'
  ['helpers/ubs_core/py_detectors/subprocess_timeout.py']='cbd909b9f5e0ca4b099c71d47561652eb5377433b93686db5d277c76fd1c8779'
  ['helpers/ubs_core/py_detectors/template_autoescape.py']='54febae8dd46dd63e2bcf4a1a75a1c78f0eba5bd9bff488962ca0585b1251755'
  ['helpers/ubs_core/py_detectors/template_injection.py']='23e7eaa53e92380718bfbb9d5e9518a5142a7796112a8ef2ad43fb9af7005e7d'
  ['helpers/ubs_core/py_detectors/tls_verification.py']='bae770e54a904f7b0cde12a1185a7bdea78886db12a5edd8e3e17516eeef2ef3'
  ['helpers/ubs_core/py_detectors/unsafe_deserialization.py']='5250a9b967e036a02914722a7ed0d50566af7c9e513c7bc9b96cf03f49f8a076'
  ['helpers/ubs_core/py_detectors/xml_parser_security.py']='397bb135e07bc41d07d6c6510c6024438c9bc923cb149ceb84390262a83cdc85'
  ['helpers/ubs_core/py_patterns/__init__.py']='7b9b471217121aa96668386d623d9be7ce5ce25e4866c548c3ac2d135faf768d'
  ['helpers/ubs_core/py_patterns/debug_typing.py']='8fd42b6759ed759ff5c2b17959b43e33bffde3e0fa75a3748fa40034a19a7626'
  ['helpers/ubs_core/py_patterns/flow.py']='fb71205da3706a05b257526767f9684f9595818e7d8255d1edb52b16c4ab97a3'
  ['helpers/ubs_core/py_patterns/foundations.py']='26f480b522bcd5e60351b872c282581810f932b8736eedc848fa983eec2f3376'
  ['helpers/ubs_core/py_patterns/io_files.py']='6f521478ceabb33daaec1b411448c932e22e7d878d983640297b21c8dee56b6a'
  ['helpers/ubs_core/py_patterns/quality.py']='9d5c30686414b7d4fc967347b7dc6dfbfeaa055ca8d1b117a7eb93c7e9c772e7'
  ['helpers/ubs_core/py_patterns/security_rg.py']='72add761922edef8a654d3e7798aa9393db604d0c7bc24c067300871018e8ffb'
  ['helpers/ubs_core/py_rules.py']='e35ae329bddcaed0a0e9d4244b9907455d00d76abe9d46d3dad2a69a1313db13'
  ['helpers/ubs_core/py_scan.py']='052e606fe94e10d4a2627f37dfaae782c49a4d3218bcf152924d6699fa7ec9bf'
  ['helpers/ubs_core/registry.py']='782a14714bc9e5e6d3d048572e1c0ef9a65639be5d3d3a691eae3c39f026a19c'
  ['helpers/ubs_core/ruby_ast.py']='fe4372cbd257e2725e4fd584dfa6cffa338a17b252962ea6062f5c22c152d472'
  ['helpers/ubs_core/ruby_detectors/__init__.py']='7b5ef3809ebd50136d741ade03d1c56b4b16053753dd79a8d90dd9021ebb0db7'
  ['helpers/ubs_core/ruby_detectors/_common.py']='5229306bddc9653d6aba535903fc2a738ccc7b3b4f2bea548aa5cc4bde3a1864'
  ['helpers/ubs_core/ruby_detectors/archive_extraction.py']='b2e4834324884524b800eb6e487569445054394e0c703e0e761725c7ed952491'
  ['helpers/ubs_core/ruby_detectors/frozen_string_literal.py']='8cef7c3646681b746ade6748d66d4e3dc137b01c5005d5797950953a40a31bc7'
  ['helpers/ubs_core/ruby_detectors/json_parse_no_rescue.py']='da8046ad2faba8d291cfac3b6a968d558959b8d0854b07b76b04b56c8baf3a06'
  ['helpers/ubs_core/ruby_detectors/open_redirect.py']='924db8e3800bf924bb14eb2ea26c8e20151bebb9e40576bd5803cb072e98d916'
  ['helpers/ubs_core/ruby_detectors/response_header_injection.py']='f31df6ed3bb8cca98629752cce3045aa9301d977a526ddbc75df5db0bcbdba0f'
  ['helpers/ubs_core/ruby_detectors/security_randomness.py']='83fa288e847e6d2e03a5741eb12507b7b489fa65e310a13b7ad7fac10dd84e9b'
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
  ['helpers/ubs_core/ruby_scan.py']='39f2ff36f39ee076010c0c430de7553533bca2bf6fde23533e20e02642322b89'
  ['helpers/ubs_core/rust_ast.py']='76c00c78d46a8232b51576283c1ea173b25ab453bb6967381e93aeab74f4af32'
  ['helpers/ubs_core/rust_detectors/__init__.py']='b238f38c0768683ea44b5bfd8e4e4c8a94e2bbbe98ddd77de32230a47bdd7799'
  ['helpers/ubs_core/rust_detectors/archive_entry_path.py']='2f49789409babffae2b1e1d36fdbfcb2dab50561b15610cde9af9494307cd019'
  ['helpers/ubs_core/rust_detectors/async_context.py']='d093a071c2a8c3b6603b4abec38d8e5bb8dd3f8f6aa0840386b9d0b39b3dd380'
  ['helpers/ubs_core/rust_detectors/command_executable.py']='8016691d5600ff52e2a1310b2238e3a88cf49ce98ed0ff147a43d86944b95357'
  ['helpers/ubs_core/rust_detectors/cors_credential.py']='ab31c4dd1cde153bd72e22e30bdcbcbd23156e4d6f8e7c9138b6c84b52ac1031'
  ['helpers/ubs_core/rust_detectors/drop_panic.py']='c9ee9b6455b6a034bb968ef572a4d63973a58458f7b7344226e95bd4bb53cf35'
  ['helpers/ubs_core/rust_detectors/format_literal.py']='3f4aaa7d3edf18bcbaf285bbca8adfd37f7e3cad1678e3353070a932df05ca5a'
  ['helpers/ubs_core/rust_detectors/hardcoded_secrets.py']='06620729eb9c69c3a2903b2c058ab8a9a451fb06224794d3dfc869b28a6c8b74'
  ['helpers/ubs_core/rust_detectors/host_header_url.py']='846b528eb628403247a028d80534214f6fa006cb7551d73150ff737f126f529c'
  ['helpers/ubs_core/rust_detectors/jwt_verification.py']='08177b038ab3ed0aaefcf4c09b2dd0d664e977493f04b6688b7d3f293a806a12'
  ['helpers/ubs_core/rust_detectors/loop_context.py']='c78aed29e2eca7487ba5d1176c7af7d2e7edaeb15283291b2b13cb806b0915b1'
  ['helpers/ubs_core/rust_detectors/open_redirect.py']='1a46af91b331690c946e62dae1926110fecf8a8a335d235571f2b68d84a5b619'
  ['helpers/ubs_core/rust_detectors/path_traversal.py']='349f549442c72df06cbac9f1bf7815c7ca72bdc92803a0479827a4c04422c32e'
  ['helpers/ubs_core/rust_detectors/redirect_flow.py']='42781a4d1f69361957b6d39e94ef4f1cdfc7319bb8ebc45b2ec256899a8adff3'
  ['helpers/ubs_core/rust_detectors/request_regex.py']='01b1ee7756d78a0f079cb785b69ac34ad655dc966fb9797ff9b13aa4962295e9'
  ['helpers/ubs_core/rust_detectors/request_url.py']='ec7351e3c5d4a1657a31bb1940f0ca4f4d6d785ae32f358b0462d73e1419a3b1'
  ['helpers/ubs_core/rust_detectors/response_header.py']='15ff23c265c318c0bd2b782c4b48e15332e07ffffbb1688955bac0700db6104f'
  ['helpers/ubs_core/rust_detectors/security_randomness.py']='cfd219ed421fc4211e30e77e2789e40ffc0e44ea80ae274e1c9ead013dcfe581'
  ['helpers/ubs_core/rust_detectors/sql_flow.py']='dc305f29001d1ac14d1f3f350d6e1aa7dece416d74fbada35e1f239316ffa8f1'
  ['helpers/ubs_core/rust_detectors/sql_injection.py']='9281711dad9bd7bd566009daa32d0fe76b12224a294ac5feb53db8fde01fd7d0'
  ['helpers/ubs_core/rust_detectors/temp_file_race.py']='1138d832a284bd37151eb81fd01aff7f81e987bf9710eb7bfd5409046a5536bf'
  ['helpers/ubs_core/rust_detectors/tls_indirect.py']='120501344abdcddf96e6a40c7b4b38617dd0649b83cfc81a0863f38027b0a755'
  ['helpers/ubs_core/rust_detectors/unbounded_request_body.py']='72eaedc5e99846eadaab246cb6398dc189f541ca14ae62e8a305a316bde69f5f'
  ['helpers/ubs_core/rust_rules.py']='d35a4d6cb061f0eb7ff70a799b415414016a3ce8e10c8331e8a9ee4b484be211'
  ['helpers/ubs_core/rust_scan.py']='af4fb4f18009ce8020a31b4dd691d3860fce89e8aa2e8eee90082cec3c93f572'
  ['helpers/ubs_core/scheduler.py']='ce86f556229c0875eb4ea11ef5958a7cd24768ffcce3b39d480a938d1c4879b7'
  ['helpers/ubs_core/selftest.py']='6ca3dd5e5534edc0b8a10e9aac1f80834f0d79b661c50c28bd00b33eb85bff08'
  ['helpers/ubs_core/shards.py']='cdc6ecab42bd962e65bb1ac1dc5e3f20b87c4d68632617286a2991274c0c98f7'
  ['helpers/ubs_core/sql_scan.py']='ad9a437fa901c01254d1f914c8082f45bd997d9deed7cd99be61c6d1096ac4a0'
  ['helpers/ubs_core/suppression.py']='8c0116a4cc61ba76262f59770d5799af8ba29eb876c43cbe0a275ebdb8b9bd3e'
  ['helpers/ubs_core/swift_ast.py']='53b2d380aeca310005241d1c43756dbf00d730163c2abbba4f8b1dbfadf799d3'
  ['helpers/ubs_core/swift_detectors/__init__.py']='e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
  ['helpers/ubs_core/swift_detectors/_common.py']='601e0f4ef42f5d007e26068f206c3dc8258de7939e642a84da248b26715ffe91'
  ['helpers/ubs_core/swift_detectors/archive_extraction.py']='e7d824d7d1c904460d8eb6851266da54b307e09fd53f0a46903aaad545e11cbd'
  ['helpers/ubs_core/swift_detectors/header_injection.py']='0333c50f4a0ce91bb29f9309be17f367a62b642089fdf855fbefb2d66e438c92'
  ['helpers/ubs_core/swift_detectors/outbound_url.py']='3d290c37fb9769dcebdda7f3e71b611ba40f98995c4514b3ff06dec176bd1579'
  ['helpers/ubs_core/swift_detectors/plist_checks.py']='a6561b6a48b3703a38ce66cb0ef1abd21cb84cc755e4a8f52d6241e2fd986b25'
  ['helpers/ubs_core/swift_detectors/security_randomness.py']='ad7ba629c0b237426fbaddd354d0dfd10bf97ab5e13fcddb2d25f63ad64ebdba'
  ['helpers/ubs_core/swift_detectors/shell_execution.py']='4e77f85b0a90d0e4494f186b629824046af8e65cacab69c3eaede493229babbb'
  ['helpers/ubs_core/swift_detectors/urlsession_correlation.py']='b43454593fe727bcc9c460656864dd89a4d77d3eb9577067fedbf8df5ad8b835'
  ['helpers/ubs_core/swift_patterns/__init__.py']='e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
  ['helpers/ubs_core/swift_patterns/closures_networking.py']='e9a53395a2ebcce3a6fa6b2271efdd67db47d489eee0457802ca1e874a27db7d'
  ['helpers/ubs_core/swift_patterns/debug_quality.py']='467066b5d51d8e0a523b6271407d36e9c44e2cfa5f15d597159011c81eb3137f'
  ['helpers/ubs_core/swift_patterns/errors_security.py']='6cc074c3909493dc6ea874ee8c5bc359ed07f1b6af657047cfb03d3d9db56539'
  ['helpers/ubs_core/swift_patterns/foundations.py']='c04908fa89c5bec54d1f88fd55c00da87114d7526b2f3a5e80aec288e52e125f'
  ['helpers/ubs_core/swift_patterns/misc_cats.py']='36b2aabee7e7acb2b7e41ddfaaf2d6a33be5901be68d11e2e54a53772efdf469'
  ['helpers/ubs_core/swift_patterns/threading_perf.py']='3282b7f8ddb9df8476c315872f828905bd3b71e539e8834289578d9bc7abdd46'
  ['helpers/ubs_core/swift_rules.py']='a832cfbaa194d08944d2cc18b4683eb0ddc78b845da8de77163cb6882d605826'
  ['helpers/ubs_core/swift_scan.py']='77a16e60dce843652c053d069dcbffce17c8ffae543bf77693d2e8254a3967de'
  ['helpers/ubs_core/taint_flow.py']='828316f978026b562f13a62e86abfefa83e5dfc802cc97151ecda6de107e16f2'
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

  local actual
  if ! ubs_sha256_into actual "$target"; then
    ubs_die "helper '$_rel': $UBS_SHA256_ERR; refusing to execute" 2
  fi

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
    local _core_rel _core_actual _core_expected _core_batch="" _core_line _core_digest _core_i
    local _core_batch_ok=0 _core_batch_valid=1
    local -a _core_files=() _core_rels=() _core_digests=()
    for _core_rel in "${!UBS_COMMON_HELPER_CHECKSUMS[@]}"; do
      if [[ "$_core_rel" == helpers/ubs_core/* && -f "${base_dir}/${_core_rel}" ]]; then
        _core_files+=("${base_dir}/${_core_rel}")
        _core_rels+=("$_core_rel")
      fi
    done
    # Hash every selected helper in one process. sha256sum escapes newlines
    # and backslashes in names, so each output line still supplies one digest.
    # A failed/unsupported batch falls back to the existing per-file verifier;
    # no cache, partial result or missing digest can authorize helper loading.
    if (( ${#_core_files[@]} > 0 )) && command -v sha256sum >/dev/null 2>&1; then
      if _core_batch="$(sha256sum -- "${_core_files[@]}" 2>/dev/null)"; then
        while IFS= read -r _core_line; do
          _core_digest="${_core_line#\\}"
          _core_digest="${_core_digest%%[[:space:]]*}"
          if [[ ! "$_core_digest" =~ ^[0-9a-fA-F]{64}$ ]]; then
            _core_batch_valid=0
            break
          fi
          _core_digests+=("${_core_digest,,}")
        done < <(printf '%s\n' "$_core_batch")
        (( _core_batch_valid && ${#_core_digests[@]} == ${#_core_files[@]} )) && _core_batch_ok=1
      fi
    fi
    for _core_i in "${!_core_files[@]}"; do
      _core_rel="${_core_rels[$_core_i]}"
      _core_expected="${UBS_COMMON_HELPER_CHECKSUMS[$_core_rel]}"
      if (( _core_batch_ok )); then
        _core_actual="${_core_digests[$_core_i]}"
      else
        if ! ubs_sha256_into _core_actual "${base_dir}/${_core_rel}"; then
          ubs_die "helper file '$_core_rel': $UBS_SHA256_ERR; refusing to execute" 2
        fi
      fi
      if [[ "$_core_actual" != "$_core_expected" ]]; then
        ubs_die "helper file '$_core_rel' failed checksum verification (expected $_core_expected, got $_core_actual); refusing to execute (run 'ubs doctor --fix' or set UBS_ALLOW_UNVERIFIED_HELPERS=1 to override)" 2
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
# ubs_list_files DIR [--ext CSV] [--names CSV] [--exclude CSV] [--files-from FILE]
# Prints NUL-separated paths (safe for names with spaces or newlines).
#   --ext       comma-separated extensions without dots (js,ts); default: all
#   --names     comma-separated literal basenames, included alongside extensions
#   --exclude   comma-separated directory names or globs to skip
#   --files-from  a file with one path per line (or NUL-separated): only those
#                 that exist under DIR are listed (meta-runner file lists)
# Uses `rg --files -0` (respects .gitignore, skips hidden and binary files
# the way the modules already do) and falls back to `find -print0`.
ubs_list_files(){
  local dir="$1"; shift
  local exts="" names="" excludes="" files_from=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --ext) exts="$2"; shift 2 ;;
      --ext=*) exts="${1#*=}"; shift ;;
      --names) names="$2"; shift 2 ;;
      --names=*) names="${1#*=}"; shift ;;
      --exclude) excludes="$2"; shift 2 ;;
      --exclude=*) excludes="${1#*=}"; shift ;;
      --files-from) files_from="$2"; shift 2 ;;
      --files-from=*) files_from="${1#*=}"; shift ;;
      *) ubs_die "ubs_list_files: unknown option $1" 2 ;;
    esac
  done
  if [[ ! -d "$dir" ]]; then
    printf 'ubs_list_files: source directory does not exist: %s\n' "$dir" >&2
    return 2
  fi
  if [[ -n "$files_from" ]]; then
    if [[ ! -f "$files_from" ]]; then
      printf 'ubs_list_files: requested file list is not a regular file: %s\n' "$files_from" >&2
      return 2
    fi
    local f delimiter=$'\n' list_fd
    if ! exec {list_fd}<"$files_from"; then
      printf 'ubs_list_files: cannot open requested file list: %s\n' "$files_from" >&2
      return 2
    fi
    # Detect the list's delimiter before reading it. Translating all newlines
    # to NUL corrupts an already NUL-delimited filename containing a newline.
    if IFS= read -r -d '' f <&"$list_fd"; then delimiter=''; fi
    if ! exec {list_fd}<&-; then
      printf 'ubs_list_files: cannot close requested file list: %s\n' "$files_from" >&2
      return 2
    fi
    if ! {
      while IFS= read -r -d "$delimiter" f || [[ -n "$f" ]]; do
        [[ -z "$f" ]] && continue
        if [[ "$f" != /* ]]; then f="$dir/$f"; fi
        if [[ -f "$f" ]] && ! printf '%s\0' "$f"; then
          printf 'ubs_list_files: cannot write selected source paths\n' >&2
          return 2
        fi
      done
    } < "$files_from"; then
      printf 'ubs_list_files: cannot read requested file list: %s\n' "$files_from" >&2
      return 2
    fi
    return 0
  fi
  local -a rg_args=(--files -0 --no-messages)
  local -a find_args=()
  local -a include_patterns=()
  local item pattern
  if [[ -n "$exts" ]]; then
    local -a ext_list
    IFS=',' read -r -a ext_list < <(printf '%s\n' "$exts")
    for item in "${ext_list[@]}"; do
      item="${item#.}"
      [[ -z "$item" ]] && continue
      include_patterns+=("*.${item}")
    done
  fi
  if [[ -n "$names" ]]; then
    local -a name_list
    IFS=',' read -r -d '' -a name_list < <(printf '%s\0' "$names")
    for item in "${name_list[@]}"; do
      [[ -z "$item" ]] && continue
      # Both discovery backends accept globs; escape literal basename syntax.
      pattern="${item//\\/\\\\}"
      pattern="${pattern//\*/\\*}"
      pattern="${pattern//\?/\\?}"
      pattern="${pattern//\[/\\[}"
      pattern="${pattern//\]/\\]}"
      pattern="${pattern//\!/\\!}"
      pattern="${pattern//#/\\#}"
      pattern="${pattern//\{/\\{}"
      pattern="${pattern//\}/\\\}}"
      include_patterns+=("$pattern")
    done
  fi
  for pattern in "${include_patterns[@]}"; do
    rg_args+=(-g "$pattern")
    if [[ ${#find_args[@]} -eq 0 ]]; then find_args+=( '(' -name "$pattern" ); else find_args+=( -o -name "$pattern" ); fi
  done
  [[ ${#find_args[@]} -gt 0 ]] && find_args+=( ')' )
  local -a prune_args=()
  if [[ -n "$excludes" ]]; then
    local -a ex_list
    IFS=',' read -r -a ex_list < <(printf '%s\n' "$excludes")
    for item in "${ex_list[@]}"; do
      [[ -z "$item" ]] && continue
      rg_args+=(-g "!${item}")
      prune_args+=( -path "*/${item}" -prune -o -path "*/${item}/*" -prune -o )
    done
  fi
  local using_rg=0
  local -a list_command list_status
  if command -v rg >/dev/null 2>&1; then
    using_rg=1
    list_command=(rg "${rg_args[@]}" -- "$dir")
  else
    list_command=(find "$dir" -xdev "${prune_args[@]}" -type f "${find_args[@]}" -print0)
  fi
  # Some rg versions do not report a failed final buffered write. Let cat
  # own the destination and check both statuses, even without pipefail or
  # when the caller runs this function in an if/OR-list (disabling errexit).
  if "${list_command[@]}" | cat; then
    list_status=("${PIPESTATUS[@]}")
  else
    list_status=("${PIPESTATUS[@]}")
  fi
  if [[ "${list_status[1]:-2}" -ne 0 ]]; then
    printf 'ubs_list_files: cannot write discovered source paths\n' >&2
    return 2
  fi
  if [[ "${list_status[0]:-2}" -eq 0 ]] ||
      [[ "$using_rg" -eq 1 && "${list_status[0]:-2}" -eq 1 ]]; then
    return 0
  fi
  printf 'ubs_list_files: cannot enumerate source directory: %s\n' "$dir" >&2
  return 2
}

# ubs_count_files DIR [options...]: number of files ubs_list_files would list.
ubs_count_files(){
  ubs_list_files "$@" | tr -cd '\0' | wc -c | awk '{print $1+0}'
}
