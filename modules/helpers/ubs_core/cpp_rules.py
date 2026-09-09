"""ubs_core.cpp_rules — ast-grep rule-pack generation for the C/C++ module (bead 1b9j.5)."""
from __future__ import annotations

import json
import re
import shutil
from pathlib import Path

__all__ = [
    "CATEGORY_MAP",
    "REMEDIATION_MAP",
    "SEVERITY_MAP",
    "SUMMARY_MAP",
    "generate",
]

SEVERITY_MAP: dict[str, str] = {
    "cpp.raw-new": "warning",
    "cpp.raw-new-array": "warning",
    "cpp.raw-delete": "critical",
    "cpp.malloc-free": "warning",
    "cpp.throw-in-destructor": "critical",
    "cpp.catch-by-value": "warning",
    "cpp.dynamic-exception-spec": "warning",
    "cpp.throw-string": "info",
    "cpp.throw-raw-value": "info",
    "cpp.manual-mutex-lock": "warning",
    "cpp.async-without-policy": "info",
    "cpp.atomic-relaxed": "info",
    "cpp.c-style-cast": "warning",
    "cpp.using-namespace-std-in-header": "warning",
    "cpp.auto_ptr": "critical",
    "cpp.std-bind": "info",
    "cpp.string_view-from-temporary": "warning",
    "cpp.move-of-const": "warning",
    "cpp.move-into-constref": "warning",
    "cpp.return-move": "info",
    "cpp.unsafe-c-apis": "critical",
    "cpp.atoi-family": "info",
    "cpp.rand": "info",
    "cpp.erase-in-loop-iterator-use": "info",
    "cpp.resource.thread-no-join": "warning",
    "cpp.resource.malloc-no-free": "warning",
    "cpp.return-local-reference": "warning",
    "cpp.module-global-fragment-include": "info",
    "cpp.delete-this": "critical",
    "cpp.vector-bool": "info",
    "cpp.unique-reset-raw": "info",
    "cpp.std-endl": "info",
}

CATEGORY_MAP: dict[str, int] = {
    "cpp.raw-new": 1,
    "cpp.raw-new-array": 1,
    "cpp.raw-delete": 1,
    "cpp.malloc-free": 1,
    "cpp.resource.malloc-no-free": 1,
    "cpp.delete-this": 1,
    "cpp.unique-reset-raw": 1,
    "cpp.throw-in-destructor": 2,
    "cpp.catch-by-value": 2,
    "cpp.dynamic-exception-spec": 2,
    "cpp.throw-string": 2,
    "cpp.throw-raw-value": 2,
    "cpp.manual-mutex-lock": 3,
    "cpp.async-without-policy": 3,
    "cpp.atomic-relaxed": 3,
    "cpp.resource.thread-no-join": 3,
    "cpp.c-style-cast": 4,
    "cpp.auto_ptr": 4,
    "cpp.move-of-const": 4,
    "cpp.move-into-constref": 4,
    "cpp.return-move": 4,
    "cpp.module-global-fragment-include": 4,
    "cpp.return-local-reference": 5,
    "cpp.atoi-family": 6,
    "cpp.rand": 7,
    "cpp.using-namespace-std-in-header": 8,
    "cpp.std-bind": 9,
    "cpp.erase-in-loop-iterator-use": 9,
    "cpp.vector-bool": 9,
    "cpp.string_view-from-temporary": 10,
    "cpp.unsafe-c-apis": 10,
    "cpp.std-endl": 10,
}

SUMMARY_MAP: dict[str, str] = {
    "cpp.raw-new": "Raw new detected",
    "cpp.raw-new-array": "Raw new[] detected",
    "cpp.raw-delete": "Manual delete detected",
    "cpp.malloc-free": "C allocation APIs in C++ code",
    "cpp.throw-in-destructor": "Throwing in destructor",
    "cpp.catch-by-value": "Catch exception by value",
    "cpp.dynamic-exception-spec": "Deprecated dynamic exception specification",
    "cpp.throw-string": "Throwing string literal",
    "cpp.throw-raw-value": "Throwing raw numeric literal",
    "cpp.manual-mutex-lock": "Manual lock/unlock on mutex",
    "cpp.async-without-policy": "std::async without explicit launch policy",
    "cpp.atomic-relaxed": "Weak memory order (relaxed/consume)",
    "cpp.c-style-cast": "C-style cast",
    "cpp.using-namespace-std-in-header": "using namespace std in scope",
    "cpp.auto_ptr": "std::auto_ptr usage",
    "cpp.std-bind": "std::bind usage",
    "cpp.string_view-from-temporary": "string_view from temporary",
    "cpp.move-of-const": "std::move on const object",
    "cpp.move-into-constref": "Moving into const reference",
    "cpp.return-move": "return std::move(x)",
    "cpp.unsafe-c-apis": "Unsafe C string/buffer APIs",
    "cpp.atoi-family": "atoi/atof conversion function",
    "cpp.rand": "rand()/srand() usage",
    "cpp.erase-in-loop-iterator-use": "erase called on container iterator",
    "cpp.resource.thread-no-join": "std::thread without join/detach",
    "cpp.resource.malloc-no-free": "malloc without free in scope",
    "cpp.return-local-reference": "Returning local/temporary reference",
    "cpp.module-global-fragment-include": "Global module fragment include",
    "cpp.delete-this": "delete this detected",
    "cpp.vector-bool": "std::vector<bool> proxy reference hazard",
    "cpp.unique-reset-raw": "Manual delete and null instead of reset",
    "cpp.std-endl": "std::endl flushes output stream",
}

REMEDIATION_MAP: dict[str, str] = {
    "cpp.raw-new": "Prefer std::make_unique or std::make_shared (RAII).",
    "cpp.raw-new-array": "Prefer std::vector or std::unique_ptr<T[]>.",
    "cpp.raw-delete": "Use smart pointers (std::unique_ptr, std::shared_ptr) to manage lifetime automatically.",
    "cpp.malloc-free": "Prefer standard C++ containers or smart pointers instead of malloc/free.",
    "cpp.throw-in-destructor": "Destructors should be noexcept and swallow or log exceptions.",
    "cpp.catch-by-value": "Catch exceptions by const reference (e.g. catch (const std::exception& e)).",
    "cpp.dynamic-exception-spec": "Replace throw(...) dynamic exception specification with noexcept.",
    "cpp.throw-string": "Throw standard exception objects derived from std::exception.",
    "cpp.throw-raw-value": "Throw typed exception objects derived from std::exception.",
    "cpp.manual-mutex-lock": "Use std::lock_guard or std::scoped_lock for RAII mutex management.",
    "cpp.async-without-policy": "Specify std::launch::async or std::launch::deferred explicitly.",
    "cpp.atomic-relaxed": "Ensure memory ordering matches happens-before requirements or use seq_cst.",
    "cpp.c-style-cast": "Prefer static_cast, reinterpret_cast, or dynamic_cast for clarity.",
    "cpp.using-namespace-std-in-header": "Avoid 'using namespace std' in header files to prevent namespace pollution.",
    "cpp.auto_ptr": "Replace std::auto_ptr with std::unique_ptr.",
    "cpp.std-bind": "Prefer lambdas over std::bind for clarity and type safety.",
    "cpp.string_view-from-temporary": "Ensure referenced string outlives the std::string_view.",
    "cpp.move-of-const": "Remove const qualifier from object before moving, or use a copy.",
    "cpp.move-into-constref": "Assign to a value type or rvalue reference to enable move semantics.",
    "cpp.return-move": "Return local variable directly ('return x;') to enable NRVO.",
    "cpp.unsafe-c-apis": "Use safer alternatives such as snprintf, std::string, or std::format.",
    "cpp.atoi-family": "Prefer std::from_chars or std::stoi with error handling.",
    "cpp.rand": "Use <random> engine and distributions instead of rand().",
    "cpp.erase-in-loop-iterator-use": "Use the iterator returned by erase (it = c.erase(it)) or std::erase_if.",
    "cpp.resource.thread-no-join": "Join or detach the thread before it goes out of scope, or use std::jthread.",
    "cpp.resource.malloc-no-free": "Free allocated memory or use RAII containers.",
    "cpp.return-local-reference": "Return by value or ensure the referenced object outlives the caller.",
    "cpp.module-global-fragment-include": "Place includes in global module fragment before 'module;' declaration.",
    "cpp.delete-this": "Use shared_from_this or reconsider ownership model.",
    "cpp.vector-bool": "Use std::vector<uint8_t> or std::deque<bool> if addressing individual elements.",
    "cpp.unique-reset-raw": "Use unique_ptr::reset() instead of manual delete and null assignment.",
    "cpp.std-endl": "Use '\\n' instead of std::endl unless stream flush is required.",
}

_RULES: tuple[tuple[str, str], ...] = (
    (
        "cpp-raw-new.yml",
        """id: cpp.raw-new
language: cpp
rule:
  any:
    - pattern: new $T($$)
    - pattern: new $T
severity: warning
message: "Raw new detected; prefer std::make_unique/make_shared (RAII)."
""",
    ),
    (
        "cpp-raw-new-array.yml",
        """id: cpp.raw-new-array
language: cpp
rule:
  pattern: new $T[$N]
severity: warning
message: "Raw new[] detected; prefer std::vector or std::unique_ptr<T[]>."
""",
    ),
    (
        "cpp-raw-delete.yml",
        """id: cpp.raw-delete
language: cpp
rule:
  pattern: delete $X
severity: error
message: "Manual delete; prefer smart pointers or RAII to avoid leaks/UB."
""",
    ),
    (
        "cpp-malloc-free.yml",
        """id: cpp.malloc-free
language: cpp
rule:
  any:
    - pattern: malloc($$)
    - pattern: free($$)
severity: warning
message: "C allocation APIs in C++ code; prefer containers or smart pointers."
""",
    ),
    (
        "cpp-throw-in-dtor.yml",
        """id: cpp.throw-in-destructor
language: cpp
rule:
  pattern: throw $EX
  inside:
    kind: function_definition
    has:
      pattern: ~$C()
severity: error
message: "Throwing in destructor can call std::terminate during stack unwinding."
""",
    ),
    (
        "cpp-catch-by-value.yml",
        """id: cpp.catch-by-value
language: cpp
rule:
  pattern: catch ($T $E)
  not:
    has:
      regex: '&'
severity: warning
message: "Catch exceptions by const reference to avoid slicing and copies."
""",
    ),
    (
        "cpp-exception-spec-dynamic.yml",
        """id: cpp.dynamic-exception-spec
language: cpp
rule:
  pattern: "throw($$)"
severity: warning
message: "Deprecated dynamic exception specification; use noexcept."
""",
    ),
    (
        "cpp-throw-string.yml",
        """id: cpp.throw-string
language: cpp
rule:
  pattern: throw "$TXT"
severity: info
message: "Throwing string literal; prefer exceptions derived from std::exception."
""",
    ),
    (
        "cpp-throw-raw-value.yml",
        """id: cpp.throw-raw-value
language: cpp
rule:
  any:
    - pattern: throw 0
    - pattern: throw 1
    - pattern: throw -1
severity: info
message: "Throwing raw value; use typed exceptions."
""",
    ),
    (
        "cpp-mutex-lock-unlock.yml",
        """id: cpp.manual-mutex-lock
language: cpp
rule:
  any:
    - pattern: $M.lock()
    - pattern: $M.unlock()
severity: warning
message: "Manual lock/unlock; prefer std::lock_guard/std::unique_lock (RAII)."
""",
    ),
    (
        "cpp-async-no-policy.yml",
        """id: cpp.async-without-policy
language: cpp
rule:
  pattern: std::async($$)
  not:
    has:
      regex: "std::launch::(async|deferred)"
severity: info
message: "std::async without explicit launch policy can be surprising."
""",
    ),
    (
        "cpp-atomic-relaxed.yml",
        """id: cpp.atomic-relaxed
language: cpp
rule:
  any:
    - pattern: std::memory_order_relaxed
    - pattern: std::memory_order_consume
severity: info
message: "Weak memory order; ensure correctness with happens-before."
""",
    ),
    (
        "cpp-c-style-cast.yml",
        """id: cpp.c-style-cast
language: cpp
rule:
  pattern: ($T)$X
severity: warning
message: "C-style cast; prefer C++-style casts for clarity and safety."
""",
    ),
    (
        "cpp-using-namespace-std-header.yml",
        """id: cpp.using-namespace-std-in-header
language: cpp
rule:
  pattern: using namespace std;
severity: warning
message: "Avoid 'using namespace std' especially in headers."
""",
    ),
    (
        "cpp-auto-ptr.yml",
        """id: cpp.auto_ptr
language: cpp
rule:
  pattern: std::auto_ptr<$T>
severity: error
message: "std::auto_ptr is removed; use std::unique_ptr."
""",
    ),
    (
        "cpp-bind.yml",
        """id: cpp.std-bind
language: cpp
rule:
  pattern: std::bind($$)
severity: info
message: "Prefer lambdas over std::bind for clarity and type safety."
""",
    ),
    (
        "cpp-string-view-from-temporary.yml",
        """id: cpp.string_view-from-temporary
language: cpp
rule:
  pattern: std::string_view($X)
severity: warning
message: "Ensure argument outlives string_view to avoid dangling references."
""",
    ),
    (
        "cpp-move-const.yml",
        """id: cpp.move-of-const
language: cpp
rule:
  pattern: std::move($X)
  has:
    regex: "const"
severity: warning
message: "std::move on const object does not move; results in a copy."
""",
    ),
    (
        "cpp-move-into-constref.yml",
        """id: cpp.move-into-constref
language: cpp
rule:
  pattern: const $T& $N = std::move($X)
severity: warning
message: "Moving into const& has no effect; value will not be moved."
""",
    ),
    (
        "cpp-return-move.yml",
        """id: cpp.return-move
language: cpp
rule:
  pattern: return std::move($X);
severity: info
message: "return std::move(x) can inhibit NRVO; prefer 'return x;'"
""",
    ),
    (
        "cpp-unsafe-c-apis.yml",
        """id: cpp.unsafe-c-apis
language: cpp
rule:
  any:
    - pattern: gets($$)
    - pattern: strcpy($$)
    - pattern: strcat($$)
    - pattern: sprintf($$)
    - pattern: scanf($$)
severity: error
message: "Unsafe C APIs; prefer safer alternatives (snprintf, std::string, streams, fmt)."
""",
    ),
    (
        "cpp-atoi-family.yml",
        """id: cpp.atoi-family
language: cpp
rule:
  any:
    - pattern: atoi($$)
    - pattern: atof($$)
    - pattern: atol($$)
    - pattern: atoll($$)
severity: info
message: "atoi/atof family: prefer std::from_chars or std::stoi with validation."
""",
    ),
    (
        "cpp-rand.yml",
        """id: cpp.rand
language: cpp
rule:
  any:
    - pattern: rand()
    - pattern: srand($$)
severity: info
message: "Prefer <random> facilities; rand() has poor quality and shared state."
""",
    ),
    (
        "cpp-iterator-invalidated-erase.yml",
        """id: cpp.erase-in-loop-iterator-use
language: cpp
rule:
  any:
    - pattern: $C.erase($IT)
    - pattern: $C.erase($B, $E)
severity: info
message: "Erasing invalidates iterators; verify loop iteration is safe."
""",
    ),
    (
        "cpp-resource-thread.yml",
        """id: cpp.resource.thread-no-join
language: cpp
rule:
  all:
    - pattern: std::thread $HANDLE($ARGS);
    - not:
        inside:
          pattern: $HANDLE.join()
    - not:
        inside:
          pattern: $HANDLE.detach()
severity: warning
message: "std::thread created without join()/detach() in the same scope."
""",
    ),
    (
        "cpp-resource-malloc.yml",
        """id: cpp.resource.malloc-no-free
language: cpp
rule:
  pattern: $VAR = malloc($ARGS);
  not:
    inside:
      pattern: free($VAR)
severity: warning
message: "malloc assigned to a variable without free() in the same scope."
""",
    ),
    (
        "cpp-return-local-ref.yml",
        """id: cpp.return-local-reference
language: cpp
rule:
  pattern: return $X;
  inside:
    kind: function_definition
severity: warning
message: "Returning reference to local or temporary can dangle (heuristic)."
""",
    ),
    (
        "cpp-module-global-fragment-include.yml",
        """id: cpp.module-global-fragment-include
language: cpp
rule:
  pattern: module;
severity: info
message: "Global module fragment present; ensure correct include hygiene."
""",
    ),
    (
        "cpp-delete-this.yml",
        """id: cpp.delete-this
language: cpp
rule:
  pattern: delete this
severity: error
message: "Deleting this is error-prone and dangerous."
""",
    ),
    (
        "cpp-vector-bool.yml",
        """id: cpp.vector-bool
language: cpp
rule:
  pattern: std::vector<bool>
severity: info
message: "std::vector<bool> uses proxy references; be careful with references and addresses."
""",
    ),
    (
        "cpp-unique-reset-raw.yml",
        """id: cpp.unique-reset-raw
language: cpp
rule:
  kind: compound_statement
  pattern: |
    {
      delete $X;
      $X = nullptr;
    }
severity: info
message: "Use unique_ptr::reset(nullptr) instead of manual delete then null."
""",
    ),
    (
        "cpp-endl.yml",
        """id: cpp.std-endl
language: cpp
rule:
  pattern: std::endl
severity: info
message: "std::endl flushes the stream; prefer '\\n' unless flushing is required."
""",
    ),
)

_ID_RE = re.compile(r"^id:\s*(\S+)", re.M)
_SEVERITY_RE = re.compile(r"^severity:\s*(\S+)", re.M)
_LANGUAGE_RE = re.compile(r"^language:\s*(\S+)", re.M)
_GRAMMAR = "cpp"


def _map_severity(raw: str) -> str:
    s = (raw or "").lower().strip()
    if s in ("error", "fatal", "critical", "high", "serious"):
        return "critical"
    if s in ("warning", "warn", "medium"):
        return "warning"
    return "info"


def _first_match(pattern: re.Pattern[str], text: str) -> str:
    match = pattern.search(text)
    return match.group(1) if match else ""


def generate(rule_dir: Path, user_rules_dir: Path | None = None) -> dict[str, dict]:
    rules_dir = rule_dir / "rules"
    rules_dir.mkdir(parents=True, exist_ok=True)
    if user_rules_dir and Path(user_rules_dir).is_dir():
        shutil.copytree(user_rules_dir, rules_dir, dirs_exist_ok=True)

    manifest: dict[str, dict] = {}
    for filename, body in _RULES:
        (rules_dir / filename).write_text(body, encoding="utf-8")
        rid = _first_match(_ID_RE, body)
        if not rid:
            continue
        grammar = _first_match(_LANGUAGE_RE, body) or _GRAMMAR
        severity = _map_severity(_first_match(_SEVERITY_RE, body))
        manifest[rid] = {
            "file": f"rules/{filename}",
            "language": grammar,
            "severity": severity,
            "category": CATEGORY_MAP.get(rid, 0),
        }

    config = rule_dir / "sgconfig-cpp.yml"
    config.write_text("ruleDirs:\n- rules\n", encoding="utf-8")
    (rule_dir / "manifest.json").write_text(
        json.dumps(manifest, indent=1, sort_keys=True), encoding="utf-8"
    )
    return manifest
