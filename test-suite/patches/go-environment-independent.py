"""Independent Go environment-source cases frozen before implementation.

Usage: python3 test-suite/patches/go-environment-independent.py REPOSITORY
Analyzed Go fixtures are never executed. All fixture files are retained.
This standalone checkpoint is intentionally outside automatic test discovery.

The original 15 labels remain unchanged. Eight additional grouped-result and
closure-write cases were reviewed against a603d20 but have not been executed.
All cases require exact findings and successful analysis; partial is not a pass.
"""
import json
from pathlib import Path
import sys
import tempfile
import textwrap

repo = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(repo / "modules/helpers"))
from ubs_core.registry import RunContext
from ubs_core.analyzers import taint_go

CASES = {
    "aliased_getenv": ('''package app
import environment "os"
func run() {
  db.Query(environment.Getenv("QUERY"))
}
''', [("go.taint.sql", 4)]),
    "lookup_value": ('''package app
import "os"
func run() {
  query, exists := os.LookupEnv("QUERY")
  _ = exists
  db.Query(query)
}
''', [("go.taint.sql", 6)]),
    "lookup_presence": ('''package app
import "os"
import "strconv"
func run() {
  _, exists := os.LookupEnv("QUERY")
  db.Query(strconv.FormatBool(exists))
}
''', []),
    "saved_getter": ('''package app
import environment "os"
func run() {
  read := environment.Getenv
  db.Query(read("QUERY"))
}
''', [("go.taint.sql", 5)]),
    "saved_lookup": ('''package app
import "os"
func run() {
  read := os.LookupEnv
  value, _ := read("QUERY")
  db.Query(value)
}
''', [("go.taint.sql", 6)]),
    "dot_import": ('''package app
import . "os"
func run() {
  db.Query(Getenv("QUERY"))
}
''', [("go.taint.sql", 4)]),
    "helper_result": ('''package app
import environment "os"
func read() string { return environment.Getenv("QUERY") }
func run() {
  db.Query(read())
}
''', [("go.taint.sql", 5)]),
    "helper_getter_argument": ('''package app
import "os"
func read(get func(string) string) string { return get("QUERY") }
func run() {
  db.Query(read(os.Getenv))
}
''', [("go.taint.sql", 5)]),
    "bound_query": ('''package app
import environment "os"
func run() {
  db.Query("SELECT * FROM users WHERE name = $1", environment.Getenv("NAME"))
}
''', []),
    "strong_overwrite": ('''package app
import "os"
func run() {
  value := os.Getenv("QUERY")
  value = "SELECT 1"
  db.Query(value)
}
''', []),
    "import_lookalike": ('''package app
import os "example.invalid/innocent"
func run() {
  db.Query(os.Getenv("QUERY"))
}
''', []),
    "parameter_shadow": ('''package app
import "os"
func run(os localConfig) {
  db.Query(os.Getenv("QUERY"))
}
''', []),
    "html_sanitizer_keeps_sql": ('''package app
import environment "os"
import "html"
func run() {
  value := html.EscapeString(environment.Getenv("QUERY"))
  fmt.Fprint(w, value)
  db.Query(value)
}
''', [("go.taint.sql", 7)]),
    "command_flow": ('''package app
import "os"
func run() {
  cmd, _ := os.LookupEnv("COMMAND")
  exec.Command("sh", "-c", cmd)
}
''', [("go.taint.command", 5)]),
    "html_output": ('''package app
import environment "os"
func run() {
  fmt.Fprint(w, environment.Getenv("HTML"))
}
''', [("go.taint.xss", 4)]),
    "lookup_grouped_result_payload": ('''package app
import (
    "fmt"
    "io"
    environment "os"
)
func run(w io.Writer) {
    value, present := (environment.LookupEnv("HTML"))
    fmt.Fprint(w, value)
    fmt.Fprint(w, present)
}
''', [("go.taint.xss", 9)]),
    "lookup_grouped_result_presence_only": ('''package app
import (
    "fmt"
    "io"
    environment "os"
)
func run(w io.Writer) {
    _, present := ((environment.LookupEnv("HTML")))
    fmt.Fprint(w, present)
}
''', []),
    "lookup_grouped_callee_control": ('''package app
import (
    "fmt"
    "io"
    environment "os"
)
func run(w io.Writer) {
    value, present := (environment.LookupEnv)("HTML")
    fmt.Fprint(w, value)
    fmt.Fprint(w, present)
}
''', [("go.taint.xss", 9)]),
    "closure_installs_environment_getter": ('''package app
import (
    "fmt"
    "html"
    "io"
    environment "os"
)
func run(w io.Writer) {
    read := html.EscapeString
    func() {
        read = environment.Getenv
    }()
    fmt.Fprint(w, read("HTML"))
}
''', [("go.taint.xss", 13)]),
    "unused_closure_does_not_install_getter": ('''package app
import (
    "fmt"
    "html"
    "io"
    environment "os"
)
func run(w io.Writer) {
    read := html.EscapeString
    _ = func() {
        read = environment.Getenv
    }
    fmt.Fprint(w, read("HTML"))
}
''', []),
    "closure_keeps_prior_copied_escaper": ('''package app
import (
    "fmt"
    "html"
    "io"
    environment "os"
)
func run(w io.Writer) {
    read := html.EscapeString
    saved := read
    func() {
        read = environment.Getenv
    }()
    fmt.Fprint(w, saved(environment.Getenv("HTML")))
    fmt.Fprint(w, read("HTML"))
}
''', [("go.taint.xss", 15)]),
    "closure_mutates_local_copy_only": ('''package app
import (
    "fmt"
    "html"
    "io"
    environment "os"
)
func run(w io.Writer) {
    read := html.EscapeString
    func() {
        copied := read
        copied = environment.Getenv
        _ = copied
    }()
    fmt.Fprint(w, read(environment.Getenv("HTML")))
}
''', []),
    "reader_grouped_result_error_control": ('''package app
import (
    "fmt"
    "io"
    "net/http"
)
func run(w io.Writer, r *http.Request) {
    payload, err := (io.ReadAll(r.Body))
    fmt.Fprint(w, payload)
    fmt.Fprint(w, err)
}
''', [("go.taint.xss", 9)]),
}

artifacts = repo / "test-suite/artifacts"
artifacts.mkdir(parents=True, exist_ok=True)
root = Path(tempfile.mkdtemp(prefix="go-environment-independent-", dir=artifacts))
failures = []
for name, (code, expected) in CASES.items():
    directory = root / name
    directory.mkdir()
    path = directory / "sample.go"
    path.write_text(textwrap.dedent(code), encoding="utf-8")
    try:
        findings = list(taint_go.run(RunContext(lang="go", files=[path])))
        actual = sorted((finding["rule"], finding["line"]) for finding in findings)
        okay = actual == sorted(expected)
        result = {"case": name, "expected": expected, "actual": actual, "passed": okay}
    except Exception as exc:
        okay = False
        result = {"case": name, "expected": expected,
                  "error": type(exc).__name__ + ": " + str(exc), "passed": False}
    print(json.dumps(result), flush=True)
    if not okay:
        failures.append(name)
print(json.dumps({"repo": str(repo), "cases": len(CASES),
                  "passed": len(CASES) - len(failures), "failures": failures,
                  "artifacts": str(root)}))
sys.exit(bool(failures))
