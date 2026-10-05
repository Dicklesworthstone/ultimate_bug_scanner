# C# Fixtures

- `buggy/` contains intentionally unsafe patterns for `ubs-csharp.sh`.
- `clean/` provides counterexamples that should stay free of critical/warning findings.
- `security/ArchiveExtractionBuggy.cs` and `security/ArchiveExtractionClean.cs` cover zip/tar archive entry path containment.
- `security/OpenRedirectBuggy.cs` and `security/OpenRedirectClean.cs` cover ASP.NET request/header/cookie/route values flowing into redirect and `Location` header sinks.
- `security/HeaderInjectionBuggy.cs` and `security/HeaderInjectionClean.cs` cover ASP.NET request/query/header/form and annotated action values flowing into response headers.
- `security/RequestPathTraversalBuggy.cs` and `security/RequestPathTraversalClean.cs` cover ASP.NET request/header/upload values flowing into file read/write/serve/delete sinks.
- `security/SsrfBuggy.cs` and `security/SsrfClean.cs` cover ASP.NET request/header values flowing into outbound HTTP clients.
- `tests/test_helper_scanners.py` covers the helper-backed type narrowing, resource lifecycle, and async task-handle analyzers directly.
- `manifest.json` now also includes a shimmed ast-grep regression case so the AST rule pack stays testable even when `ast-grep` is not installed globally.
- Manifest cases run with `--no-dotnet` so scanner regressions stay stable even when the .NET SDK is absent.

## Request-path dataflow

`csharp.taint.request_traversal` follows request and upload paths through method
parameters, returns, and file-sink effects within each selected C# file. Method
state is separate; constant assignments replace old facts, branches join, and
loops and mutually recursive helper summaries converge over a finite lattice.
Named arguments and generic/expression-bodied helpers are supported. Unknown
calls conservatively propagate their inputs instead of being trusted merely
because their names contain `Safe` or `Validate`.

Sinks inspect path parameters, not arbitrary arguments: request-controlled
contents passed to a fixed-path `WriteAllText`/`WriteAllTextAsync` are not path
traversal. Copy/move destinations and replace-backup paths are checked, as are
async file operations. Findings retain source/call/assignment/sink evidence in
`extras.taint_path` through the native scanner's findings sink.

`Path.GetFileName` is a modeled basename transformation. A containment guard
must constrain a canonical path below a root with a directory separator;
`StartsWith(root)` alone also accepts siblings such as `uploads-evil` and is
not treated as validation. A user-controlled root remains tainted. A guard on
only one branch cannot sanitize paths that reach the sink through another.

This remains a lexical, explicit-flow analyzer, not Roslyn: it does not resolve
cross-file calls, virtual dispatch, heap fields, delegate targets, closure
captures, or helper `ref`/`out` writes. `Request.*.TryGetValue(..., out value)` is
modeled directly. Exception-handler edges are conservative. Conditional
compilation, unbalanced syntax, unsupported `goto`, and exhausted analysis
budgets produce an incomplete-analysis error rather than a verified clean scan.
The module does not cache those failures. Excluding security category 8 avoids
running this analyzer altogether.

Run the actual analyzer/solver and native-sink regressions with:

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover \
  -s test-suite/quality -p test_taint_csharp_dataflow.py -v
```
