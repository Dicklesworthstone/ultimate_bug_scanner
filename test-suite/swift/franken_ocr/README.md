# franken_ocr production Swift regression snapshot

These 21 Swift files are copied byte for byte from
[Dicklesworthstone/franken_ocr](https://github.com/Dicklesworthstone/franken_ocr/tree/b77ba7ac6de17aeb82f104cf4a54eda86913b094)
at commit `b77ba7ac6de17aeb82f104cf4a54eda86913b094`. The original relative paths
are retained under `ios/`, including the app, share extension, widget, and tests.
The upstream `LICENSE` is included without changes.

The production files are deliberately unmodified. Do not add UBS suppression
comments or simplify their expressions to make an analyzer test pass. The
quality test pins their Git blob hashes so a reduced fixture cannot silently
replace the real reproduction.

[UBS issue #204](https://github.com/Dicklesworthstone/ultimate_bug_scanner/issues/204)
reported these five files:

| Source | Construct exercised |
| --- | --- |
| `ios/Sources/HtmlExport.swift` | Raw HTML strings, nested interpolation, regex literals after a newline |
| `ios/Sources/LabModel.swift` | Escaping timer callback, weak capture, nested MainActor task, associated-value switch cases |
| `ios/Sources/ModelStore.swift` | Stored asynchronous task, weak self, guard, defer, typed catch |
| `ios/Shared/FrankenOCRSystemState.swift` | Closure-local conditional control flow and `compactMap` |
| `ios/Sources/LabView.swift` | SwiftUI result builders, escaping initializer callback, static `Self` method calls |

The full snapshot also includes `ios/Sources/RecognitionHistory.swift`, which
exercises stored-property initializers and the distinction between OCR request
fields and inbound web request data.

Run the offline regression suite from the UBS repository root:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s test-suite/quality -p test_swift_production_completeness.py
```

The suite checks focused analyzer entry points and runs the ordinary
`ubs --only=swift` CLI in JSON and SARIF modes over the complete snapshot.
Completion is independent of findings: these production files are not a
zero-warning fixture. Existing resource and code-quality findings must remain
visible. An unmodeled semantic effect must produce a located warning explaining
the conservative analysis; it must not erase findings in the same function,
sibling functions, or other files. Malformed Swift must still fail the scan.

The file-URL proof API remains strict. If an effect prevents establishing that a
read is file-only, it must refuse that proof even after the normal scanner has
reported a local diagnostic and continued. The tests check this distinction
instead of treating completion as permission to grant a network exemption.
Generated sources, outputs, and run identities are retained only under
`test-suite/artifacts/`.
