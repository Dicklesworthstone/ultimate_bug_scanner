// GH #91 suppression fixture (bead A7) for the Swift module, twin of
// suppression_buggy_nomarkers.swift (identical buggy code, no markers).
// Every native swift finding below (the path:line code samples printed by
// the module: force-try, force cast, Timer scheduled without invalidate)
// carries a suppression marker in one of the documented arrangements, so
// `./ubs test-suite/swift/suppression/suppression_buggy.swift` must report
// zero finding lines, while the nomarkers twin reproduces them.

import Foundation

final class SuppressionFixture {

    private var timer: Timer?

    // Arrangement 1: previous-line marker.
    func decodePrevLine(_ payload: Data) throws {
        // ubs:ignore -- fixture: marker on the line immediately above the finding
        let decoded = try! JSONDecoder().decode([String: Int].self, from: payload)
        print(decoded)
    }

    // Arrangement 2: trailing marker on the flagged line itself.
    func castTrailing(_ any: Any) {
        let label = any as! String // ubs:ignore -- fixture: trailing marker
        print(label)
    }

    // Arrangement 3: multi-line statement, marker on a continuation line.
    func decodeMultiline(_ payload: Data) throws {
        let decoded = try! JSONDecoder().decode(
            [String: Int].self, from: payload) // ubs:ignore -- fixture: marker on a physical line of a multi-line statement
        print(decoded)
    }

    // Arrangement 4: formatter-relocated marker on the first line inside a block.
    func startTimer() {
        timer = Timer.scheduledTimer(withTimeInterval: 1.0, repeats: true) { _ in
            // ubs:ignore -- fixture: formatter moved the marker inside the block
            print("tick")
        }
    }

    // Arrangement 5: rule-scoped markers (rule id in square brackets). The
    // swift module's code-sample lines carry no rule id, so these suppress
    // through the runner's same-line/previous-line path.
    func ruleScopedPrevLine(_ payload: Data) throws {
        // ubs:ignore[swift.force-try] -- fixture: rule-scoped marker above the finding
        let decoded = try! JSONDecoder().decode([String: Int].self, from: payload)
        print(decoded)
    }

    func ruleScopedTrailing(_ any: Any) {
        let flag = any as! Int // ubs:ignore[swift.force-cast] -- fixture: rule-scoped trailing marker
        print(flag)
    }
}
