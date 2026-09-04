// GH #91 suppression fixture (bead A7) for the Swift module, twin of
// suppression_buggy.swift: identical buggy code with every suppression marker
// removed, so a scan of this file must reproduce the native swift findings
// (force-try, force cast, Timer scheduled without invalidate) that the
// markered twin suppresses. Lines stay aligned with the markered twin; each
// marker is replaced by this placeholder comment, keeping line numbers equal.
// Scanning this twin reproduces every finding the markered twin suppresses.

import Foundation

final class SuppressionFixture {

    private var timer: Timer?

    // Arrangement 1: previous-line marker.
    func decodePrevLine(_ payload: Data) throws {
        // fixture: marker removed in the nomarkers twin
        let decoded = try! JSONDecoder().decode([String: Int].self, from: payload)
        print(decoded)
    }

    // Arrangement 2: trailing marker on the flagged line itself.
    func castTrailing(_ any: Any) {
        let label = any as! String // fixture: marker removed in the nomarkers twin
        print(label)
    }

    // Arrangement 3: multi-line statement, marker on a continuation line.
    func decodeMultiline(_ payload: Data) throws {
        let decoded = try! JSONDecoder().decode(
            [String: Int].self, from: payload) // fixture: marker removed in the nomarkers twin
        print(decoded)
    }

    // Arrangement 4: formatter-relocated marker on the first line inside a block.
    func startTimer() {
        timer = Timer.scheduledTimer(withTimeInterval: 1.0, repeats: true) { _ in
            // fixture: marker removed in the nomarkers twin
            print("tick")
        }
    }

    // Arrangement 5: rule-scoped markers (rule id in square brackets). The
    // swift module's code-sample lines carry no rule id, so these suppress
    // through the runner's same-line/previous-line path.
    func ruleScopedPrevLine(_ payload: Data) throws {
        // fixture: marker removed in the nomarkers twin
        let decoded = try! JSONDecoder().decode([String: Int].self, from: payload)
        print(decoded)
    }

    func ruleScopedTrailing(_ any: Any) {
        let flag = any as! Int // fixture: marker removed in the nomarkers twin
        print(flag)
    }
}
