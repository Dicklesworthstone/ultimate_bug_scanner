// GH #91 suppression fixture (bead A7) for the Swift module, twin of
// suppression_buggy_nomarkers.swift (identical buggy code, no markers).
// Force-try, force-cast and Timer lifecycle findings below carry markers
// in the documented arrangements. The unmarked print calls remain positive
// informational controls, including the calls after previous-line scopes.
// Scanning this file must omit the marked hazard sites while retaining
// those print findings; the nomarkers twin also reproduces the hazards.

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

    // Arrangement 5: scopes name public diagnostic identifiers explicitly.
    // Each scope suppresses only its named force-try or force-cast finding.
    // Unmarked print calls continue to exercise independent diagnostics.
    func ruleScopedPrevLine(_ payload: Data) throws {
        // ubs:ignore[swift.force-try,swift.optionals.try-bang,swift.optionals.force-some] -- fixture: rule-scoped marker above the finding
        let decoded = try! JSONDecoder().decode([String: Int].self, from: payload)
        print(decoded)
    }

    func ruleScopedTrailing(_ any: Any) {
        let flag = any as! Int // ubs:ignore[swift.force-cast,swift.optionals.as-bang,swift.optionals.force-some] -- fixture: rule-scoped trailing marker
        print(flag)
    }
}
