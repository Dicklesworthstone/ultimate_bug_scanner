import Foundation
// #204 A: a switch with an associated-value binding analyzes; the managed
// Timer is invalidated, so the lifecycle engine reports no leak.
final class Ticker {
    enum Phase { case idle, running(Int) }
    private let timer = Timer.scheduledTimer(withTimeInterval: 1, repeats: true) { _ in }
    func describe(_ p: Phase) -> String {
        switch p {
        case .idle: return "idle"
        case .running(let seconds): return "running \(seconds)"
        }
    }
    func stop() { timer.invalidate() }
}
