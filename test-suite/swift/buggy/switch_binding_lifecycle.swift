import Foundation
// #204 A: a Timer acquired inside a `case .start(let interval):` arm and never
// invalidated must be reported — the leak flows through the switch binding.
final class Scheduler {
    enum Command { case start(Int), stop }
    private var ticker: Timer?
    func handle(_ c: Command) {
        switch c {
        case .start(let interval):
            ticker = Timer.scheduledTimer(withTimeInterval: Double(interval), repeats: true) { _ in }
        case .stop:
            break
        }
    }
}
