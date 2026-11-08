import Foundation
final class SwitchOneArm {
    enum Event { case idle, shut(Int) }
    private let timer = Timer.scheduledTimer(withTimeInterval: 1, repeats: true) { _ in }
    func on(_ e: Event) {
        switch e {
        case .idle:
            break
        case .shut(let code):
            _ = code
            timer.invalidate()
        }
    }
}
