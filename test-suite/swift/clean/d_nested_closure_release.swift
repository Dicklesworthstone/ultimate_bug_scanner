import Foundation
final class NestedRelease {
    let timer = Timer.scheduledTimer(withTimeInterval: 1, repeats: true) { _ in }
    func go() {
        DispatchQueue.main.async { DispatchQueue.global().async { self.timer.invalidate() } }
    }
}
