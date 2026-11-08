import Foundation
final class TwoTimers {
    let t1 = Timer.scheduledTimer(withTimeInterval: 1, repeats: true) { _ in }
    let t2 = Timer.scheduledTimer(withTimeInterval: 2, repeats: true) { _ in }
    func go() {
        DispatchQueue.main.async { self.t1.invalidate() }
    }
}
