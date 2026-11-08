import Foundation
final class AcquireInClosure {
    func go() {
        DispatchQueue.main.async {
            let t = Timer.scheduledTimer(withTimeInterval: 1, repeats: true) { _ in }
            _ = t
        }
    }
}
