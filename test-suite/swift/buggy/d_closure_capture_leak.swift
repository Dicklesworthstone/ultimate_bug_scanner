import Foundation
final class CaptureLeak {
    let timer = Timer.scheduledTimer(withTimeInterval: 1, repeats: true) { _ in }
    func go() {
        DispatchQueue.main.async { _ = self.timer }
    }
}
