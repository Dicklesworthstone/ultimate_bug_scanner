import Foundation
final class CaptureRelease {
    let timer = Timer.scheduledTimer(withTimeInterval: 1, repeats: true) { _ in }
    func go() {
        DispatchQueue.main.async { self.timer.invalidate() }
    }
}
