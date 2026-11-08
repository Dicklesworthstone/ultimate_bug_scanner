import Foundation
struct Request { let query: [String: String] }
let documentRoot = "/srv/app/files"
enum E: Error { case x }
func work() {}
func risky() throws {}
func minimalDoCatch(request: Request) {
  do { try risky() } catch { return }
}
