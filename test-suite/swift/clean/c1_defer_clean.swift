import Foundation
struct Request { let query: [String: String] }
let documentRoot = "/srv/app/files"
enum E: Error { case x }
func work() {}
func risky() throws {}
func deferClean(request: Request) { defer { work() }
  _ = request.query["x"]
}
