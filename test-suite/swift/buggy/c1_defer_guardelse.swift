import Foundation
struct Request { let query: [String: String] }
let documentRoot = "/srv/app/files"
enum E: Error { case x }
func work() {}
func risky() throws {}
func deferGuardElse(request: Request) { defer { _ = try? String(contentsOfFile: documentRoot + "/" + (request.query["file"] ?? "x")) }
  guard request.query["c"] != nil else { return }
  work()
}
