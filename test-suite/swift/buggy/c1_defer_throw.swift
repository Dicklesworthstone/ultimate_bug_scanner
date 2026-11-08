import Foundation
struct Request { let query: [String: String] }
let documentRoot = "/srv/app/files"
enum E: Error { case x }
func work() {}
func risky() throws {}
func deferThrow(request: Request) throws { defer { _ = try? String(contentsOfFile: documentRoot + "/" + (request.query["file"] ?? "x")) }
  if request.query["c"] != nil { throw E.x }
  work()
}
