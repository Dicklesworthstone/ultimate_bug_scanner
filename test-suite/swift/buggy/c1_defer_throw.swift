import Foundation
struct Request { let query: [String: String] }
let documentRoot = "/srv/app/files"
enum E: Error { case x }
func work() {}
func risky() throws {}
func deferThrow(request: Request) throws { var p = "/safe"
  defer { _ = try? String(contentsOfFile: p) }
  p = documentRoot + "/" + (request.query["file"] ?? "x")
  if request.query["c"] != nil { throw E.x }
  p = "/safe-again"
}
