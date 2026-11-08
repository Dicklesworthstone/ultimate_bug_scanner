import Foundation
struct Request { let query: [String: String] }
let documentRoot = "/srv/app/files"
enum E: Error { case x }
func work() {}
func risky() throws {}
func deferKill(request: Request) { var p = "/safe"
  defer { _ = try? String(contentsOfFile: p) }
  p = documentRoot + "/" + (request.query["file"] ?? "x")
  p = "/safe-again"
}
