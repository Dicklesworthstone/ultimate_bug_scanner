import Foundation
struct Request { let query: [String: String] }
let documentRoot = "/srv/app/files"
enum E: Error { case x }
func work() {}
func risky() throws {}
func deferLateAssign(request: Request) { var p = "/safe"
  defer { _ = try? String(contentsOfFile: p) }
  if request.query["c"] != nil { p = documentRoot + "/" + (request.query["file"] ?? "x")
    return }
  p = "/safe-again"
}
