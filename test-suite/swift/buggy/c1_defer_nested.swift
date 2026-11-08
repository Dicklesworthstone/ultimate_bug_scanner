import Foundation
struct Request { let query: [String: String] }
let documentRoot = "/srv/app/files"
enum E: Error { case x }
func work() {}
func risky() throws {}
func deferNested(request: Request) { var p = "/safe"
  if request.query["a"] != nil { defer { _ = try? String(contentsOfFile: p) }
    p = documentRoot + "/" + (request.query["file"] ?? "x")
    if request.query["b"] != nil { return }
  }
  p = "/safe-again"
}
