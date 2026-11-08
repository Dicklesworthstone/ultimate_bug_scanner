import Foundation
struct Request { let query: [String: String] }
let documentRoot = "/srv/app/files"
enum E: Error { case x }
func work() {}
func risky() throws {}
func deferContinue(request: Request) { var p = "/safe"
  for _ in 0..<2 { defer { _ = try? String(contentsOfFile: p) }
    p = documentRoot + "/" + (request.query["file"] ?? "x")
    if request.query["c"] != nil { continue }
    p = "/safe-again"
  }
}
