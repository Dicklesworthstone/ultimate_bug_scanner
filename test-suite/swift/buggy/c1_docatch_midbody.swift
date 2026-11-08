import Foundation
struct Request { let query: [String: String] }
let documentRoot = "/srv/app/files"
enum E: Error { case x }
func work() {}
func risky() throws {}
func docatchMidBody(request: Request) throws { var p = "/safe"
  do { p = documentRoot + "/" + (request.query["file"] ?? "x")
    try risky()
  } catch { _ = try? String(contentsOfFile: p) }
}
