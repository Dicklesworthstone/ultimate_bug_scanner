import Foundation
struct Request { let query: [String: String] }
let documentRoot = "/srv/app/files"
func work() {}
func killOneArm(request: Request) throws { var p = documentRoot + "/" + (request.query["f"] ?? "x")
  #if DEBUG
  p = "/safe"
  #endif
  _ = try String(contentsOfFile: p)
}
