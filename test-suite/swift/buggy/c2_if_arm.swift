import Foundation
struct Request { let query: [String: String] }
let documentRoot = "/srv/app/files"
func work() {}
func ifArm(request: Request) throws { #if DEBUG
  _ = try String(contentsOfFile: documentRoot + "/" + (request.query["f"] ?? "x"))
  #endif
}
