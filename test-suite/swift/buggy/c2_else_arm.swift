import Foundation
struct Request { let query: [String: String] }
let documentRoot = "/srv/app/files"
func work() {}
func elseArm(request: Request) throws { #if DEBUG
  work()
  #else
  _ = try String(contentsOfFile: documentRoot + "/" + (request.query["f"] ?? "x"))
  #endif
}
