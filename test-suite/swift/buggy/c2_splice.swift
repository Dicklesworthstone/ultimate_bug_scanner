import Foundation
struct Request { let query: [String: String] }
let documentRoot = "/srv/app/files"
func work() {}
func sliceAfterEndif(request: Request) throws { #if DEBUG
  let p = documentRoot + "/" + (request.query["f"] ?? "x")
  #endif
  _ = try String(contentsOfFile: p)
}
