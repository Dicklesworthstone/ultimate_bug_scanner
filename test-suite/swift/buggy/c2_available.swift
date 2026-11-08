import Foundation
struct Request { let query: [String: String] }
let documentRoot = "/srv/app/files"
func work() {}
func inAvailable(request: Request) throws { if #available(iOS 15, *) {
  _ = try String(contentsOfFile: documentRoot + "/" + (request.query["f"] ?? "x"))
  } }
