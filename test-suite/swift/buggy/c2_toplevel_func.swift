import Foundation
struct Request { let query: [String: String] }
let documentRoot = "/srv/app/files"
#if DEBUG
func wrappedTop(request: Request) throws {
  _ = try String(contentsOfFile: documentRoot + "/" + (request.query["f"] ?? "x"))
}
#endif
