import Foundation
struct Request { let query: [String: String] }
let documentRoot = "/srv/app/files"
#if DEBUG
struct Handler {
  func serve(request: Request) throws { _ = try String(contentsOfFile: documentRoot + "/" + (request.query["f"] ?? "x")) }
}
#else
struct Handler {
  func serve(request: Request) throws {}
}
#endif
