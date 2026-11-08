import Foundation
struct Request { let query: [String: String] }
let documentRoot = "/srv/app/files"
#if DEBUG
struct Handler2 {
  func serve(request: Request) throws {}
}
#else
struct Handler2 {
  func serve(request: Request) throws { _ = try String(contentsOfFile: documentRoot + "/" + (request.query["f"] ?? "x")) }
}
#endif
