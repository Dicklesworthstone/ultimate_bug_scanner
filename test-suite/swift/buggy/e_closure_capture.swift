import Foundation
struct Request { let query: [String: String] }
let documentRoot = "/srv/app/files"
func handle(_ request: Request) {
    let p = request.query["f"] ?? "x"
    perform { _ = try? String(contentsOfFile: documentRoot + "/" + p) }
}
