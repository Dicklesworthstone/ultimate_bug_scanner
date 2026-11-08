import Foundation
struct Request { let query: [String: String] }
let documentRoot = "/srv/app/files"
func handle(_ request: Request) {
    var out = "x"
    configure { out = request.query["f"] ?? "x" }
    _ = try? String(contentsOfFile: documentRoot + "/" + out)
}
