import Foundation
struct Request { let query: [String: String] }
let documentRoot = "/srv/app/files"
func handle(_ request: Request) {
    forward(request.query["f"] ?? "x") { item in _ = try? String(contentsOfFile: documentRoot + "/" + item) }
}
