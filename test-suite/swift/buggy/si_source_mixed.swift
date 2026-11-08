import Foundation
struct Request { let query: [String: String] }
struct Attachment { let filename: String }
let documentRoot = "/srv/app/files"
func handle(_ request: Request) {
    let a = Attachment(filename: "x")
    _ = a.filename  // ubs:ignore[taint-source] app-controlled
    _ = try? String(contentsOfFile: documentRoot + "/" + (request.query["f"] ?? "y"))
}
