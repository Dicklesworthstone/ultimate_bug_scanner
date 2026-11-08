import Foundation
struct Request { let query: [String: String] }
let documentRoot = "/srv/app/files"
func boot() {
    listen { (req: Request) in _ = try? String(contentsOfFile: documentRoot + "/" + (req.query["f"] ?? "x")) }
}
