import Foundation
struct Request { let query: [String: String] }
func handler(req: Request) {
    var p = "" { didSet { _ = try? String(contentsOfFile: p) } }
    p = req.query["f"] ?? ""
}
