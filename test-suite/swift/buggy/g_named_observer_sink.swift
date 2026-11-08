import Foundation
struct Request { let query: [String: String] }
let documentRoot = "/srv/app/files"
func activate(_ request: Request) { _ = request.query }
struct Prefs { var p = "" { didSet(old) { _ = old; _ = try? String(contentsOfFile: documentRoot + "/" + p) } } }
