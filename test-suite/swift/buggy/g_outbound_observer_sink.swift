import Foundation
struct Request { let query: [String: String] }
let documentRoot = "/srv/app/files"
func activate(_ request: Request) { _ = request.query }
struct Prefs { var p = "" { didSet { _ = URLRequest(url: URL(string: p)!) } } }
