import Foundation
struct Request { let query: [String: String] }
let documentRoot = "/srv/app/files"
func activate(_ request: Request) { _ = request.query }
struct Prefs { var flag = false { didSet { UserDefaults.standard.set(flag, forKey: "k") } } }
