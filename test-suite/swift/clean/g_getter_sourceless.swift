import Foundation
struct Request { let query: [String: String] }
let documentRoot = "/srv/app/files"
func activate(_ request: Request) { _ = request.query }
struct Box { let base: String; var derived: String { base.uppercased() } }
