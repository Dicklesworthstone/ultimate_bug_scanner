import Foundation
let documentRoot = "/srv/app/files"
struct Prefs { var p = "" { didSet { _ = try? String(contentsOfFile: documentRoot + "/" + p) } } }
