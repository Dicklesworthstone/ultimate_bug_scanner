import Foundation
struct Request { let query: [String: String] }
let documentRoot = "/srv/app/files"
func noop() {}
#if DEBUG
struct A { func f(request: Request) {} }
#else
struct A { func f(request: Request) {} }
#endif
