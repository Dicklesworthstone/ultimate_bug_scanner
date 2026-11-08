import Foundation
struct Request { let query: [String: String] }
let documentRoot = "/srv/app/files"
func work() {}
func ifClean(request: Request) throws { #if DEBUG
  work()
  #else
  work()
  #endif
}
