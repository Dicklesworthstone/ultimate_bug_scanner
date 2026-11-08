import Foundation
struct Request { let query: [String: String] }
let documentRoot = "/srv/app/files"
func work() {}
func ifInExpression(request: Request) -> [String] {
  return [request.query["f"] ?? "x",
    #if DEBUG
    "d",
    #endif
  ]
}
