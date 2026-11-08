import Foundation
struct Request { let query: [String: String] }
let documentRoot = "/srv/app/files"
enum E: Error { case x }
func work() {}
func risky() throws {}
func buggyDoCatch(request: Request) throws {
  do { try risky() } catch {
    _ = try? String(contentsOfFile: documentRoot + "/" + (request.query["file"] ?? "x"))
  }
}
