import Foundation
struct Request { let query: [String: String] }
func boot(_ server: Server, _ request: Request) {
    _ = request
    server.onRequest { r in _ = try? String(contentsOfFile: r.path) }
}
