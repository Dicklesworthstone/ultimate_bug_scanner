import Foundation
struct Request { let query: [String: String] }
func boot(_ server: Server, _ request: Request) {
    _ = request
    server.configure { item in print(item.title) }
}
