import Foundation
struct Request { let filename: String }
struct Draft {
    let name: String
    init(request: Request) { self.name = request.filename }
}
