import Foundation
struct SentFile { init(_ u: URL) {} }
struct Attachment: Transferable {
    let filename: String
    let payload: String
    static var transferRepresentation: some TransferRepresentation {
        FileRepresentation(exportedContentType: .plainText) { file in
            let url = try Self.makeURL(name: file.filename)  // ubs:ignore[taint-source] export stem is app-controlled, not request input
            try file.payload.write(to: url, atomically: true, encoding: .utf8)
            return SentFile(url)
        }
    }
    static func makeURL(name: String) throws -> URL { FileManager.default.temporaryDirectory.appendingPathComponent(name) }
}
