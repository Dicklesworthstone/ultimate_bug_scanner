import Foundation
struct ExportFile { let filename: String }
func export() -> String {
    var captured = ""
    FileRepresentation(exportedContentType: .plainText) { file in captured = file.filename }
    return captured
}
