import Foundation
struct ExportFile { let filename: String }
struct Card {
    func make() -> ExportFile { ExportFile(filename: "note.txt") }
    var label: String { "file: " + make().filename }
}
