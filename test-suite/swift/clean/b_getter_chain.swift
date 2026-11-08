import Foundation
struct ExportFile2 { let filename: String }
struct Tag {
    let base: ExportFile2
    var upper: String { base.filename.uppercased() }
}
