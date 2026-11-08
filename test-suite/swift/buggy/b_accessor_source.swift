import Foundation
struct ExportFile3 { let filename: String }
struct Proxy {
    let base: ExportFile3
    var value: String {
        get { base.filename }
        set { _ = newValue }
    }
}
