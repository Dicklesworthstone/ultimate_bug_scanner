import Foundation

// #204: a Swift regex literal that begins a continuation line. The `.replacing(`
// call wraps after the open paren, so the regex starts the next line. The lexer
// must treat `/.../` as a regex literal, not division, or structural validation
// fails with "Unbalanced Swift delimiters" and the whole file goes partial.
enum Markup {
    static func stripImageTags(_ input: String) -> String {
        var t = input
        t = t.replacing(
            /!\[[^\]]*\]\([^)]*\)/,
            with: "[image]"
        )
        return t
    }
}
