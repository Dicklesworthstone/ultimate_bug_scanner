import SwiftUI

// Regression fixture for ubs#101: SwiftUI implicit- and qualified-member
// expressions spell `.system(...)` with a leading dot. A word-boundary anchor
// matches at that dot, so every font constructor here used to be reported as
// shell execution. None of these lines executes anything.
struct MemberCallStyles: View {
    let bodyFont = Font.system(size: 12)
    let titleFont = UIFont.systemFont(ofSize: 24)
    let accent = Color.systemRed

    var body: some View {
        VStack {
            Text("hello")
                .font(.system(size: 13))
            Text("world")
                .font(.system(size: 15, weight: .semibold, design: .rounded))
            Image(systemName: "gear")
        }
        .popover(isPresented: .constant(false)) {
            Text("detail")
        }
    }
}

// Members that merely share a name with the C free functions are not calls to
// them either.
struct CommandRecorder {
    func system(_ label: String) -> String { label }
    func popen(_ label: String) -> String { label }
}

func describe(_ recorder: CommandRecorder) -> String {
    recorder.system("not a shell") + recorder.popen("also not a shell")
}
