import Foundation

// True positives for the shell-execution rule (ubs#101): every call below is a
// C free function that runs its argument through a shell.
func runViaSystem(_ userInput: String) {
    system("ls \(userInput)")
}

func runViaModuleQualifiedSystem(_ userInput: String) {
    // Module-qualified C calls are the one legitimate dotted form.
    Darwin.system("rm -rf \(userInput)")
}

func readViaPopen(_ userInput: String) -> String? {
    guard let handle = popen("cat \(userInput)", "r") else { return nil }
    defer { pclose(handle) }
    return "read"
}

func spawnShell(_ userInput: String) {
    var pid: pid_t = 0
    let argv: [UnsafeMutablePointer<CChar>?] = []
    posix_spawn(&pid, "/bin/sh", nil, nil, argv, ["-c", userInput].map { _ in nil })
}

func runShellProcess(_ userInput: String) throws {
    let task = Process()
    task.executableURL = URL(fileURLWithPath: "/bin/bash")
    task.arguments = ["-c", "grep \(userInput) /etc/passwd"]
    try task.run()
}
