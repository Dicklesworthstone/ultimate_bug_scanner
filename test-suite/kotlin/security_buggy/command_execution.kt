fun runShell(userInput: String) {
    ProcessBuilder("sh", "-c", "ls $userInput").start()
    ProcessBuilder(listOf("cmd", "/C", "dir $userInput")).start()
}
