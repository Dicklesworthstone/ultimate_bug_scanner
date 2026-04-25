fun runFixedCommand(path: String) {
    ProcessBuilder("git", "-C", path, "status", "--short").start()
}
