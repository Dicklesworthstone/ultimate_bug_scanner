// Swift ast-grep rule pack coverage fixture
import Foundation
import CryptoKit

func testSwiftAstRules() {
    let data = Data()
    let url = URL(string: "https://example.com")!
    let session = URLSession.shared

    // 1. swift.force-try
    let _ = try! String(contentsOf: url)

    // 2. swift.force-cast
    let _ = (123 as Any) as! String

    // 3. swift.task-sleep-blocking
    sleep(1)

    // 4. swift.urlsession.task-no-resume
    let _ = session.dataTask(with: url)

    // 5. swift.fatal-error
    if false { fatalError("unreachable") }

    // 6. swift.precondition-failure
    if false { preconditionFailure("failed") }

    // 7. swift.assertion-failure
    if false { assertionFailure("assert") }

    // 8. swift.keyed-unarchiver
    let _ = NSKeyedUnarchiver.unarchiveObject(with: data)

    // 9. swift.md5-digest
    let _ = Insecure.MD5.hash(data: data)

    // 10. swift.sha1-digest
    let _ = Insecure.SHA1.hash(data: data)

    // 11. swift.process-run
    let _ = Process.run(url, arguments: [])

    // 12. swift.thread-sleep
    Thread.sleep(forTimeInterval: 0.1)

    // 13. swift.dispatch-sync-main
    DispatchQueue.main.sync {
        let _ = 1
    }

    // 14. swift.timer-scheduled
    let _ = Timer.scheduledTimer(withTimeInterval: 1.0, repeats: false) { _ in }

    // 15. swift.print-call
    print("test")

    // 16. swift.debug-print
    debugPrint("debug")

    // 17. swift.unsafe-bitcast
    let _ = unsafeBitCast(123, to: Int.self)

    // 18. swift.unmanaged-pass-unretained
    let u = Unmanaged.passUnretained(session)

    // 19. swift.unmanaged-take-unretained
    let _ = u.takeUnretainedValue()

    // 20. swift.exit-call
    if false { exit(0) }

    // 21. swift.abort-call
    if false { abort() }

    // 22. swift.ns-assert
    NSAssert(true, "assert")
}
