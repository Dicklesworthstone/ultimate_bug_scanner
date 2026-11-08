import Foundation
// #204 A: tuple / multi-name associated-value bindings analyze; the managed
// Timer is invalidated, so no leak is reported.
final class Pair {
    enum Combo { case single(Int), double(Int, Int) }
    private let timer = Timer.scheduledTimer(withTimeInterval: 1, repeats: true) { _ in }
    func sum(_ c: Combo) -> Int {
        switch c {
        case .single(let a): return a
        case .double(let a, let b): return a + b
        }
    }
    func stop() { timer.invalidate() }
}
