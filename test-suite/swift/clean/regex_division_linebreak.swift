import Foundation

// #204 guard: a `/` that begins a continuation line is DIVISION when the last
// significant token is an operand or `)`. It must stay division after the regex
// heuristic learns to skip the intervening newline token.
func ratios(_ a: Double, _ b: Double) -> Double {
    let y = (a
        / b)
    let z = a
        / b
    let w = (a + b)
        / b
    return y + z + w
}
