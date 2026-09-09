"""Bounded index arithmetic (self-scan gate, bead D8).

Every neighbour lookup below is provably in range — an inline comparison, an
enclosing test, a loop that supplies the bound, an early exit, an assert, or a
caught IndexError. The old line regex reported all of them; the category-3
ladder turns warning above 12 hits, and there are more than 12 here, so a
regression in the guard analysis fails this fixture loudly.
"""
MARKER = "ubs"


def inline_and(i, line):
    if i + 1 < len(line) and line[i + 1] == "/":
        return True
    return False


def chained(idx, lines):
    return 0 <= idx - 1 < len(lines) and MARKER in lines[idx - 1]


def enclosing_if(i, line):
    if i + 1 < len(line):
        return line[i + 1]
    return ""


def case_split(idx, text):
    return idx == 0 or text[idx - 1] != "_"


def one_based(lines):
    for idx, _ in enumerate(lines, start=1):
        yield lines[idx - 1]


def bounded_range(seq):
    for i in range(len(seq) - 1):
        yield seq[i + 1]


def range_from_one(seq, n):
    for i in range(1, n):
        yield seq[i - 1]


def early_exit(index, lines):
    start = index
    for _ in range(8):
        if start <= 0:
            break
        if lines[start - 1].strip():
            return start
        start -= 1
    return -1


def caught(seq, i):
    try:
        return seq[i + 1]
    except IndexError:
        return None


def ternary(i, seq):
    return seq[i + 1] if i + 1 < len(seq) else None


def comprehension(seq, n):
    return [seq[i + 1] for i in range(n) if i + 1 < len(seq)]


def while_bounded(i, s):
    while i + 1 < len(s):
        if s[i + 1] == "a":
            return i
        i += 1
    return -1


def asserted(i, seq):
    assert i + 1 < len(seq)
    return seq[i + 1]


def truthy(start, lines):
    return lines[start - 1] if start else ""


def lower_bound(pos, text):
    return pos > 0 and text[pos - 1].isalnum()
