"""Unbounded index arithmetic the category-3 ladder must still report.

Companion to index_arithmetic_clean.py. Nothing here checks the offset, so
each access can walk off the end (or silently wrap to the tail for a negative
index). There are more than 12 so the ladder reaches its warning tier.
"""


def neighbours(x, i, j, k, m, n):
    return (
        x[i + 1],
        x[j - 1],
        x[k + 2],
        x[m - 2],
        x[n + 3],
    )


def flag_value(args):
    i = args.index("--root")
    return args[i + 1]


def pairs(seq, a, b, c, d, e, f, g):
    return [
        seq[a + 1],
        seq[b + 1],
        seq[c + 1],
        seq[d - 1],
        seq[e - 1],
        seq[f + 4],
        seq[g - 4],
    ]


def plain_enumerate(seq):
    for i, _ in enumerate(seq):
        yield seq[i - 1]


def after_loop(seq, n):
    for i in range(n):
        pass
    return seq[i + 1]
