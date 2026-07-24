"""Prose-heavy module: the English word "is" must never be read as an operator.

Regression fixture for issue #66. Every occurrence of the word "is" below
lives inside a string literal, a docstring, or a comment. A line-oriented
ripgrep for ` is <literal>` flagged all of them; the AST-backed check must
stay silent because there is no `is` comparison against a literal anywhere in
this file.
"""

PROMPT = """
If the text contains a genuine question, the correct label
is "respond".
The default label (when there is no actionable
material) is "respond", never no_response_needed.
The retry budget is 5 and the fallback label is 'skip'.
"""

SINGLE_QUOTED = 'The status is "ready", the attempt is 3, and the flag is True.'

# The default mode is "strict", the timeout is 30, and verbose is False.
FORMAT_TEMPLATE = f"The active profile is {PROMPT!r} whenever the count is 0."


def classify(text, marker=None, sentinel=None):
    """Return the prompt for ``text``; ``marker is None`` is the idiomatic form."""
    if marker is None:
        return PROMPT + text
    if sentinel is not None:
        return SINGLE_QUOTED + text
    return FORMAT_TEMPLATE + text
