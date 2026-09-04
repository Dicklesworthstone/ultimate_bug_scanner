// GH #91 suppression fixture (bead A7) for the C/C++ module, twin of
// suppression_buggy.cpp: identical buggy code with every suppression marker
// removed, so a scan of this file must reproduce the native cpp findings
// (strcpy/strcat/sprintf unsafe C APIs, raw new/delete, manual mutex
// lock/unlock) that the markered twin suppresses.

#include <cstddef>
#include <cstdio>
#include <cstring>
#include <mutex>

// Arrangement 1: previous-line marker.
void copy_prev_line(char *dst, const char *src) {
    std::strcpy(dst, src);
}

// Arrangement 2: trailing marker on the flagged line itself.
void append_trailing(char *dst, const char *src) {
    std::strcat(dst, src);
}

// Arrangement 3: multi-line statement, marker on a continuation line.
void format_multiline(char *dst, const char *fmt, int value) {
    std::sprintf(dst,
                 fmt,
                 value);
}

// Arrangement 4: formatter-relocated marker on the first line inside a block.
void copy_in_block(char *dst, const char *src, bool ready) {
    if (ready) { std::strcpy(dst, src);
    }
}

// Arrangement 5: rule-scoped markers (rule id in square brackets). The cpp
// code-sample lines carry no rule id, so these suppress through the runner's
// same-line/previous-line path.
void rule_scoped_previous_line(char *heap, std::mutex &m) {
    delete[] heap;
    m.lock();
    m.unlock();
}

void rule_scoped_trailing(std::size_t n) {
    char *buf = new char[n];
}
