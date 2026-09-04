// GH #91 suppression fixture (bead A7) for the C/C++ module, twin of
// suppression_buggy_nomarkers.cpp (identical buggy code, no markers).
// Every native cpp finding below (the path:line code samples printed by the
// module) carries a suppression marker in one of the documented arrangements,
// so `./ubs test-suite/cpp/suppression/suppression_buggy.cpp` must report
// zero findings, while the nomarkers twin reproduces them.

#include <cstddef>
#include <cstdio>
#include <cstring>
#include <mutex>

// Arrangement 1: previous-line marker.
void copy_prev_line(char *dst, const char *src) {
    // ubs:ignore -- fixture: marker on the line immediately above the finding
    std::strcpy(dst, src);
}

// Arrangement 2: trailing marker on the flagged line itself.
void append_trailing(char *dst, const char *src) {
    std::strcat(dst, src); // ubs:ignore -- fixture: trailing marker
}

// Arrangement 3: multi-line statement, marker on a continuation line.
void format_multiline(char *dst, const char *fmt, int value) {
    std::sprintf(dst,
                 fmt, // ubs:ignore -- fixture: marker on a physical line of a multi-line statement
                 value);
}

// Arrangement 4: formatter-relocated marker on the first line inside a block.
void copy_in_block(char *dst, const char *src, bool ready) {
    if (ready) { std::strcpy(dst, src);
        // ubs:ignore -- fixture: formatter moved the marker inside the block
    }
}

// Arrangement 5: rule-scoped markers (rule id in square brackets). The cpp
// module's code-sample lines carry no rule id, so these suppress through the
// runner's same-line/previous-line path.
void rule_scoped_previous_line(char *heap, std::mutex &m) {
    // ubs:ignore[cpp.raw-delete] -- fixture: rule-scoped marker above the finding
    delete[] heap;
    // ubs:ignore[cpp.manual-mutex-lock] -- fixture: rule-scoped marker above the finding
    m.lock();
    // ubs:ignore[cpp.manual-mutex-lock] -- fixture: rule-scoped marker above the finding
    m.unlock();
}

void rule_scoped_trailing(std::size_t n) {
    char *buf = new char[n]; // ubs:ignore[cpp.raw-new] -- fixture: rule-scoped trailing marker
}
