// test-suite/cpp/narrowing_buggy.cpp
// Partial null guards: the guard branch logs but does not exit, so the
// fall-through path still dereferences the possibly-null pointer.
// Expect narrowing_cpp findings on every dereference below.

#include <cstdio>
#include <cstddef>

struct Session {
    int user_id;
    char name[32];
};

static void log_null(const char *what) {
    std::printf("null pointer: %s\n", what);
}

// Guard branch only logs; the fall-through dereferences p.
int session_user_id(Session *p) {
    if (!p) {
        log_null("session");
    }
    return p->user_id;
}

// Null-comparison guard falls through; the value is dereferenced anyway.
int deref_value(int *p) {
    if (p == nullptr) {
        log_null("value");
    }
    return *p;
}

// Legacy NULL spelling with the same fall-through defect.
const char *session_name(Session *p) {
    if (p == NULL) {
        log_null("name");
    }
    return p->name;
}
