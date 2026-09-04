// test-suite/cpp/narrowing_clean.cpp
// Properly narrowed pointer usage: every dereference is either preceded by an
// exiting null guard, happens inside a non-null branch, or follows a
// re-binding of the pointer. Expect zero narrowing_cpp findings.

#include <cstdio>
#include <stdexcept>

struct Session {
    int user_id;
    char name[32];
};

static int fail_closed() {
    return -1;
}

// Exiting negation guard: the fall-through path implies p is valid.
int session_user_id(Session *p) {
    if (!p) {
        return fail_closed();
    }
    return p->user_id;
}

// Exiting null-comparison guard via throw.
int deref_value(int *p) {
    if (p == nullptr) {
        std::printf("value is null\n");
        throw std::runtime_error("value is null");
    }
    return *p;
}

// Use inside the positive branch only runs when p is valid.
void print_session(Session *p) {
    if (p != nullptr) {
        std::printf("session %d\n", p->user_id);
    }
}

// The guard logs without exiting, but p is re-bound before the dereference.
int fallback_value(int *p) {
    int local = 7;
    if (!p) {
        std::printf("value is null\n");
    }
    p = &local;
    return *p;
}

// Only the unrelated pointer q is used, and only inside its positive branch.
void mixed_pointers(int *p, int *q) {
    if (!p) {
        return;
    }
    if (q != nullptr) {
        *q = 3;
    }
}

// Use in the else branch runs only when p is valid.
void rename_else(Session *p) {
    if (p == nullptr) {
        std::printf("session is null\n");
    } else {
        std::printf("session %s\n", p->name);
    }
}
