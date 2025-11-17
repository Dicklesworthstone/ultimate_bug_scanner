#include <array>
#include <cstring>
#include <iostream>
#include <memory>
#include <mutex>
#include <string>

std::unique_ptr<char[]> copy_safely(const std::string &input) {
    auto buf = std::make_unique<char[]>(input.size() + 1);
    std::snprintf(buf.get(), input.size() + 1, "%s", input.c_str());
    return buf;
}

int main() {
    auto safe = copy_safely("hello world");
    std::cout << safe.get() << "\n";

    std::mutex m;
    std::lock_guard<std::mutex> guard{m};
    // protected critical section
    return 0;
}
