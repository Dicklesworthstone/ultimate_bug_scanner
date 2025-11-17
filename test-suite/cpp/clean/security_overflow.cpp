#include <array>
#include <cstring>
#include <iostream>
#include <string>

void safeCopy(const std::string &input) {
    std::array<char, 8> buf{};
    std::strncpy(buf.data(), input.c_str(), buf.size() - 1);
    std::cout << buf.data() << std::endl;
}

int main() {
    safeCopy("hello");
    auto data = std::make_unique<char[]>(64);
    std::strcpy(data.get(), "secret");
    std::cout << data.get() << std::endl;
    return 0;
}
