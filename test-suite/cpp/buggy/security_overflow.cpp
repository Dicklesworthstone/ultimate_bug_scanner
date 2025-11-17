#include <cstring>
#include <iostream>
#include <memory>
#include <string>

void insecureCopy(const char *input) {
    char buf[8];
    std::strcpy(buf, input); // buffer overflow
    std::cout << buf << std::endl;
}

void leakedMemory() {
    char *data = new char[64];
    std::strcpy(data, "secret");
    // missing delete
}

int main() {
    insecureCopy("AAAAAAAAAAAAAAAA");
    leakedMemory();
    system("ls");
    return 0;
}
