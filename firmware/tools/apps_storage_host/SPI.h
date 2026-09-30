#pragma once
#define HSPI 1
class SPIClass {
public:
    explicit SPIClass(int) {}
    bool begin(int, int, int, int) { return true; }
    void end() {}
};
