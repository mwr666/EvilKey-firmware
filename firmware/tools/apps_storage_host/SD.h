#pragma once
#include <stddef.h>
#include <stdint.h>
#include <string>
#include <vector>
#include "SPI.h"

#define FILE_READ "r"
#define FILE_WRITE "w"

class File {
public:
    File() = default;
    File(std::vector<uint8_t> *bytes, const char *name, size_t offset = 0)
        : bytes_(bytes), name_(name), offset_(offset) {}
    explicit operator bool() const { return bytes_ != nullptr; }
    bool isDirectory() const { return false; }
    size_t size() const { return bytes_ ? bytes_->size() : 0; }
    const char *name() const { return name_.c_str(); }
    File openNextFile() { return {}; }
    bool seek(size_t offset) {
        if (!bytes_ || offset > bytes_->size()) return false;
        offset_ = offset;
        return true;
    }
    size_t read(uint8_t *out, size_t count) {
        if (!bytes_ || count > bytes_->size() - offset_) return 0;
        for (size_t i = 0; i < count; ++i) out[i] = (*bytes_)[offset_ + i];
        offset_ += count;
        return count;
    }
    size_t write(const uint8_t *input, size_t count) {
        if (!bytes_) return 0;
        if (offset_ + count > bytes_->size()) bytes_->resize(offset_ + count);
        for (size_t i = 0; i < count; ++i) (*bytes_)[offset_ + i] = input[i];
        offset_ += count;
        return count;
    }
    void flush() {}
    void close() { bytes_ = nullptr; }
private:
    std::vector<uint8_t> *bytes_ = nullptr;
    std::string name_;
    size_t offset_ = 0;
};

class SDClass {
public:
    std::vector<uint8_t> save;
    bool exists = false;
    bool begin(int, SPIClass &, uint32_t, const char *, int, bool) { return true; }
    void end() {}
    File open(const char *name, const char *mode = FILE_READ) {
        if (std::string(name) != "/evilkey/apps/example.save") return {};
        if (!exists && std::string(mode) != FILE_WRITE) return {};
        if (!exists) { exists = true; save.clear(); }
        return File(&save, name, std::string(mode) == FILE_WRITE ? save.size() : 0);
    }
};
extern SDClass SD;
