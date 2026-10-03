#pragma once
#include <stddef.h>
#include <stdint.h>
#include <string>
#include <vector>
#include "SPI.h"

#define FILE_READ "r"
#define FILE_WRITE "w"
struct MockEntry { std::string name;std::vector<uint8_t> bytes;bool directory=false;size_t read_bytes=0; };

class File {
public:
    File() = default;
    File(std::vector<uint8_t> *bytes, const char *name, size_t offset = 0)
        : bytes_(bytes), name_(name), offset_(offset) {}
    explicit File(std::vector<MockEntry> *entries):entries_(entries){}
    explicit operator bool() const { return bytes_ != nullptr || entries_ != nullptr; }
    bool isDirectory() const { return entries_ != nullptr || directory_; }
    size_t size() const { return bytes_ ? bytes_->size() : 0; }
    const char *name() const { return name_.c_str(); }
    File openNextFile() {
        if(!entries_ || next_>=entries_->size())return {};
        MockEntry &e=(*entries_)[next_++];File f(&e.bytes,e.name.c_str());
        f.directory_=e.directory;f.read_count_=&e.read_bytes;return f;
    }
    bool seek(size_t offset) {
        if (!bytes_ || offset > bytes_->size()) return false;
        offset_ = offset;
        return true;
    }
    size_t read(uint8_t *out, size_t count) {
        if (!bytes_ || count > bytes_->size() - offset_) return 0;
        for (size_t i = 0; i < count; ++i) out[i] = (*bytes_)[offset_ + i];
        offset_ += count;
        if(read_count_)*read_count_+=count;
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
    void close() { bytes_ = nullptr;entries_=nullptr; }
private:
    std::vector<uint8_t> *bytes_ = nullptr;
    std::string name_;
    size_t offset_ = 0;
    std::vector<MockEntry> *entries_=nullptr;
    size_t next_=0,*read_count_=nullptr;
    bool directory_=false;
};

class SDClass {
public:
    std::vector<uint8_t> save;
    bool exists = false;
    bool catalog_exists=false;
    unsigned directory_opens=0;
    std::vector<MockEntry> entries;
    bool begin(int, SPIClass &, uint32_t, const char *, int, bool) { return true; }
    void end() {}
    File open(const char *name, const char *mode = FILE_READ) {
        if(std::string(name)=="/evilkey/apps") {
            ++directory_opens;return catalog_exists?File(&entries):File();
        }
        for(auto &entry:entries) {
            if(std::string(name)=="/evilkey/apps/"+entry.name)
                return File(&entry.bytes,name);
        }
        if (std::string(name) != "/evilkey/apps/example.save") return {};
        if (!exists && std::string(mode) != FILE_WRITE) return {};
        if (!exists) { exists = true; save.clear(); }
        return File(&save, name, std::string(mode) == FILE_WRITE ? save.size() : 0);
    }
};
extern SDClass SD;
