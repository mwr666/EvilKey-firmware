#pragma once
#include <stddef.h>
#include <stdint.h>
#include <string>
#include <vector>
#include <map>
#include <set>
#include "SPI.h"

#define FILE_READ "r"
#define FILE_WRITE "w"
struct MockEntry { std::string name;std::vector<uint8_t> bytes;bool directory=false;size_t read_bytes=0; };
struct MockIO {bool short_write=false,corrupt_read=false,fail_read=false;void (*on_write)()=nullptr;};

class File {
public:
    File() = default;
    File(std::vector<uint8_t> *bytes, const char *name, size_t offset = 0,MockIO *io=nullptr)
        : bytes_(bytes), name_(name), offset_(offset),io_(io) {}
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
        if(io_&&io_->fail_read)return 0;
        if (!bytes_ || count > bytes_->size() - offset_) return 0;
        for (size_t i = 0; i < count; ++i) out[i] = (*bytes_)[offset_ + i];
        if(io_&&io_->corrupt_read&&count)out[0]^=1;
        offset_ += count;
        if(read_count_)*read_count_+=count;
        return count;
    }
    size_t write(const uint8_t *input, size_t count) {
        if (!bytes_) return 0;
        if(io_&&io_->short_write&&count)--count;
        if (offset_ + count > bytes_->size()) bytes_->resize(offset_ + count);
        for (size_t i = 0; i < count; ++i) (*bytes_)[offset_ + i] = input[i];
        offset_ += count;
        if(io_&&io_->on_write)io_->on_write();
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
    MockIO *io_=nullptr;
};

class SDClass {
public:
    std::vector<uint8_t> save;
    bool save_exists = false;
    bool fail_mkdir=false,fail_log_open=false,fail_log_read_open=false,fail_rename=false;
    MockIO log_io;
    std::map<std::string,std::vector<uint8_t>> logs;
    std::set<std::string> directories;
    std::vector<std::string> removed;
    bool exists(const char *name){return logs.count(name)||directories.count(name);}
    bool mkdir(const char *name){if(fail_mkdir)return false;directories.insert(name);return true;}
    bool remove(const char *name){removed.push_back(name);return logs.erase(name)>0;}
    bool rename(const char *from,const char *to){
        if(fail_rename||!logs.count(from)||logs.count(to))return false;
        logs[to]=logs[from];logs.erase(from);return true;
    }
    bool catalog_exists=false;
    unsigned directory_opens=0;
    std::vector<MockEntry> entries;
    bool begin(int, SPIClass &, uint32_t, const char *, int, bool) { return true; }
    void end() {}
    File open(const char *name, const char *mode = FILE_READ) {
        if(std::string(name).find("/evilkey/diagnostics/")==0){
            if(std::string(mode)==FILE_WRITE){
                if(fail_log_open)return {};
                logs[name]={};return File(&logs[name],name,0,&log_io);
            }
            if(fail_log_read_open||!logs.count(name))return {};
            return File(&logs[name],name,0,&log_io);
        }
        if(std::string(name)=="/evilkey/apps") {
            ++directory_opens;return catalog_exists?File(&entries):File();
        }
        for(auto &entry:entries) {
            if(std::string(name)=="/evilkey/apps/"+entry.name)
                return File(&entry.bytes,name);
        }
        if (std::string(name) != "/evilkey/apps/example.save") return {};
        if (!save_exists && std::string(mode) != FILE_WRITE) return {};
        if (!save_exists) { save_exists = true; save.clear(); }
        return File(&save, name, std::string(mode) == FILE_WRITE ? save.size() : 0);
    }
};
extern SDClass SD;
