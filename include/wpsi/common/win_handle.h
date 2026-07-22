#pragma once

#include <Windows.h>

namespace wpsi {

class WinHandle {
public:
    WinHandle() noexcept = default;
    explicit WinHandle(HANDLE handle) noexcept : handle_(handle) {}
    ~WinHandle() { reset(); }

    WinHandle(const WinHandle&) = delete;
    WinHandle& operator=(const WinHandle&) = delete;

    WinHandle(WinHandle&& other) noexcept : handle_(other.release()) {}

    WinHandle& operator=(WinHandle&& other) noexcept {
        if (this != &other) {
            reset(other.release());
        }
        return *this;
    }

    HANDLE get() const noexcept { return handle_; }

    HANDLE release() noexcept {
        HANDLE released = handle_;
        handle_ = nullptr;
        return released;
    }

    bool valid() const noexcept {
        return handle_ != nullptr && handle_ != INVALID_HANDLE_VALUE;
    }

    void reset(HANDLE handle = nullptr) noexcept {
        if (valid()) {
            CloseHandle(handle_);
        }
        handle_ = handle;
    }

private:
    HANDLE handle_ = nullptr;
};

} // namespace wpsi
