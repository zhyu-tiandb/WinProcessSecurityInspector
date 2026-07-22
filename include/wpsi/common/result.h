#pragma once

#include <string>

namespace wpsi {

enum class ErrorCode {
    Ok,
    InvalidArgument,
    ProcessNotFound,
    AccessDenied,
    PartialData,
    ApiFailed,
    Timeout,
    Unsupported,
    InternalError
};

struct ErrorInfo {
    ErrorCode code = ErrorCode::Ok;
    unsigned long win32Error = 0;
    std::string message;
};

template <typename T>
struct Result {
    T value {};
    ErrorInfo error {};
    bool ok = true;
    bool partial = false;
};

template <typename T>
struct FieldValue {
    T value {};
    bool available = false;
    ErrorInfo error {};
};

} // namespace wpsi
