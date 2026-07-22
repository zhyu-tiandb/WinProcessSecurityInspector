#pragma once

#include "wpsi/report/markdown_exporter.h"

namespace wpsi {

inline std::string html_escape(std::string_view value) {
    std::string result;
    for (char ch : value) {
        switch (ch) {
        case '&': result += "&amp;"; break;
        case '<': result += "&lt;"; break;
        case '>': result += "&gt;"; break;
        case '"': result += "&quot;"; break;
        default: result += ch; break;
        }
    }
    return result;
}

inline std::string exportDiagnosisReportHtml(const DiagnosisReport& report) {
    std::string body = html_escape(exportDiagnosisReportMarkdown(report));
    return "<!doctype html><html><head><meta charset=\"utf-8\"><title>WPSI Diagnosis Report</title>"
           "<style>body{font-family:Segoe UI,Arial,sans-serif;margin:24px;line-height:1.5}"
           "pre{white-space:pre-wrap;background:#f6f8fa;padding:16px;border:1px solid #d0d7de}</style>"
           "</head><body><pre>" + body + "</pre></body></html>";
}

} // namespace wpsi
