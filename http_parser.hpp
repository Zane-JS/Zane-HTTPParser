#ifndef ZANE_HTTP_PARSER_H
#define ZANE_HTTP_PARSER_H

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <map>
#include <string>
#include <vector>

namespace zane {
namespace http {

// ============================================================================
// Parsed HTTP Request
// ============================================================================

struct Request {
    std::string m_method;
    std::string m_url;
    std::string m_pathname;                              // URL before '?'
    std::map<std::string, std::string> m_headers;
    std::vector<uint8_t> m_body;
};

// ============================================================================
// HTTP/1.1 Request Parser — state-machine based, bounds-checked
// ============================================================================

class Parser {
  public:
    Parser();
    ~Parser() = default;

    Parser(const Parser&) = delete;
    Parser& operator=(const Parser&) = delete;
    Parser(Parser&&) = delete;
    Parser& operator=(Parser&&) = delete;

    /// Feed raw bytes. Returns 0 on success, non-zero on parse error.
    int32_t execute(const char* p_data, size_t len);

    /// True when a complete HTTP request has been parsed.
    bool isComplete() const { return m_state == ParseState::ST_COMPLETE; }

    /// True when a parse error occurred.
    bool hasError() const { return m_state == ParseState::ST_ERROR; }

    /// Latest error message.
    const std::string& errorMessage() const { return m_error_msg; }

    /// Get parsed result (valid only when isComplete() == true).
    const Request& result() const { return m_request; }
    Request& result() { return m_request; }

    /// Reset parser for next request.
    void reset();

  private:
    enum class ParseState : int32_t {
        ST_METHOD,
        ST_URL,
        ST_HEADER_FIELD,
        ST_HEADER_VALUE,
        ST_BODY,
        ST_COMPLETE,
        ST_ERROR
    };

    ParseState m_state;
    Request m_request;
    std::string m_error_msg;
    std::string m_scratch_buf;               // Temporary field name accumulator
    int32_t m_remaining_body;                // Content-Length remaining
    bool m_has_content_length;

    // Parse helpers
    void setError(const char* p_msg);
    int32_t parseMethod(const char* p_start, const char* p_end);
    int32_t parseUrl(const char* p_start, const char* p_end);
    int32_t parseHeaderLine(const char* p_start, const char* p_end);
};

// ============================================================================
// HTTP Response Builder (helper)
// ============================================================================

// Strip CR/LF/NUL from a header field so it cannot split a header line or
// smuggle a second response, even if an upstream caller bypassed validation.
// Defense-in-depth at the serializer level.
inline std::string sanitizeHeaderValue(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (char c : s) {
        if (c != '\r' && c != '\n' && c != '\0') {
            out.push_back(c);
        }
    }
    return out;
}

inline std::string buildResponse(int32_t status, const std::string& status_text,
                                  const std::map<std::string, std::string>& headers,
                                  const uint8_t* p_body, size_t body_len) {
    std::string res;
    res.reserve(256 + headers.size() * 64 + body_len);

    // Status line
    res += "HTTP/1.1 ";
    res += std::to_string(status);
    res += ' ';
    res += sanitizeHeaderValue(status_text);
    res += "\r\n";

    // Headers
    for (const auto& [key, val] : headers) {
        // Skip headers whose name is empty or contains line terminators — they
        // cannot form a valid header line and would corrupt the wire format.
        if (key.empty() || key.find('\r') != std::string::npos ||
            key.find('\n') != std::string::npos || key.find('\0') != std::string::npos) {
            continue;
        }
        res += key;
        res += ": ";
        res += sanitizeHeaderValue(val);
        res += "\r\n";
    }

    // Issue #15 (item 2): auto-add defense-in-depth security headers that
    // are sensible for almost any HTTP response. Apps can still override
    // by passing them in the headers map. We don't randomly set a Server
    // header (that would help fingerprinting more than anything).
    if (headers.find("X-Content-Type-Options") == headers.end()) {
        res += "X-Content-Type-Options: nosniff\r\n";
    }
    if (headers.find("Connection") == headers.end()) {
        // Trantor's TcpServer closes after each request by default in the
        // single-connection mode; setting Connection: close makes the
        // client's behavior explicit and avoids keep-alive ambiguity.
        res += "Connection: close\r\n";
    }

    // Content-Length (auto-add if not present)
    if (headers.find("Content-Length") == headers.end() && headers.find("Transfer-Encoding") == headers.end()) {
        res += "Content-Length: ";
        res += std::to_string(body_len);
        res += "\r\n";
    }

    // End of headers
    res += "\r\n";

    // Body
    if (body_len > 0) {
        res.append(reinterpret_cast<const char*>(p_body), body_len);
    }

    return res;
}

} // namespace http
} // namespace zane

#endif // ZANE_HTTP_PARSER_H
