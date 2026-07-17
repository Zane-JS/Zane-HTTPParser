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

inline std::string buildResponse(int32_t status, const std::string& status_text,
                                  const std::map<std::string, std::string>& headers,
                                  const uint8_t* p_body, size_t body_len) {
    std::string res;
    res.reserve(256 + headers.size() * 64 + body_len);

    // Status line
    res += "HTTP/1.1 ";
    res += std::to_string(status);
    res += ' ';
    res += status_text;
    res += "\r\n";

    // Headers
    for (const auto& [key, val] : headers) {
        res += key;
        res += ": ";
        res += val;
        res += "\r\n";
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
