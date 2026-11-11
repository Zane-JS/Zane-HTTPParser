#ifndef ZANE_HTTP_PARSER_H
#define ZANE_HTTP_PARSER_H

#include <algorithm>
#include <cstdint>
#include <cstdio>
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

// ============================================================================
// Response builders
// ============================================================================

// Build a complete HTTP/1.1 response with a known-length body. Auto-adds
// Content-Length if neither Content-Length nor Transfer-Encoding is present.
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

// Build only the response head (status line + headers + blank line).
// Used by streaming responses (writeHead) where the body will be sent as
// chunks via buildChunk() / buildChunkEnd(). Caller is responsible for
// ensuring Transfer-Encoding: chunked (or Content-Length) is set if needed;
// we do NOT auto-add Content-Length here because the body length is unknown
// at this point.
inline std::string buildResponseHead(int32_t status, const std::string& status_text,
                                     const std::map<std::string, std::string>& headers) {
    std::string res;
    res.reserve(128 + headers.size() * 64);

    // Status line
    res += "HTTP/1.1 ";
    res += std::to_string(status);
    res += ' ';
    res += sanitizeHeaderValue(status_text);
    res += "\r\n";

    // Headers (with CRLF guard, same as buildResponse).
    for (const auto& [key, val] : headers) {
        if (key.empty() || key.find('\r') != std::string::npos ||
            key.find('\n') != std::string::npos || key.find('\0') != std::string::npos) {
            continue;
        }
        res += key;
        res += ": ";
        res += sanitizeHeaderValue(val);
        res += "\r\n";
    }

    // Defense-in-depth security headers, identical policy to buildResponse.
    if (headers.find("X-Content-Type-Options") == headers.end()) {
        res += "X-Content-Type-Options: nosniff\r\n";
    }
    if (headers.find("Connection") == headers.end()) {
        res += "Connection: close\r\n";
    }

    // If the caller didn't set framing headers and didn't set Content-Length,
    // default to chunked so the head is well-formed and the upcoming chunks
    // are valid. Apps that know the total length up front should still set
    // Content-Length explicitly.
    if (headers.find("Content-Length") == headers.end() &&
        headers.find("Transfer-Encoding") == headers.end()) {
        res += "Transfer-Encoding: chunked\r\n";
    }

    // End of headers
    res += "\r\n";
    return res;
}

// Build a single chunked-encoding frame:
//     <hex-size>\r\n<data>\r\n
// Per RFC 7230 §4.1, chunk size is in hex without "0x" prefix. An empty
// chunk (size 0) is the terminator and should be built with buildChunkEnd()
// instead of this helper.
inline std::string buildChunk(const uint8_t* p_data, size_t len) {
    if (len == 0) {
        // Zero-length chunks are not meaningful mid-stream; return empty so
        // the caller can no-op rather than emit a malformed frame.
        return std::string();
    }
    std::string res;
    // Reserve: hex size (max 16 chars for size_t on 64-bit) + CRLF + data + CRLF.
    res.reserve(24 + len);
    char hex_buf[32];
    int hex_len = snprintf(hex_buf, sizeof(hex_buf), "%zx", len);
    res.append(hex_buf, hex_len);
    res += "\r\n";
    if (len > 0) {
        res.append(reinterpret_cast<const char*>(p_data), len);
    }
    res += "\r\n";
    return res;
}

// Build the chunked-encoding terminator: "0\r\n\r\n".
inline std::string buildChunkEnd() {
    return std::string("0\r\n\r\n", 5);
}

} // namespace http
} // namespace zane

#endif // ZANE_HTTP_PARSER_H
