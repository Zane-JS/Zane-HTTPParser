#include "http_parser.hpp"

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <cstdlib>

namespace zane {
namespace http {

// Defense-in-depth limits to prevent parser abuse:
//   * kMaxBodySize  - caps an advertised Content-Length so a peer cannot claim a
//                     huge body (avoids int32 overflow / preallocation abuse).
//   * kMaxHeaders   - caps the number of unique headers per request to bound
//                     memory and CPU (a single flooded request could otherwise
//                     exhaust memory via std::map growth).
//   * kMaxUrlLength - caps the request-target length so a single request line
//                     cannot blow up memory. 8 KB is generous for any
//                     legitimate URL and well below the 64 MB body cap.
static constexpr int64_t kMaxBodySize = static_cast<int64_t>(64) * 1024 * 1024; // 64 MB
static constexpr size_t kMaxHeaders = 100;
static constexpr size_t kMaxUrlLength = 8 * 1024; // 8 KB

Parser::Parser() { reset(); }

void Parser::reset() {
    m_state = ParseState::ST_METHOD;
    m_request = {};
    m_error_msg.clear();
    m_scratch_buf.clear();
    m_remaining_body = 0;
    m_has_content_length = false;
}

void Parser::setError(const char* p_msg) {
    m_state = ParseState::ST_ERROR;
    m_error_msg = p_msg;
}

// ============================================================================
// Main execute — parse a chunk of data
// ============================================================================

int32_t Parser::execute(const char* p_data, size_t len) {
    if (m_state == ParseState::ST_COMPLETE || m_state == ParseState::ST_ERROR) {
        reset();
    }

    const char* p_pos = p_data;
    const char* p_end = p_data + len;

    if (m_state == ParseState::ST_METHOD) {
        const char* p_space = static_cast<const char*>(std::memchr(p_pos, ' ', p_end - p_pos));
        if (!p_space) return setError("Invalid request line: no space after method"), -1;
        if (parseMethod(p_pos, p_space) != 0) return -1;
        p_pos = p_space + 1;
        m_state = ParseState::ST_URL;
    }

    if (m_state == ParseState::ST_URL) {
        const char* p_space = static_cast<const char*>(std::memchr(p_pos, ' ', p_end - p_pos));
        if (!p_space) return 0;
        if (parseUrl(p_pos, p_space) != 0) return -1;
        p_pos = p_space + 1;

        // Skip HTTP/1.1\r\n
        while (p_pos < p_end && *p_pos != '\r' && *p_pos != '\n') ++p_pos;
        while (p_pos < p_end && (*p_pos == '\r' || *p_pos == '\n')) ++p_pos;
        m_state = ParseState::ST_HEADER_FIELD;
    }

    if (m_state == ParseState::ST_HEADER_FIELD || m_state == ParseState::ST_HEADER_VALUE) {
        while (p_pos < p_end) {
            const char* p_line_end = static_cast<const char*>(
                std::memchr(p_pos, '\n', p_end - p_pos));
            if (!p_line_end) return 0;

            const char* p_line_start = p_pos;
            p_pos = p_line_end + 1;

            const char* p_line_trim = (p_line_end > p_line_start && *(p_line_end - 1) == '\r')
                                          ? p_line_end - 1
                                          : p_line_end;

            if (p_line_start == p_line_trim || *p_line_start == '\r') {
                m_state = ParseState::ST_BODY;

                // Issue #10: HTTP request smuggling via Transfer-Encoding.
                // The parser below only knows how to consume a body when
                // Content-Length is set. If a client sends Transfer-Encoding:
                // chunked, the body is silently dropped and the request is
                // marked COMPLETE — which means a proxy in front of Zane
                // could decode the chunked body and forward it, while Zane
                // thinks the request ended early. That's a textbook
                // smuggling gate.
                //
                // Until we have a real chunked decoder we reject any
                // request that arrives with Transfer-Encoding, and also
                // reject the RFC 7230 confusing case where both
                // Content-Length and Transfer-Encoding are present.
                auto te_it = m_request.m_headers.find("transfer-encoding");
                if (te_it != m_request.m_headers.end()) {
                    return setError("Transfer-Encoding not supported (chunked body not yet implemented)"), -1;
                }

                // Check Content-Length (headers are stored lowercase)
                auto it = m_request.m_headers.find("content-length");
                if (it != m_request.m_headers.end()) {
                    m_has_content_length = true;
                    // strtoll gives well-defined behavior on overflow (vs. atoi,
                    // whose contract ends at INT_MAX). Reject empty values,
                    // leading junk, negative values, and absurd sizes.
                    const std::string& cl = it->second;
                    char* p_end_ptr = nullptr;
                    errno = 0;
                    int64_t body_len = std::strtoll(cl.c_str(), &p_end_ptr, 10);
                    if (p_end_ptr == cl.c_str() || p_end_ptr != cl.c_str() + cl.size() ||
                        body_len < 0 || body_len > kMaxBodySize || errno == ERANGE) {
                        return setError("Invalid or too large Content-Length"), -1;
                    }
                    m_remaining_body = static_cast<int32_t>(body_len);
                }
                break;
            }

            if (parseHeaderLine(p_line_start, p_line_trim) != 0) return -1;
        }
    }

    if (m_state == ParseState::ST_BODY) {
        if (m_has_content_length) {
            const int32_t avail = static_cast<int32_t>(p_end - p_pos);
            const int32_t to_copy = std::min(avail, m_remaining_body);
            if (to_copy > 0) {
                size_t old_size = m_request.m_body.size();
                m_request.m_body.resize(old_size + static_cast<size_t>(to_copy));
                std::memcpy(&m_request.m_body[old_size], p_pos, static_cast<size_t>(to_copy));
                m_remaining_body -= to_copy;
                p_pos += to_copy;
            }
            if (m_remaining_body <= 0) {
                m_state = ParseState::ST_COMPLETE;
            }
        } else {
            m_state = ParseState::ST_COMPLETE;
        }
    }

    if (m_state == ParseState::ST_COMPLETE) {
        if (m_request.m_pathname.empty()) {
            size_t qpos = m_request.m_url.find('?');
            m_request.m_pathname = (qpos != std::string::npos)
                                       ? m_request.m_url.substr(0, qpos)
                                       : m_request.m_url;
        }
        return 0;
    }

    return 0;
}

// ============================================================================
// Parse helpers
// ============================================================================

int32_t Parser::parseMethod(const char* p_start, const char* p_end) {
    size_t len = static_cast<size_t>(p_end - p_start);

    // Issue #12: HTTP method whitelist. Accept only RFC 9110 §9 methods,
    // and additionally reject any method that contains non-token chars
    // (CR, LF, control bytes, separators) so a TRACE / XST / log-injection
    // request is rejected with 400 instead of being parsed.
    if (len == 0 || len > 32) {
        return setError("Method too long or empty"), -1;
    }

    // RFC 9110 §5.6.2 token chars: !#$%&'*+-.^_` + alnum. We reject anything
    // outside that set rather than try to coerce it.
    for (size_t i = 0; i < len; ++i) {
        unsigned char c = static_cast<unsigned char>(p_start[i]);
        bool is_token = (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') ||
                        (c >= 'a' && c <= 'z') || c == '!' || c == '#' ||
                        c == '$' || c == '%' || c == '&' || c == '\'' ||
                        c == '*' || c == '+' || c == '-' || c == '.' ||
                        c == '^' || c == '_' || c == '`';
        if (!is_token) {
            return setError("Invalid method character"), -1;
        }
    }

    if (len == 3 && std::memcmp(p_start, "GET", 3) == 0) {
        m_request.m_method = "GET";
    } else if (len == 4 && std::memcmp(p_start, "POST", 4) == 0) {
        m_request.m_method = "POST";
    } else if (len == 3 && std::memcmp(p_start, "PUT", 3) == 0) {
        m_request.m_method = "PUT";
    } else if (len == 6 && std::memcmp(p_start, "DELETE", 6) == 0) {
        m_request.m_method = "DELETE";
    } else if (len == 4 && std::memcmp(p_start, "HEAD", 4) == 0) {
        m_request.m_method = "HEAD";
    } else if (len == 7 && std::memcmp(p_start, "OPTIONS", 7) == 0) {
        m_request.m_method = "OPTIONS";
    } else if (len == 5 && std::memcmp(p_start, "PATCH", 5) == 0) {
        m_request.m_method = "PATCH";
    } else {
        // Known-good method per RFC 9110 §9 but not on the supported list
        // (CONNECT, TRACE, custom verbs). Refuse rather than accept.
        return setError("Method not supported"), -1;
    }
    return 0;
}

int32_t Parser::parseUrl(const char* p_start, const char* p_end) {
    size_t len = static_cast<size_t>(p_end - p_start);
    if (len > kMaxUrlLength) {
        return setError("URL too long"), -1;
    }
    m_request.m_url.assign(p_start, p_end);
    return 0;
}

int32_t Parser::parseHeaderLine(const char* p_start, const char* p_end) {
    const char* p_colon = static_cast<const char*>(
        std::memchr(p_start, ':', p_end - p_start));

    if (!p_colon) {
        if (!m_scratch_buf.empty()) {
            auto& last_val = m_request.m_headers.rbegin()->second;
            last_val += ' ';
            last_val.append(p_start, p_end);
        }
        return 0;
    }

    m_scratch_buf.assign(p_start, p_colon);

    while (!m_scratch_buf.empty() &&
           (m_scratch_buf.back() == ' ' || m_scratch_buf.back() == '\t')) {
        m_scratch_buf.pop_back();
    }

    const char* p_val = p_colon + 1;
    while (p_val < p_end && (*p_val == ' ' || *p_val == '\t')) ++p_val;

    std::string val(p_val, p_end);

    while (!val.empty() && (val.back() == ' ' || val.back() == '\t')) {
        val.pop_back();
    }

    // Lowercase field name for consistency
    std::string field_name;
    field_name.reserve(m_scratch_buf.size());
    for (char c : m_scratch_buf) {
        field_name += static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }

    auto it = m_request.m_headers.find(field_name);
    if (it != m_request.m_headers.end()) {
        it->second += ", ";
        it->second += val;
    } else {
        // Cap the number of unique headers to bound memory/CPU. Appending to an
        // existing header (above) is allowed since it doesn't grow the map.
        if (m_request.m_headers.size() >= kMaxHeaders) {
            return setError("Too many headers"), -1;
        }
        m_request.m_headers[field_name] = std::move(val);
    }

    return 0;
}

} // namespace http
} // namespace zane
