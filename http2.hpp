#ifndef ZANE_HTTP2_H
#define ZANE_HTTP2_H

#include <cstdint>
#include <functional>
#include <map>
#include <string>
#include <vector>

namespace zane {
namespace http2 {

// ============================================================================
// Frame Types
// ============================================================================

enum class FrameType : uint8_t {
    DATA = 0,
    HEADERS = 1,
    PRIORITY = 2,
    RST_STREAM = 3,
    SETTINGS = 4,
    PUSH_PROMISE = 5,
    PING = 6,
    GOAWAY = 7,
    WINDOW_UPDATE = 8,
    CONTINUATION = 9
};

// ============================================================================
// Frame Header
// ============================================================================

struct FrameHeader {
    uint32_t m_length;    // 24-bit payload length
    FrameType m_type;
    uint8_t m_flags;
    uint32_t m_stream_id; // 31-bit stream identifier
};

// ============================================================================
// Settings Parameters
// ============================================================================

enum class SettingsId : uint16_t {
    HEADER_TABLE_SIZE = 1,
    ENABLE_PUSH = 2,
    MAX_CONCURRENT_STREAMS = 3,
    INITIAL_WINDOW_SIZE = 4,
    MAX_FRAME_SIZE = 5,
    MAX_HEADER_LIST_SIZE = 6
};

// ============================================================================
// Error Codes
// ============================================================================

enum class ErrorCode : uint32_t {
    NO_ERROR = 0,
    PROTOCOL_ERROR = 1,
    INTERNAL_ERROR = 2,
    FLOW_CONTROL_ERROR = 3,
    SETTINGS_TIMEOUT = 4,
    STREAM_CLOSED = 5,
    FRAME_SIZE_ERROR = 6,
    REFUSED_STREAM = 7,
    CANCEL = 8,
    COMPRESSION_ERROR = 9,
    CONNECT_ERROR = 10,
    ENHANCE_YOUR_CALM = 11,
    INADEQUATE_SECURITY = 12,
    HTTP_1_1_REQUIRED = 13
};

// ============================================================================
// Frame Flags
// ============================================================================

struct FrameFlags {
    static constexpr uint8_t END_STREAM = 0x01;
    static constexpr uint8_t ACK = 0x01; // for SETTINGS / PING
    static constexpr uint8_t END_HEADERS = 0x04;
    static constexpr uint8_t PADDED = 0x08;
    static constexpr uint8_t PRIORITY = 0x20;
};

// ============================================================================
// HPACK — Header Compression
// ============================================================================

class HPACK {
public:
    HPACK();
    ~HPACK() = default;
    HPACK(const HPACK&) = delete;
    HPACK& operator=(const HPACK&) = delete;

    /// Reset dynamic table to initial state.
    void reset();

    /// Encode a set of headers into HPACK binary.
    std::vector<uint8_t> encode(
        const std::vector<std::pair<std::string, std::string>>& headers);

    /// Decode HPACK binary into header pairs.
    int32_t decode(const uint8_t* p_data, size_t size,
                   std::vector<std::pair<std::string, std::string>>& out);

    /// Update max dynamic table size (from SETTINGS).
    void setMaxTableSize(uint32_t size);

    uint32_t maxTableSize() const { return m_max_table_size; }

private:
    uint32_t m_max_table_size = 4096;

    struct HeaderEntry {
        std::string m_name;
        std::string m_value;
    };
    std::vector<HeaderEntry> m_dynamic_table;
    uint32_t m_dynamic_table_size = 0;

    uint32_t findTableIndex(const std::string& name) const;
    int32_t findTableEntry(const std::string& name, const std::string& value) const;
    void addToDynamicTable(const std::string& name, const std::string& value);
    void evictToFit(uint32_t needed);

    static bool getStaticEntry(size_t index, std::string& name, std::string& value);
    bool getDynamicEntry(size_t index, std::string& name, std::string& value) const;
    size_t totalEntries() const;
};

// ============================================================================
// Frame Reader
// ============================================================================

class FrameReader {
public:
    FrameReader() = default;

    /// Feed raw bytes, extract one frame if available.
    /// Returns bytes consumed on success (>0), 0 if more data needed,
    /// negative on error.
    int32_t readFrame(const uint8_t* p_data, size_t size,
                      FrameHeader& out, const uint8_t*& p_payload);

    void setMaxFrameSize(uint32_t sz) { m_max_frame_size = sz; }

private:
    uint32_t m_max_frame_size = 16384;
};

// ============================================================================
// Stream State
// ============================================================================

enum class StreamState : uint8_t {
    IDLE,
    RESERVED_LOCAL,
    RESERVED_REMOTE,
    OPEN,
    HALF_CLOSED_LOCAL,
    HALF_CLOSED_REMOTE,
    CLOSED
};

// ============================================================================
// Connection
// ============================================================================

class Connection {
public:
    Connection();
    ~Connection() = default;
    Connection(const Connection&) = delete;
    Connection& operator=(const Connection&) = delete;

    /// Reset connection to initial state.
    void reset();

    /// Process incoming bytes (connection preface + frames).
    int32_t feed(const uint8_t* p_data, size_t size,
                 std::function<void(const FrameHeader&, const uint8_t*)> on_frame,
                 std::function<void(ErrorCode)> on_error);

    /// Build a SETTINGS frame.
    std::vector<uint8_t> buildSettings(
        const std::map<SettingsId, uint32_t>& settings);

    /// Build a GOAWAY frame.
    std::vector<uint8_t> buildGoaway(uint32_t last_stream_id, ErrorCode error);

    /// Build HEADERS + optionally DATA frame for a response.
    std::vector<uint8_t> buildResponse(
        uint32_t stream_id,
        const std::vector<std::pair<std::string, std::string>>& headers,
        const uint8_t* p_body, size_t body_len, bool end_stream);

    /// Connection preface bytes (client connection).
    static const uint8_t* clientPreface();
    static size_t clientPrefaceLen();

    bool prefaceReceived() const { return m_preface_received; }

private:
    bool m_preface_received = false;
    uint32_t m_last_peer_stream_id = 0;
    uint32_t m_last_local_stream_id = 0;
    HPACK m_hpack;
    FrameReader m_frame_reader;
    uint32_t m_settings_max_frame_size = 16384;

    int32_t processFrame(const FrameHeader& hdr, const uint8_t* p_payload,
                         std::function<void(ErrorCode)> on_error);
};

} // namespace http2
} // namespace zane

#endif // ZANE_HTTP2_H
