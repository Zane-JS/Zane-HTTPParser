#ifndef ZANE_HTTP3_H
#define ZANE_HTTP3_H

#include <cstdint>
#include <functional>
#include <map>
#include <string>
#include <vector>

namespace zane {
namespace http3 {

// ============================================================================
// Variable-Length Integer Encoding (RFC 9000 Section 16)
// ============================================================================

/// Maximum number of bytes needed for a varint.
static constexpr size_t kMaxVarintSize = 8;

/// Encode a value as QUIC variable-length integer.
/// Returns number of bytes written (1, 2, 4, or 8).
size_t encodeVarint(uint8_t* p_buf, uint64_t value);

/// Decode a QUIC variable-length integer.
/// Returns bytes consumed (0 on error).
size_t decodeVarint(const uint8_t* p_data, size_t size, uint64_t& value);

// ============================================================================
// HTTP/3 Frame Types (RFC 9114 Section 7)
// ============================================================================

enum class FrameType : uint64_t {
    DATA = 0x00,
    HEADERS = 0x01,
    CANCEL_PUSH = 0x03,
    SETTINGS = 0x04,
    PUSH_PROMISE = 0x05,
    GOAWAY = 0x07,
    MAX_PUSH_ID = 0x0D,
    DUPLICATE_PUSH = 0x0E,
    // Reserved frame types: 0x02, 0x06, 0x08-0x0C
};

/// Returns true if the frame type is reserved / known to be ignored.
bool isReservedFrameType(uint64_t raw_type);

// ============================================================================
// HTTP/3 Settings (RFC 9114 Section 7.2.4)
// ============================================================================

enum class SettingsId : uint64_t {
    HEADER_TABLE_SIZE = 0x01,
    MAX_FIELD_SECTION_SIZE = 0x06,
    QPACK_MAX_TABLE_CAPACITY = 0x01,
    QPACK_BLOCKED_STREAMS = 0x07,
    // RFC 9220: Extended CONNECT
    ENABLE_CONNECT_PROTOCOL = 0x08,
    // RFC 9297: HTTP Datagrams
    H3_DATAGRAM = 0x33,  // 0x276, but draft uses 0x33
};

// ============================================================================
// HTTP/3 Error Codes (RFC 9114 Section 8)
// ============================================================================

enum class ErrorCode : uint64_t {
    NO_ERROR = 0x00,
    GENERAL_PROTOCOL_ERROR = 0x01,
    INTERNAL_ERROR = 0x02,
    STREAM_CREATION_ERROR = 0x03,
    CLOSED_CRITICAL_STREAM = 0x04,
    FRAME_UNEXPECTED = 0x05,
    FRAME_ERROR = 0x06,
    EXCESSIVE_LOAD = 0x07,
    ID_ERROR = 0x09,
    SETTINGS_ERROR = 0x0A,
    MISSING_SETTINGS = 0x0B,
    REQUEST_REJECTED = 0x0C,
    REQUEST_CANCELLED = 0x0D,
    REQUEST_INCOMPLETE = 0x0E,
    MESSAGE_ERROR = 0x0F,
    CONNECT_ERROR = 0x10,
    VERSION_FALLBACK = 0x11,
    QPACK_DECOMPRESSION_FAILED = 0x200,
    QPACK_ENCODER_STREAM_ERROR = 0x201,
    QPACK_DECODER_STREAM_ERROR = 0x202,
};

// ============================================================================
// HTTP/3 Stream Types (RFC 9114 Section 6.2)
// ============================================================================

enum class StreamType : uint64_t {
    CONTROL = 0x00,
    PUSH = 0x01,
    QPACK_ENCODER = 0x02,
    QPACK_DECODER = 0x03,
    // 0x04-0x3F: reserved for future use
    // 0x40-0x3FFF: reserved for experiments
};

// ============================================================================
// Frame Header (decoded from varint encoding)
// ============================================================================

struct FrameHeader {
    FrameType m_type;
    uint64_t m_length;
};

// ============================================================================
// Frame Reader / Writer
// ============================================================================

class FrameReader {
public:
    FrameReader() = default;

    /// Try to read one frame from buffer.
    /// Returns bytes consumed (>0), 0 if incomplete, negative on error.
    int32_t readFrame(const uint8_t* p_data, size_t size,
                      FrameHeader& out, const uint8_t*& p_payload);
};

class FrameWriter {
public:
    FrameWriter() = default;

    /// Start building a frame. Reserves space for type + length varints.
    void beginFrame(FrameType type);

    /// Write raw payload data.
    void writePayload(const uint8_t* p_data, size_t size);

    /// Finalize the frame (fill in length varint).
    std::vector<uint8_t> endFrame();

    /// Build a complete frame in one shot.
    static std::vector<uint8_t> buildFrame(FrameType type,
                                            const uint8_t* p_payload,
                                            size_t payload_len);

private:
    std::vector<uint8_t> m_buf;
    size_t m_type_pos = 0;
    size_t m_len_pos = 0;
};

// ============================================================================
// QPACK — Header Compression for HTTP/3 (RFC 9204)
// ============================================================================

/// Simplified QPACK implementation using the same static table as HPACK.
/// Uses the HPACK static table (RFC 7541 Appendix A) internally.
class QPACK {
public:
    QPACK();
    ~QPACK() = default;
    QPACK(const QPACK&) = delete;
    QPACK& operator=(const QPACK&) = delete;

    /// Encode headers into a QPACK field section prefix + encoded field lines.
    std::vector<uint8_t> encode(
        const std::vector<std::pair<std::string, std::string>>& headers);

    /// Decode a QPACK field section.
    int32_t decode(const uint8_t* p_data, size_t size,
                   std::vector<std::pair<std::string, std::string>>& out);

    /// Process an encoder stream instruction.
    int32_t feedEncoderStream(const uint8_t* p_data, size_t size);

    /// Generate a decoder stream instruction (e.g., Insert Count Increment).
    std::vector<uint8_t> buildDecoderStream(uint64_t increment);

    /// Set max table capacity (from SETTINGS).
    void setMaxTableCapacity(uint64_t cap);

    /// Reset dynamic table to initial state.
    void reset();

    uint64_t maxTableCapacity() const { return m_max_table_capacity; }

private:
    uint64_t m_max_table_capacity = 4096;
    uint64_t m_table_capacity = 4096;

    struct HeaderEntry {
        std::string m_name;
        std::string m_value;
    };
    std::vector<HeaderEntry> m_dynamic_table;
    uint64_t m_dynamic_table_size = 0;
    uint64_t m_known_received_count = 0;

    // HPACK static table access (shared with http2)
    static bool getStaticEntry(size_t index, std::string& name,
                               std::string& value);
    uint32_t findTableIndex(const std::string& name) const;
    int32_t findTableEntry(const std::string& name,
                           const std::string& value) const;
    void addToDynamicTable(const std::string& name, const std::string& value);
    void evictToFit(uint64_t needed);
};

// ============================================================================
// QUIC Transport Interface (abstract)
//
// HTTP/3 requires a QUIC transport layer. Users must provide an
// implementation of this interface to send/receive UDP packets.
// ============================================================================

class QUICTransport {
public:
    virtual ~QUICTransport() = default;

    /// Send data on a given stream.
    virtual void sendStreamData(uint64_t stream_id, const uint8_t* p_data,
                                size_t size, bool fin) = 0;

    /// Send data on the control stream.
    virtual void sendControlData(const uint8_t* p_data, size_t size) = 0;

    /// Close connection with error.
    virtual void closeWithError(uint64_t error_code,
                                const std::string& reason) = 0;

    /// Returns true if the connection is still active.
    virtual bool isConnected() const = 0;
};

// ============================================================================
// HTTP/3 Connection
// ============================================================================

class Connection {
public:
    explicit Connection(QUICTransport* p_transport);
    ~Connection() = default;
    Connection(const Connection&) = delete;
    Connection& operator=(const Connection&) = delete;

    /// Reset connection state.
    void reset();

    /// Initialize HTTP/3 — send SETTINGS on control stream.
    void init();

    /// Feed data received on a QUIC stream.
    /// Stream type is auto-detected (control, encoder, decoder, or request).
    int32_t feedStream(uint64_t stream_id, const uint8_t* p_data, size_t size,
                       bool fin,
                       std::function<void(uint64_t stream_id,
                                          const FrameHeader&,
                                          const uint8_t*)> on_frame,
                       std::function<void(ErrorCode)> on_error);

    /// Build a response (HEADERS + optionally DATA) on a stream.
    std::vector<uint8_t> buildResponse(
        uint64_t stream_id,
        const std::vector<std::pair<std::string, std::string>>& headers,
        const uint8_t* p_body, size_t body_len, bool fin);

    /// Build a SETTINGS frame for the control stream.
    std::vector<uint8_t> buildSettings(
        const std::map<SettingsId, uint64_t>& settings);

    /// Build a GOAWAY frame.
    std::vector<uint8_t> buildGoaway(uint64_t last_stream_id);

    bool initialized() const { return m_initialized; }

private:
    QUICTransport* m_p_transport;
    bool m_initialized = false;

    uint64_t m_max_field_section_size = 0;
    QPACK m_qpack;

    // Stream tracking
    bool m_control_stream_received = false;
    bool m_encoder_stream_received = false;
    bool m_decoder_stream_received = false;

    int32_t processControlFrame(uint64_t stream_id, const FrameHeader& hdr,
                                const uint8_t* p_payload,
                                std::function<void(ErrorCode)> on_error);

    int32_t processFrames(uint64_t stream_id,
                          const uint8_t* p_data, size_t size, bool fin,
                          std::function<void(uint64_t, const FrameHeader&, const uint8_t*)> on_frame,
                          std::function<void(ErrorCode)> on_error);
};

} // namespace http3
} // namespace zane

#endif // ZANE_HTTP3_H
