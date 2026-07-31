#include "http3.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <limits>

namespace zane {
namespace http3 {

// ============================================================================
// Variable-Length Integer Encoding (RFC 9000 Section 16)
// ============================================================================

size_t encodeVarint(uint8_t* p_buf, uint64_t value) {
    if (value <= 63) {
        p_buf[0] = static_cast<uint8_t>(value);
        return 1;
    }
    if (value <= 16383) {
        p_buf[0] = static_cast<uint8_t>(0x40 | (value >> 8));
        p_buf[1] = static_cast<uint8_t>(value & 0xFF);
        return 2;
    }
    if (value <= 1073741823) {
        p_buf[0] = static_cast<uint8_t>(0x80 | (value >> 24));
        p_buf[1] = static_cast<uint8_t>((value >> 16) & 0xFF);
        p_buf[2] = static_cast<uint8_t>((value >> 8) & 0xFF);
        p_buf[3] = static_cast<uint8_t>(value & 0xFF);
        return 4;
    }
    // 8-byte (value <= 2^62-1)
    p_buf[0] = static_cast<uint8_t>(0xC0 | ((value >> 56) & 0x3F));
    p_buf[1] = static_cast<uint8_t>((value >> 48) & 0xFF);
    p_buf[2] = static_cast<uint8_t>((value >> 40) & 0xFF);
    p_buf[3] = static_cast<uint8_t>((value >> 32) & 0xFF);
    p_buf[4] = static_cast<uint8_t>((value >> 24) & 0xFF);
    p_buf[5] = static_cast<uint8_t>((value >> 16) & 0xFF);
    p_buf[6] = static_cast<uint8_t>((value >> 8) & 0xFF);
    p_buf[7] = static_cast<uint8_t>(value & 0xFF);
    return 8;
}

size_t decodeVarint(const uint8_t* p_data, size_t size, uint64_t& value) {
    if (size == 0) return 0;
    uint8_t first = p_data[0];
    uint8_t prefix = first >> 6;

    switch (prefix) {
        case 0: // 1 byte, 6-bit value
            value = first & 0x3F;
            return 1;
        case 1: // 2 bytes, 14-bit value
            if (size < 2) return 0;
            value = (static_cast<uint64_t>(first & 0x3F) << 8) | p_data[1];
            return 2;
        case 2: // 4 bytes, 30-bit value
            if (size < 4) return 0;
            value = (static_cast<uint64_t>(first & 0x3F) << 24) |
                    (static_cast<uint64_t>(p_data[1]) << 16) |
                    (static_cast<uint64_t>(p_data[2]) << 8) |
                    static_cast<uint64_t>(p_data[3]);
            return 4;
        case 3: // 8 bytes, 62-bit value
            if (size < 8) return 0;
            value = (static_cast<uint64_t>(first & 0x3F) << 56) |
                    (static_cast<uint64_t>(p_data[1]) << 48) |
                    (static_cast<uint64_t>(p_data[2]) << 40) |
                    (static_cast<uint64_t>(p_data[3]) << 32) |
                    (static_cast<uint64_t>(p_data[4]) << 24) |
                    (static_cast<uint64_t>(p_data[5]) << 16) |
                    (static_cast<uint64_t>(p_data[6]) << 8) |
                    static_cast<uint64_t>(p_data[7]);
            return 8;
    }
    return 0;
}

// ============================================================================
// Reserved Frame Types
// ============================================================================

bool isReservedFrameType(uint64_t raw_type) {
    return (raw_type == 0x02 || raw_type == 0x06 ||
            (raw_type >= 0x08 && raw_type <= 0x0C) ||
            (raw_type >= 0x10 && raw_type <= 0x1F));
}

// ============================================================================
// Frame Reader
// ============================================================================

int32_t FrameReader::readFrame(const uint8_t* p_data, size_t size,
                                FrameHeader& out, const uint8_t*& p_payload) {
    size_t pos = 0;

    // Decode frame type (varint)
    uint64_t raw_type = 0;
    size_t type_consumed = decodeVarint(p_data + pos, size - pos, raw_type);
    if (type_consumed == 0) return 0;
    pos += type_consumed;

    // Decode length (varint)
    uint64_t length = 0;
    size_t len_consumed = decodeVarint(p_data + pos, size - pos, length);
    if (len_consumed == 0) return 0;
    pos += len_consumed;

    // Check if we have the full frame
    if (pos + static_cast<size_t>(length) > size) {
        return 0;
    }

    if (isReservedFrameType(raw_type)) {
        out.m_type = static_cast<FrameType>(raw_type);
        out.m_length = length;
        p_payload = p_data + pos;
        return static_cast<int32_t>(pos + static_cast<size_t>(length));
    }

    out.m_type = static_cast<FrameType>(raw_type);
    out.m_length = length;
    p_payload = p_data + pos;

    return static_cast<int32_t>(pos + static_cast<size_t>(length));
}

// ============================================================================
// Frame Writer
// ============================================================================

void FrameWriter::beginFrame(FrameType type) {
    m_type_pos = m_buf.size();
    // Reserve space for type varint (max 8 bytes) and length varint (max 8 bytes)
    m_buf.resize(m_buf.size() + kMaxVarintSize * 2);
    m_len_pos = m_type_pos;

    // Write type (placeholder, will be overwritten in endFrame after payload)
    size_t used = encodeVarint(&m_buf[m_type_pos], static_cast<uint64_t>(type));
    m_len_pos = m_type_pos + used;
    // Leave length placeholder
}

void FrameWriter::writePayload(const uint8_t* p_data, size_t size) {
    m_buf.insert(m_buf.end(), p_data, p_data + size);
}

std::vector<uint8_t> FrameWriter::endFrame() {
    size_t payload_start = m_len_pos + kMaxVarintSize; // rough
    // Actually, payload starts after both varints. Let's find the real start.
    // The type is already written. We need to shift everything after type
    // and write the actual length.

    // Re-construct: type + length + payload follows
    std::vector<uint8_t> result;
    result.reserve(m_buf.size() + 16);

    // Write type
    uint64_t type_val = 0;
    size_t type_used = decodeVarint(&m_buf[m_type_pos],
                                     kMaxVarintSize, type_val);
    (void)type_val;

    uint8_t type_buf[kMaxVarintSize];
    size_t type_len = encodeVarint(type_buf, type_val);

    // Payload is everything after the type+length placeholders
    // The payload starts at m_type_pos + kMaxVarintSize + kMaxVarintSize
    size_t payload_offset = m_type_pos + kMaxVarintSize * 2;
    size_t payload_len = m_buf.size() - payload_offset;

    uint8_t len_buf[kMaxVarintSize];
    size_t len_len = encodeVarint(len_buf, static_cast<uint64_t>(payload_len));

    result.insert(result.end(), type_buf, type_buf + type_len);
    result.insert(result.end(), len_buf, len_buf + len_len);
    if (payload_len > 0) {
        result.insert(result.end(), &m_buf[payload_offset],
                      &m_buf[payload_offset] + payload_len);
    }

    m_buf.clear();
    return result;
}

std::vector<uint8_t> FrameWriter::buildFrame(FrameType type,
                                               const uint8_t* p_payload,
                                               size_t payload_len) {
    std::vector<uint8_t> buf;
    uint8_t tmp[kMaxVarintSize * 2];

    size_t type_len = encodeVarint(tmp, static_cast<uint64_t>(type));
    buf.insert(buf.end(), tmp, tmp + type_len);

    size_t len_len = encodeVarint(tmp, static_cast<uint64_t>(payload_len));
    buf.insert(buf.end(), tmp, tmp + len_len);

    if (p_payload && payload_len > 0) {
        buf.insert(buf.end(), p_payload, p_payload + payload_len);
    }
    return buf;
}

// ============================================================================
// QPACK — Static Table (same as HPACK, RFC 7541 Appendix A)
// ============================================================================

struct StaticEntry {
    const char* p_name;
    const char* p_value;
    bool m_has_value;
};

static const StaticEntry kQPACKStaticTable[61] = {
    {":authority", "", false},
    {":method", "GET", true},
    {":method", "POST", true},
    {":path", "/", true},
    {":path", "/index.html", true},
    {":scheme", "http", true},
    {":scheme", "https", true},
    {":status", "200", true},
    {":status", "204", true},
    {":status", "206", true},
    {":status", "304", true},
    {":status", "400", true},
    {":status", "404", true},
    {":status", "500", true},
    {"accept-charset", "", false},
    {"accept-encoding", "", false},
    {"accept-language", "", false},
    {"accept-ranges", "", false},
    {"accept", "", false},
    {"access-control-allow-origin", "", false},
    {"age", "", false},
    {"allow", "", false},
    {"authorization", "", false},
    {"cache-control", "", false},
    {"content-disposition", "", false},
    {"content-encoding", "", false},
    {"content-language", "", false},
    {"content-length", "", false},
    {"content-location", "", false},
    {"content-range", "", false},
    {"content-type", "", false},
    {"cookie", "", false},
    {"date", "", false},
    {"etag", "", false},
    {"expect", "", false},
    {"expires", "", false},
    {"from", "", false},
    {"host", "", false},
    {"if-match", "", false},
    {"if-modified-since", "", false},
    {"if-none-match", "", false},
    {"if-range", "", false},
    {"if-unmodified-since", "", false},
    {"last-modified", "", false},
    {"link", "", false},
    {"location", "", false},
    {"max-forwards", "", false},
    {"proxy-authenticate", "", false},
    {"proxy-authorization", "", false},
    {"range", "", false},
    {"referer", "", false},
    {"refresh", "", false},
    {"retry-after", "", false},
    {"server", "", false},
    {"set-cookie", "", false},
    {"strict-transport-security", "", false},
    {"transfer-encoding", "", false},
    {"user-agent", "", false},
    {"vary", "", false},
    {"via", "", false},
    {"www-authenticate", "", false},
};

// ============================================================================
// QPACK — Integer Encoding (same as HPACK, RFC 7541 Section 5.1)
// ============================================================================

static void qpackEncodeInteger(uint8_t*& p_out, uint64_t value,
                                uint8_t prefix_bits, uint8_t prefix_byte) {
    uint64_t max_prefix = (1ULL << prefix_bits) - 1;
    if (value < max_prefix) {
        *p_out++ = static_cast<uint8_t>(prefix_byte | value);
    } else {
        *p_out++ = static_cast<uint8_t>(prefix_byte | max_prefix);
        value -= max_prefix;
        while (value >= 128) {
            *p_out++ = static_cast<uint8_t>((value & 0x7F) | 0x80);
            value >>= 7;
        }
        *p_out++ = static_cast<uint8_t>(value & 0x7F);
    }
}

static uint64_t qpackDecodeInteger(const uint8_t* p_data, size_t size,
                                    uint8_t prefix_bits, size_t& consumed) {
    consumed = 0;
    if (size == 0) return 0;
    uint64_t max_prefix = (1ULL << prefix_bits) - 1;
    uint64_t value = p_data[0] & max_prefix;
    if (value < max_prefix) {
        consumed = 1;
        return value;
    }
    size_t pos = 1;
    uint64_t shift = 0;
    while (pos < size) {
        uint8_t byte = p_data[pos++];
        value += static_cast<uint64_t>(byte & 0x7F) << shift;
        shift += 7;
        if (!(byte & 0x80)) {
            consumed = pos;
            return value;
        }
    }
    return 0;
}

// ============================================================================
// QPACK — String Decoding (same HPACK Huffman, adapted)
// ============================================================================

// Reuse HPACK Huffman tables from http2.cpp. Since http2 and http3 are
// separate translation units, we replicate a minimal Huffman decoder here.

struct HuffNode {
    int16_t m_next[2];
    uint8_t m_value;
    bool m_is_leaf;
};

static const uint32_t kHuffCode[256] = {
    0x1ff8, 0x7fffd8, 0xfffffe2, 0xfffffe3, 0xfffffe4, 0xfffffe5, 0xfffffe6,
    0xfffffe7, 0xfffffe8, 0xffffea, 0x3ffffffc, 0xfffffe9, 0xfffffea, 0x3ffffffd,
    0xfffffeb, 0xfffffec, 0xfffffed, 0xfffffee, 0xfffffef, 0xffffff0, 0xffffff1,
    0xffffff2, 0x3ffffffe, 0xffffff3, 0xffffff4, 0xffffff5, 0xffffff6, 0xffffff7,
    0xffffff8, 0xffffff9, 0xffffffa, 0xffffffb, 0x14, 0x3f8, 0x3f9, 0xffa,
    0x1ff9, 0x15, 0xf8, 0x7fa, 0x3fa, 0x3fb, 0xf9, 0x7fb, 0xfa, 0x16, 0x17,
    0x18, 0x0, 0x1, 0x2, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x5c,
    0xfb, 0x7ffc, 0x20, 0xffb, 0x3fc, 0x1ffa, 0x21, 0x5d, 0x5e, 0x5f, 0x60,
    0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c,
    0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0xfc, 0x73, 0xfd, 0x1ffb, 0x7fff0,
    0x1ffc, 0x3ffc, 0x22, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x7b,
    0x7c, 0x7d, 0x7e, 0x7f, 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
    0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f, 0x90, 0x91, 0x92, 0x93,
    0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
    0xa0, 0x1ffd, 0xffc, 0xffd, 0x1ffe, 0x1fff, 0x2000, 0x3ffd, 0x3ffe, 0x3fff,
    0x4000, 0x4001, 0x4002, 0x4003, 0x4004, 0x4005, 0x4006, 0x4007, 0x4008,
    0x4009, 0x400a, 0x400b, 0x400c, 0x400d, 0x400e, 0x400f, 0x4010, 0x4011,
    0x4012, 0x4013, 0x4014, 0x4015, 0x4016, 0x4017, 0x4018, 0x4019, 0x401a,
    0x401b, 0x401c, 0x401d, 0x401e, 0x401f, 0x4020, 0x4021, 0x4022, 0x4023,
    0x4024, 0x4025, 0x4026, 0x4027, 0x4028, 0x4029, 0x402a, 0x402b, 0x402c,
    0x402d, 0x402e, 0x402f, 0x4030, 0x4031, 0x4032, 0x4033, 0x4034, 0x4035,
    0x4036, 0x4037, 0x4038, 0x4039, 0x403a, 0x403b, 0x403c, 0x403d, 0x403e,
    0x403f,
};

static const uint8_t kHuffBits[256] = {
    13,23,28,28,28,28,28,28,28,24,30,28,28,30,28,28,28,28,28,28,28,28,30,28,
    28,28,28,28,28,28,28,28,6,10,10,12,13,6,8,11,10,10,8,11,8,6,6,6,5,5,5,6,
    6,6,6,6,6,6,7,8,15,6,12,10,13,6,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,
    7,7,7,7,8,7,8,13,19,13,14,6,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,
    7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,13,12,12,13,13,13,
    14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,
    14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,
    14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,
    14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,14,
};

static void buildHuffmanTree(HuffNode* p_nodes, int32_t& node_count) {
    p_nodes[0].m_next[0] = -1;
    p_nodes[0].m_next[1] = -1;
    p_nodes[0].m_is_leaf = false;
    node_count = 1;

    for (int32_t sym = 0; sym < 256; ++sym) {
        uint32_t code = kHuffCode[sym];
        int32_t bits = kHuffBits[sym];
        int32_t idx = 0;
        for (int32_t b = bits - 1; b >= 0; --b) {
            int32_t bit = static_cast<int32_t>((code >> b) & 1);
            if (p_nodes[idx].m_next[bit] == -1) {
                p_nodes[idx].m_next[bit] = static_cast<int16_t>(node_count);
                int32_t new_idx = node_count++;
                p_nodes[new_idx].m_next[0] = -1;
                p_nodes[new_idx].m_next[1] = -1;
                p_nodes[new_idx].m_is_leaf = false;
            }
            idx = p_nodes[idx].m_next[bit];
        }
        p_nodes[idx].m_value = static_cast<uint8_t>(sym);
        p_nodes[idx].m_is_leaf = true;
    }
}

static const HuffNode* getHuffmanTree() {
    static HuffNode s_nodes[4096];
    static int32_t s_node_count = 0;
    static bool s_init = false;
    if (!s_init) {
        buildHuffmanTree(s_nodes, s_node_count);
        s_init = true;
    }
    return s_nodes;
}

static int32_t qpackDecodeString(const uint8_t* p_data, size_t size,
                                  std::string& out, size_t& consumed) {
    consumed = 0;
    if (size == 0) return -1;
    bool huffman = (p_data[0] & 0x80) != 0;
    size_t len_consumed = 0;
    uint64_t str_len = qpackDecodeInteger(p_data, size, 7, len_consumed);
    if (len_consumed == 0 || len_consumed + static_cast<size_t>(str_len) > size) {
        return -1;
    }
    const uint8_t* p_str = p_data + len_consumed;

    if (huffman) {
        const HuffNode* p_tree = getHuffmanTree();
        out.clear();
        out.reserve(static_cast<size_t>(str_len));
        uint32_t bits_buf = 0;
        int32_t bits_in_buf = 0;
        const uint8_t* p_end = p_str + str_len;
        const uint8_t* p_src = p_str;

        while (p_src < p_end) {
            while (p_src < p_end && bits_in_buf <= 24) {
                bits_buf = (bits_buf << 8) | *p_src++;
                bits_in_buf += 8;
            }
            int32_t node_idx = 0;
            int32_t bits_used = 0;
            while (bits_in_buf > 0) {
                int32_t bit = static_cast<int32_t>((bits_buf >> (bits_in_buf - 1)) & 1);
                --bits_in_buf;
                ++bits_used;
                int32_t next = p_tree[node_idx].m_next[bit];
                if (next < 0) {
                    consumed = 0;
                    return -2;
                }
                node_idx = next;
                if (p_tree[node_idx].m_is_leaf) {
                    out.push_back(static_cast<char>(p_tree[node_idx].m_value));
                    break;
                }
            }
        }
    } else {
        out.assign(reinterpret_cast<const char*>(p_str),
                   reinterpret_cast<const char*>(p_str + str_len));
    }

    consumed = len_consumed + static_cast<size_t>(str_len);
    return 0;
}

// ============================================================================
// QPACK — String Encoding (plain, no Huffman for simplicity)
// ============================================================================

static void qpackEncodeString(uint8_t*& p_out, const std::string& str) {
    uint64_t len = static_cast<uint64_t>(str.size());
    // H flag = 0 (no Huffman), encode length with 7-bit prefix
    qpackEncodeInteger(p_out, len, 7, 0x00);
    if (len > 0) {
        std::memcpy(p_out, str.data(), static_cast<size_t>(len));
        p_out += static_cast<size_t>(len);
    }
}

// ============================================================================
// QPACK — Dynamic Table
// ============================================================================

bool QPACK::getStaticEntry(size_t index, std::string& name,
                            std::string& value) {
    if (index < 1 || index > 61) return false;
    const auto& e = kQPACKStaticTable[index - 1];
    name = e.p_name;
    value = e.m_has_value ? e.p_value : "";
    return true;
}

uint32_t QPACK::findTableIndex(const std::string& name) const {
    for (int32_t i = 0; i < 61; ++i) {
        if (name == kQPACKStaticTable[i].p_name) {
            return static_cast<uint32_t>(i + 1);
        }
    }
    for (size_t i = 0; i < m_dynamic_table.size(); ++i) {
        if (name == m_dynamic_table[i].m_name) {
            return static_cast<uint32_t>(62 + i);
        }
    }
    return 0;
}

int32_t QPACK::findTableEntry(const std::string& name,
                               const std::string& value) const {
    for (int32_t i = 0; i < 61; ++i) {
        if (name == kQPACKStaticTable[i].p_name &&
            kQPACKStaticTable[i].m_has_value && value == kQPACKStaticTable[i].p_value) {
            return i + 1;
        }
    }
    for (size_t i = 0; i < m_dynamic_table.size(); ++i) {
        if (name == m_dynamic_table[i].m_name &&
            value == m_dynamic_table[i].m_value) {
            return static_cast<int32_t>(62 + i);
        }
    }
    return 0;
}

void QPACK::addToDynamicTable(const std::string& name,
                               const std::string& value) {
    uint64_t entry_size = static_cast<uint64_t>(name.size() + value.size() + 32);
    evictToFit(entry_size);
    if (entry_size > m_table_capacity) return;
    m_dynamic_table.insert(m_dynamic_table.begin(), HeaderEntry{name, value});
    m_dynamic_table_size += entry_size;
}

void QPACK::evictToFit(uint64_t needed) {
    while (!m_dynamic_table.empty() &&
           m_dynamic_table_size + needed > m_table_capacity) {
        auto& entry = m_dynamic_table.back();
        uint64_t entry_size =
            static_cast<uint64_t>(entry.m_name.size() + entry.m_value.size() + 32);
        if (m_dynamic_table_size >= entry_size) {
            m_dynamic_table_size -= entry_size;
        } else {
            m_dynamic_table_size = 0;
        }
        m_dynamic_table.pop_back();
    }
}

// ============================================================================
// QPACK — Constructor / Settings
// ============================================================================

QPACK::QPACK() {
    m_dynamic_table.reserve(32);
}

void QPACK::setMaxTableCapacity(uint64_t cap) {
    m_max_table_capacity = cap;
    m_table_capacity = cap;
    while (m_dynamic_table_size > m_table_capacity && !m_dynamic_table.empty()) {
        auto& entry = m_dynamic_table.back();
        uint64_t entry_size =
            static_cast<uint64_t>(entry.m_name.size() + entry.m_value.size() + 32);
        if (m_dynamic_table_size >= entry_size) {
            m_dynamic_table_size -= entry_size;
        } else {
            m_dynamic_table_size = 0;
        }
        m_dynamic_table.pop_back();
    }
}

void QPACK::reset() {
    m_dynamic_table.clear();
    m_dynamic_table_size = 0;
    m_table_capacity = 4096;
    m_max_table_capacity = 4096;
    m_known_received_count = 0;
}

// ============================================================================
// QPACK — Encoder Stream
// ============================================================================

int32_t QPACK::feedEncoderStream(const uint8_t* p_data, size_t size) {
    // Simplified: handle Set Dynamic Table Capacity (RFC 9204 Section 4.1.2)
    // and Duplicate (Section 4.1.3), but mostly for capacity updates.
    size_t pos = 0;
    while (pos < size) {
        uint8_t first = p_data[pos];
        if ((first & 0xE0) == 0x20) {
            // Set Dynamic Table Capacity
            size_t consumed = 0;
            uint64_t cap = qpackDecodeInteger(p_data + pos, size - pos, 5, consumed);
            if (consumed == 0) return -1;
            pos += consumed;
            setMaxTableCapacity(cap);
        } else {
            // Other instructions (Insert With Name, Duplicate) — skip for now
            // In a full implementation these would add entries to dynamic table
            break;
        }
    }
    return 0;
}

// ============================================================================
// QPACK — Decoder Stream
// ============================================================================

std::vector<uint8_t> QPACK::buildDecoderStream(uint64_t increment) {
    std::vector<uint8_t> buf(8);
    uint8_t* p_out = buf.data();
    qpackEncodeInteger(p_out, increment, 7, 0x00); // Insert Count Increment
    buf.resize(static_cast<size_t>(p_out - buf.data()));
    return buf;
}

// ============================================================================
// QPACK — Encode
// ============================================================================

std::vector<uint8_t> QPACK::encode(
    const std::vector<std::pair<std::string, std::string>>& headers) {
    // QPACK field section: Required Insert Count + Delta Base + encoded lines
    // Simplified: use Indexed and Literal with Name Reference, always with
    // a base of 0 (no dynamic table reference from encoder).

    size_t est = 0;
    for (const auto& h : headers) {
        est += h.first.size() + h.second.size() + 16;
    }
    std::vector<uint8_t> buf(est + 64);
    uint8_t* p_out = buf.data();

    // QPACK prefix: Required Insert Count = 0 (no dynamic entries referenced)
    // Using 2-bit prefix encoding for small values (RFC 9204 Section 4.2.1)
    *p_out++ = 0x00; // Required Insert Count = 0 (2-bit prefix, no dynamic table refs)
    *p_out++ = 0x00; // Delta Base = 0 (S bit = 0, 7-bit value = 0)

    for (const auto& [name, value] : headers) {
        // Try indexed (name + value)
        int32_t idx = findTableEntry(name, value);
        if (idx > 0) {
            // Indexed Header Field (Section 4.3.1)
            qpackEncodeInteger(p_out, static_cast<uint64_t>(idx), 6, 0xC0);
            continue;
        }

        // Try indexed name
        uint32_t name_idx = findTableIndex(name);
        if (name_idx > 0) {
            // Literal with Name Reference (Section 4.3.2)
            qpackEncodeInteger(p_out, static_cast<uint64_t>(name_idx), 4, 0x50);
            qpackEncodeString(p_out, value);
        } else {
            // Literal with no Name Reference
            qpackEncodeInteger(p_out, 0, 4, 0x40);
            qpackEncodeString(p_out, name);
            qpackEncodeString(p_out, value);
        }
    }

    buf.resize(static_cast<size_t>(p_out - buf.data()));
    return buf;
}

// ============================================================================
// QPACK — Decode
// ============================================================================

int32_t QPACK::decode(const uint8_t* p_data, size_t size,
                       std::vector<std::pair<std::string, std::string>>& out) {
    // Skip Required Insert Count and Delta Base (first 2 bytes in simplest case)
    size_t pos = 0;
    if (size < 2) return -1;

    // Read Required Insert Count (2-bit prefix)
    // For simplicity, assume 0 (no dynamic table references)
    size_t consumed = 0;
    uint64_t required_insert_count = qpackDecodeInteger(p_data, size, 2, consumed);
    if (consumed == 0) return -1;
    pos += consumed;

    // Read Delta Base (7-bit prefix, S bit determines sign)
    uint64_t base = qpackDecodeInteger(p_data + pos, size - pos, 7, consumed);
    if (consumed == 0) return -1;
    pos += consumed;
    (void)base; // unused when no dynamic table references

    out.clear();

    while (pos < size) {
        uint8_t first_byte = p_data[pos];

        if ((first_byte & 0xC0) == 0xC0) {
            // Indexed Header Field (Section 4.3.1)
            uint64_t index = qpackDecodeInteger(p_data + pos, size - pos, 6, consumed);
            if (consumed == 0) return -2;
            pos += consumed;

            std::string name, value;
            if (index >= 1 && index <= 61) {
                getStaticEntry(static_cast<size_t>(index), name, value);
            } else {
                // Dynamic table lookup
                size_t dyn_idx = static_cast<size_t>(index) - 62;
                if (dyn_idx >= m_dynamic_table.size()) return -3;
                name = m_dynamic_table[dyn_idx].m_name;
                value = m_dynamic_table[dyn_idx].m_value;
            }
            out.emplace_back(std::move(name), std::move(value));

        } else if ((first_byte & 0xF0) == 0x50) {
            // Literal with Name Reference (static)
            uint64_t name_index = qpackDecodeInteger(p_data + pos, size - pos, 4, consumed);
            if (consumed == 0) return -4;
            pos += consumed;

            std::string name;
            if (name_index >= 1 && name_index <= 61) {
                std::string tmp;
                getStaticEntry(static_cast<size_t>(name_index), name, tmp);
            } else {
                size_t dyn_idx = static_cast<size_t>(name_index) - 62;
                if (dyn_idx >= m_dynamic_table.size()) return -5;
                name = m_dynamic_table[dyn_idx].m_name;
            }

            std::string value;
            size_t str_consumed = 0;
            if (qpackDecodeString(p_data + pos, size - pos, value, str_consumed) != 0) {
                return -6;
            }
            pos += str_consumed;
            out.emplace_back(std::move(name), std::move(value));

        } else if ((first_byte & 0xF0) == 0x40) {
            // Literal with no Name Reference
            consumed = 0;
            uint64_t dummy = qpackDecodeInteger(p_data + pos, size - pos, 4, consumed);
            if (consumed == 0) return -7;
            pos += consumed;
            (void)dummy;

            std::string name;
            size_t str_consumed = 0;
            if (qpackDecodeString(p_data + pos, size - pos, name, str_consumed) != 0) {
                return -8;
            }
            pos += str_consumed;

            std::string value;
            str_consumed = 0;
            if (qpackDecodeString(p_data + pos, size - pos, value, str_consumed) != 0) {
                return -9;
            }
            pos += str_consumed;
            out.emplace_back(std::move(name), std::move(value));

        } else if ((first_byte & 0xE0) == 0x20) {
            // Dynamic Table Capacity Update (in field section)
            uint64_t cap = qpackDecodeInteger(p_data + pos, size - pos, 5, consumed);
            if (consumed == 0) return -10;
            pos += consumed;
            setMaxTableCapacity(cap);

        } else {
            return -11;
        }
    }

    return 0;
}

// ============================================================================
// Connection — Constructor / Reset / Init
// ============================================================================

Connection::Connection(QUICTransport* p_transport)
    : p_transport(p_transport) {
    reset();
}

void Connection::reset() {
    m_initialized = false;
    m_control_stream_received = false;
    m_encoder_stream_received = false;
    m_decoder_stream_received = false;
    m_max_field_section_size = 0;
    m_qpack.reset();
}

void Connection::init() {
    if (m_initialized || !p_transport) return;

    // Send SETTINGS on the control stream (stream ID 2 = first client-initiated
    // unidirectional stream per QUIC stream mapping).
    // In practice, QUIC transport handles stream ID allocation.
    auto settings = buildSettings({
        {SettingsId::QPACK_MAX_TABLE_CAPACITY, 4096},
        {SettingsId::QPACK_BLOCKED_STREAMS, 100},
        {SettingsId::MAX_FIELD_SECTION_SIZE, 65536},
    });
    p_transport->sendControlData(settings.data(), settings.size());

    m_initialized = true;
}

// ============================================================================
// Connection — Feed Stream
// ============================================================================

int32_t Connection::feedStream(
    uint64_t stream_id,
    const uint8_t* p_data, size_t size, bool fin,
    std::function<void(uint64_t, const FrameHeader&, const uint8_t*)> on_frame,
    std::function<void(ErrorCode)> on_error) {

    // Detect stream type from first bytes
    // Control stream: first varint is StreamType::CONTROL (0x00)
    // QPACK encoder: StreamType::QPACK_ENCODER (0x02)
    // QPACK decoder: StreamType::QPACK_DECODER (0x03)
    // Request stream: first frame type (not a stream type marker)

    if (size == 0) {
        if (fin && on_frame) {
            // Empty stream with fin — stream close notification
            FrameHeader hdr{static_cast<FrameType>(0), 0};
            on_frame(stream_id, hdr, nullptr);
        }
        return 0;
    }

    // Try to decode as a reserved stream type
    uint64_t stream_type = 0;
    size_t consumed = decodeVarint(p_data, size, stream_type);
    if (consumed == 0) return 0;

    // Check for known unidirectional stream types
    if (stream_type == static_cast<uint64_t>(StreamType::CONTROL)) {
        if (m_control_stream_received) {
            if (on_error) on_error(ErrorCode::STREAM_CREATION_ERROR);
            return -1;
        }
        m_control_stream_received = true;
        // Process frames after the stream type marker
        return processFrames(stream_id, p_data + consumed,
                             size - consumed, fin, on_frame, on_error);
    }

    if (stream_type == static_cast<uint64_t>(StreamType::QPACK_ENCODER)) {
        if (m_encoder_stream_received) {
            if (on_error) on_error(ErrorCode::STREAM_CREATION_ERROR);
            return -2;
        }
        m_encoder_stream_received = true;
        int32_t res = m_qpack.feedEncoderStream(p_data + consumed,
                                                  size - consumed);
        if (res != 0 && on_error) {
            on_error(ErrorCode::QPACK_ENCODER_STREAM_ERROR);
        }
        return res;
    }

    if (stream_type == static_cast<uint64_t>(StreamType::QPACK_DECODER)) {
        if (m_decoder_stream_received) {
            if (on_error) on_error(ErrorCode::STREAM_CREATION_ERROR);
            return -3;
        }
        m_decoder_stream_received = true;
        // Decoder stream acknowledgments — process in full implementation
        return 0;
    }

    // Request stream: no stream type marker, process frames directly
    return processFrames(stream_id, p_data, size, fin, on_frame, on_error);
}

int32_t Connection::processFrames(
    uint64_t stream_id,
    const uint8_t* p_data, size_t size, bool fin,
    std::function<void(uint64_t, const FrameHeader&, const uint8_t*)> on_frame,
    std::function<void(ErrorCode)> on_error) {

    FrameReader reader;
    size_t pos = 0;

    while (pos < size) {
        FrameHeader hdr;
        const uint8_t* p_payload = nullptr;
        int32_t res = reader.readFrame(p_data + pos, size - pos,
                                        hdr, p_payload);
        if (res < 0) {
            if (on_error) on_error(ErrorCode::FRAME_ERROR);
            return -4;
        }
        if (res == 0) {
            break; // need more data
        }

        // Process control frames
        int32_t proc = processControlFrame(stream_id, hdr, p_payload, on_error);
        if (proc != 0) return proc;

        if (on_frame) {
            on_frame(stream_id, hdr, p_payload);
        }

        pos += static_cast<size_t>(res);
    }

    if (fin && pos == size && on_frame) {
        // End of stream notification
        FrameHeader eof_hdr{static_cast<FrameType>(0xFF), 0};
        on_frame(stream_id, eof_hdr, nullptr);
    }

    return 0;
}

int32_t Connection::processControlFrame(
    uint64_t stream_id,
    const FrameHeader& hdr,
    const uint8_t* p_payload,
    std::function<void(ErrorCode)> on_error) {
    (void)stream_id;

    switch (hdr.m_type) {
        case FrameType::SETTINGS: {
            size_t pos = 0;
            while (pos < hdr.m_length) {
                uint64_t id_raw = 0;
                size_t id_consumed = decodeVarint(p_payload + pos,
                                                   hdr.m_length - pos, id_raw);
                if (id_consumed == 0) {
                    if (on_error) on_error(ErrorCode::SETTINGS_ERROR);
                    return -5;
                }
                pos += id_consumed;

                uint64_t val = 0;
                size_t val_consumed = decodeVarint(p_payload + pos,
                                                    hdr.m_length - pos, val);
                if (val_consumed == 0) {
                    if (on_error) on_error(ErrorCode::SETTINGS_ERROR);
                    return -6;
                }
                pos += val_consumed;

                if (id_raw == static_cast<uint64_t>(SettingsId::HEADER_TABLE_SIZE)) {
                    m_qpack.setMaxTableCapacity(val);
                } else if (id_raw == static_cast<uint64_t>(SettingsId::MAX_FIELD_SECTION_SIZE)) {
                    m_max_field_section_size = val;
                }
            }
            break;
        }

        case FrameType::GOAWAY: {
            if (hdr.m_length < 8) {
                if (on_error) on_error(ErrorCode::FRAME_ERROR);
                return -7;
            }
            // Process GOAWAY — full implementation would track last stream ID
            break;
        }

        case FrameType::DATA:
        case FrameType::HEADERS:
        case FrameType::PUSH_PROMISE:
            // These are request/response frames, handled by the user callback
            break;

        case FrameType::CANCEL_PUSH:
        case FrameType::MAX_PUSH_ID:
        case FrameType::DUPLICATE_PUSH:
            // Server push related — ignored in basic implementation
            break;

        default:
            if (isReservedFrameType(static_cast<uint64_t>(hdr.m_type))) {
                // Reserved frame types MUST be ignored (RFC 9114 Section 7)
                break;
            }
            if (on_error) on_error(ErrorCode::FRAME_UNEXPECTED);
            return -8;
    }
    return 0;
}

// ============================================================================
// Connection — Build Settings
// ============================================================================

std::vector<uint8_t> Connection::buildSettings(
    const std::map<SettingsId, uint64_t>& settings) {

    // Build payload: alternating setting ID + value as varints
    std::vector<uint8_t> payload;
    payload.reserve(settings.size() * 8);

    uint8_t tmp[8];
    for (const auto& [id, val] : settings) {
        size_t id_len = encodeVarint(tmp, static_cast<uint64_t>(id));
        payload.insert(payload.end(), tmp, tmp + id_len);
        size_t val_len = encodeVarint(tmp, val);
        payload.insert(payload.end(), tmp, tmp + val_len);
    }

    return FrameWriter::buildFrame(FrameType::SETTINGS,
                                    payload.data(), payload.size());
}

// ============================================================================
// Connection — Build Goaway
// ============================================================================

std::vector<uint8_t> Connection::buildGoaway(uint64_t last_stream_id) {
    uint8_t payload[8];
    size_t used = encodeVarint(payload, last_stream_id);
    return FrameWriter::buildFrame(FrameType::GOAWAY, payload, used);
}

// ============================================================================
// Connection — Build Response
// ============================================================================

std::vector<uint8_t> Connection::buildResponse(
    uint64_t stream_id,
    const std::vector<std::pair<std::string, std::string>>& headers,
    const uint8_t* p_body, size_t body_len, bool fin) {

    std::vector<uint8_t> result;
    (void)stream_id;
    (void)fin;

    // Encode HEADERS frame
    std::vector<uint8_t> hpack_block = m_qpack.encode(headers);
    auto headers_frame = FrameWriter::buildFrame(FrameType::HEADERS,
                                                   hpack_block.data(),
                                                   hpack_block.size());
    result.insert(result.end(), headers_frame.begin(), headers_frame.end());

    // Encode DATA frame if body present
    if (p_body && body_len > 0) {
        auto data_frame = FrameWriter::buildFrame(FrameType::DATA,
                                                    p_body, body_len);
        result.insert(result.end(), data_frame.begin(), data_frame.end());
    }

    return result;
}

} // namespace http3
} // namespace zane
