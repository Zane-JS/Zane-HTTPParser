#include "http2.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <limits>

namespace zane {
namespace http2 {

// ============================================================================
// Huffman Tables (RFC 7541 Appendix B)
// ============================================================================

struct HuffmanCode {
    uint32_t m_code;
    uint8_t m_bits;
};

// (code, bits) for each symbol 0x00-0xFF
static const HuffmanCode kHuffmanEncode[256] = {
    {0x1ff8, 13},      {0x7fffd8, 23},    {0xfffffe2, 28},   {0xfffffe3, 28},
    {0xfffffe4, 28},   {0xfffffe5, 28},   {0xfffffe6, 28},   {0xfffffe7, 28},
    {0xfffffe8, 28},   {0xffffea, 24},    {0x3ffffffc, 30},  {0xfffffe9, 28},
    {0xfffffea, 28},   {0x3ffffffd, 30},  {0xfffffeb, 28},   {0xfffffec, 28},
    {0xfffffed, 28},   {0xfffffee, 28},   {0xfffffef, 28},   {0xffffff0, 28},
    {0xffffff1, 28},   {0xffffff2, 28},   {0x3ffffffe, 30},  {0xffffff3, 28},
    {0xffffff4, 28},   {0xffffff5, 28},   {0xffffff6, 28},   {0xffffff7, 28},
    {0xffffff8, 28},   {0xffffff9, 28},   {0xffffffa, 28},   {0xffffffb, 28},
    {0x14, 6},         {0x3f8, 10},       {0x3f9, 10},       {0xffa, 12},
    {0x1ff9, 13},      {0x15, 6},         {0xf8, 8},         {0x7fa, 11},
    {0x3fa, 10},       {0x3fb, 10},       {0xf9, 8},         {0x7fb, 11},
    {0xfa, 8},         {0x16, 6},         {0x17, 6},         {0x18, 6},
    {0x0, 5},          {0x1, 5},          {0x2, 5},          {0x19, 6},
    {0x1a, 6},         {0x1b, 6},         {0x1c, 6},         {0x1d, 6},
    {0x1e, 6},         {0x1f, 6},         {0x5c, 7},         {0xfb, 8},
    {0x7ffc, 15},      {0x20, 6},         {0xffb, 12},       {0x3fc, 10},
    {0x1ffa, 13},      {0x21, 6},         {0x5d, 7},         {0x5e, 7},
    {0x5f, 7},         {0x60, 7},         {0x61, 7},         {0x62, 7},
    {0x63, 7},         {0x64, 7},         {0x65, 7},         {0x66, 7},
    {0x67, 7},         {0x68, 7},         {0x69, 7},         {0x6a, 7},
    {0x6b, 7},         {0x6c, 7},         {0x6d, 7},         {0x6e, 7},
    {0x6f, 7},         {0x70, 7},         {0x71, 7},         {0x72, 7},
    {0xfc, 8},         {0x73, 7},         {0xfd, 8},         {0x1ffb, 13},
    {0x7fff0, 19},     {0x1ffc, 13},      {0x3ffc, 14},      {0x22, 6},
    {0x74, 7},         {0x75, 7},         {0x76, 7},         {0x77, 7},
    {0x78, 7},         {0x79, 7},         {0x7a, 7},         {0x7b, 7},
    {0x7c, 7},         {0x7d, 7},         {0x7e, 7},         {0x7f, 7},
    {0x80, 7},         {0x81, 7},         {0x82, 7},         {0x83, 7},
    {0x84, 7},         {0x85, 7},         {0x86, 7},         {0x87, 7},
    {0x88, 7},         {0x89, 7},         {0x8a, 7},         {0x8b, 7},
    {0x8c, 7},         {0x8d, 7},         {0x8e, 7},         {0x8f, 7},
    {0x90, 7},         {0x91, 7},         {0x92, 7},         {0x93, 7},
    {0x94, 7},         {0x95, 7},         {0x96, 7},         {0x97, 7},
    {0x98, 7},         {0x99, 7},         {0x9a, 7},         {0x9b, 7},
    {0x9c, 7},         {0x9d, 7},         {0x9e, 7},         {0x9f, 7},
    {0xa0, 7},         {0x1ffd, 13},      {0xffc, 12},       {0xffd, 12},
    {0x1ffe, 13},      {0x1fff, 13},      {0x2000, 13},      {0x3ffd, 14},
    {0x3ffe, 14},      {0x3fff, 14},      {0x4000, 14},      {0x4001, 14},
    {0x4002, 14},      {0x4003, 14},      {0x4004, 14},      {0x4005, 14},
    {0x4006, 14},      {0x4007, 14},      {0x4008, 14},      {0x4009, 14},
    {0x400a, 14},      {0x400b, 14},      {0x400c, 14},      {0x400d, 14},
    {0x400e, 14},      {0x400f, 14},      {0x4010, 14},      {0x4011, 14},
    {0x4012, 14},      {0x4013, 14},      {0x4014, 14},      {0x4015, 14},
    {0x4016, 14},      {0x4017, 14},      {0x4018, 14},      {0x4019, 14},
    {0x401a, 14},      {0x401b, 14},      {0x401c, 14},      {0x401d, 14},
    {0x401e, 14},      {0x401f, 14},      {0x4020, 14},      {0x4021, 14},
    {0x4022, 14},      {0x4023, 14},      {0x4024, 14},      {0x4025, 14},
    {0x4026, 14},      {0x4027, 14},      {0x4028, 14},      {0x4029, 14},
    {0x402a, 14},      {0x402b, 14},      {0x402c, 14},      {0x402d, 14},
    {0x402e, 14},      {0x402e, 14},      {0x402f, 14},      {0x402f, 14},
    {0x4030, 14},      {0x4030, 14},      {0x4031, 14},      {0x4031, 14},
    {0x4032, 14},      {0x4032, 14},      {0x4033, 14},      {0x4033, 14},
    {0x4034, 14},      {0x4034, 14},      {0x4035, 14},      {0x4035, 14},
    {0x4036, 14},      {0x4036, 14},      {0x4037, 14},      {0x4037, 14},
    {0x4038, 14},      {0x4038, 14},      {0x4039, 14},      {0x4039, 14},
    {0x403a, 14},      {0x403a, 14},      {0x403b, 14},      {0x403b, 14},
    {0x403c, 14},      {0x403c, 14},      {0x403d, 14},      {0x403d, 14},
    {0x403e, 14},      {0x403e, 14},      {0x403f, 14},      {0x403f, 14},
};

// Huffman decode tree node
struct HuffmanDecodeNode {
    int16_t m_next[2]; // child indices, -1 = none
    uint8_t m_value;
    bool m_is_leaf;
};

static void buildHuffmanTree(HuffmanDecodeNode* p_nodes, int32_t& node_count) {
    p_nodes[0].m_next[0] = -1;
    p_nodes[0].m_next[1] = -1;
    p_nodes[0].m_is_leaf = false;
    node_count = 1;

    for (int32_t sym = 0; sym < 256; ++sym) {
        uint32_t code = kHuffmanEncode[sym].m_code;
        int32_t bits = kHuffmanEncode[sym].m_bits;
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

// Lazily-initialized Huffman decode tree. As a function-local static with a
// non-trivial constructor, it benefits from the C++11 "magic statics" guarantee:
// the constructor runs exactly once, thread-safely, with proper
// synchronization/happens-before for all subsequent readers. This replaces a
// previous manual double-checked-locking pattern on a plain bool flag, which
// was a data race (UB) when two threads reached first-call concurrently.
struct HuffmanTree {
    HuffmanDecodeNode nodes[4096];
    int32_t m_node_count = 0;
    HuffmanTree() { buildHuffmanTree(nodes, m_node_count); }
};

static const HuffmanDecodeNode* getHuffmanTree() {
    static HuffmanTree s_tree;
    return s_tree.nodes;
}

// ============================================================================
// Static HPACK Table (RFC 7541 Appendix A)
// ============================================================================

struct StaticEntry {
    const char* p_name;
    const char* p_value;
    bool m_has_value;
};

static const StaticEntry kStaticTable[61] = {
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
// HPACK — Integer Encoding (RFC 7541 Section 5.1)
// ============================================================================

static void encodeInteger(uint8_t*& p_out, uint32_t value,
                           uint8_t prefix_bits, uint8_t prefix_byte) {
    uint32_t max_prefix = (1u << prefix_bits) - 1;
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

static uint32_t decodeInteger(const uint8_t* p_data, size_t size,
                               uint8_t prefix_bits, size_t& consumed) {
    consumed = 0;
    if (size == 0) return 0;
    uint32_t max_prefix = (1u << prefix_bits) - 1;
    uint32_t value = p_data[0] & max_prefix;
    if (value < max_prefix) {
        consumed = 1;
        return value;
    }
    size_t pos = 1;
    uint32_t shift = 0;
    while (pos < size) {
        uint8_t byte = p_data[pos++];
        value += static_cast<uint32_t>(byte & 0x7F) << shift;
        shift += 7;
        if (!(byte & 0x80)) {
            consumed = pos;
            return value;
        }
    }
    return 0;
}

// ============================================================================
// HPACK — String Encoding (RFC 7541 Section 5.2)
// ============================================================================

static void encodeString(uint8_t*& p_out, const std::string& str) {
    uint32_t len = static_cast<uint32_t>(str.size());
    // H flag = 0 (no Huffman), encode length in 7-bit prefix
    uint32_t max_prefix = 127;
    if (len < max_prefix) {
        *p_out++ = static_cast<uint8_t>(len); // bit 7 (H) = 0, 7-bit length
    } else {
        *p_out++ = static_cast<uint8_t>(max_prefix); // bit 7 = 0, lower 7 bits = 127
        len -= max_prefix;
        while (len >= 128) {
            *p_out++ = static_cast<uint8_t>((len & 0x7F) | 0x80);
            len >>= 7;
        }
        *p_out++ = static_cast<uint8_t>(len & 0x7F);
    }
    if (str.size() > 0) {
        std::memcpy(p_out, str.data(), str.size());
        p_out += str.size();
    }
}

static int32_t decodeString(const uint8_t* p_data, size_t size,
                             std::string& out, size_t& consumed) {
    consumed = 0;
    if (size == 0) return -1;
    bool huffman = (p_data[0] & 0x80) != 0;
    size_t len_consumed = 0;
    uint32_t str_len = decodeInteger(p_data, size, 7, len_consumed);
    if (len_consumed == 0 || len_consumed + static_cast<size_t>(str_len) > size) {
        return -1;
    }
    const uint8_t* p_str_start = p_data + len_consumed;

    if (huffman) {
        const HuffmanDecodeNode* p_tree = getHuffmanTree();
        out.clear();
        out.reserve(str_len);

        uint32_t bits_buf = 0;
        int32_t bits_in_buf = 0;
        const uint8_t* p_end = p_str_start + str_len;
        const uint8_t* p_src = p_str_start;

        while (p_src < p_end) {
            while (p_src < p_end && bits_in_buf <= 24) {
                bits_buf = (bits_buf << 8) | *p_src++;
                bits_in_buf += 8;
            }
            int32_t node_idx = 0;
            bool found = false;
            int32_t bits_used = 0;
            while (bits_in_buf > 0 && !found) {
                int32_t bit = static_cast<int32_t>((bits_buf >> (bits_in_buf - 1)) & 1);
                --bits_in_buf;
                ++bits_used;

                int32_t next = p_tree[node_idx].m_next[bit];
                if (next < 0) {
                    // Invalid Huffman sequence
                    consumed = 0;
                    return -2;
                }
                node_idx = next;
                if (p_tree[node_idx].m_is_leaf) {
                    out.push_back(static_cast<char>(p_tree[node_idx].m_value));
                    found = true;
                }
            }
            if (!found) {
                consumed = 0;
                return -2;
            }
        }
    } else {
        out.assign(reinterpret_cast<const char*>(p_str_start),
                   reinterpret_cast<const char*>(p_str_start + str_len));
    }

    consumed = len_consumed + static_cast<size_t>(str_len);
    return 0;
}

// ============================================================================
// HPACK — Dynamic Table
// ============================================================================

void HPACK::addToDynamicTable(const std::string& name, const std::string& value) {
    uint32_t entry_size = static_cast<uint32_t>(name.size() + value.size() + 32);
    evictToFit(entry_size);
    if (entry_size > m_max_table_size) {
        return;
    }
    m_dynamic_table.insert(m_dynamic_table.begin(), HeaderEntry{name, value});
    m_dynamic_table_size += entry_size;
}

void HPACK::evictToFit(uint32_t needed) {
    while (!m_dynamic_table.empty() &&
           m_dynamic_table_size + needed > m_max_table_size) {
        auto& entry = m_dynamic_table.back();
        uint32_t entry_size =
            static_cast<uint32_t>(entry.m_name.size() + entry.m_value.size() + 32);
        if (m_dynamic_table_size >= entry_size) {
            m_dynamic_table_size -= entry_size;
        } else {
            m_dynamic_table_size = 0;
        }
        m_dynamic_table.pop_back();
    }
}

bool HPACK::getStaticEntry(size_t index, std::string& name, std::string& value) {
    if (index < 1 || index > 61) return false;
    const auto& e = kStaticTable[index - 1];
    name = e.m_name;
    value = e.m_has_value ? e.m_value : "";
    return true;
}

bool HPACK::getDynamicEntry(size_t index, std::string& name,
                             std::string& value) const {
    size_t dyn_idx = index - 62;
    if (dyn_idx >= m_dynamic_table.size()) return false;
    name = m_dynamic_table[dyn_idx].m_name;
    value = m_dynamic_table[dyn_idx].m_value;
    return true;
}

size_t HPACK::totalEntries() const {
    return 61 + m_dynamic_table.size();
}

uint32_t HPACK::findTableIndex(const std::string& name) const {
    for (int32_t i = 0; i < 61; ++i) {
        if (name == kStaticTable[i].m_name) {
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

int32_t HPACK::findTableEntry(const std::string& name,
                               const std::string& value) const {
    for (int32_t i = 0; i < 61; ++i) {
        if (name == kStaticTable[i].m_name &&
            kStaticTable[i].m_has_value && value == kStaticTable[i].m_value) {
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

// ============================================================================
// HPACK — Encode
// ============================================================================

std::vector<uint8_t> HPACK::encode(
    const std::vector<std::pair<std::string, std::string>>& headers) {
    size_t est = 0;
    for (const auto& h : headers) {
        est += h.first.size() + h.second.size() + 16;
    }
    std::vector<uint8_t> buf(est + 128);
    uint8_t* p_out = buf.data();

    for (const auto& [name, value] : headers) {
        int32_t idx = findTableEntry(name, value);
        if (idx > 0) {
            // Indexed Header Field (RFC 7541 Section 6.1)
            encodeInteger(p_out, static_cast<uint32_t>(idx), 7, 0x80);
            continue;
        }

        uint32_t name_idx = findTableIndex(name);
        if (name_idx > 0) {
            // Literal with Incremental Indexing (RFC 7541 Section 6.2.1)
            encodeInteger(p_out, name_idx, 6, 0x40);
            encodeString(p_out, value);
            addToDynamicTable(name, value);
        } else {
            // Literal with Incremental Indexing, new name
            encodeInteger(p_out, 0, 6, 0x40); // index 0 = no name reference
            encodeString(p_out, name);
            encodeString(p_out, value);
            addToDynamicTable(name, value);
        }
    }

    buf.resize(static_cast<size_t>(p_out - buf.data()));
    return buf;
}

// ============================================================================
// HPACK — Decode
// ============================================================================

int32_t HPACK::decode(const uint8_t* p_data, size_t size,
                       std::vector<std::pair<std::string, std::string>>& out) {
    size_t pos = 0;
    out.clear();

    while (pos < size) {
        uint8_t first_byte = p_data[pos];

        if (first_byte & 0x80) {
            // Indexed Header Field (RFC 7541 Section 6.1)
            size_t consumed = 0;
            uint32_t index = decodeInteger(p_data + pos, size - pos, 7, consumed);
            if (consumed == 0) return -1;
            pos += consumed;

            std::string name, value;
            if (index >= 1 && index <= 61) {
                getStaticEntry(index, name, value);
            } else if (!getDynamicEntry(index, name, value)) {
                return -2;
            }
            out.emplace_back(std::move(name), std::move(value));

        } else if ((first_byte & 0xC0) == 0x40) {
            // Literal with Incremental Indexing (RFC 7541 Section 6.2.1)
            size_t consumed = 0;
            uint32_t name_index = decodeInteger(p_data + pos, size - pos, 6, consumed);
            if (consumed == 0) return -3;
            pos += consumed;

            std::string name;
            if (name_index == 0) {
                size_t str_consumed = 0;
                if (decodeString(p_data + pos, size - pos, name, str_consumed) != 0) {
                    return -4;
                }
                pos += str_consumed;
            } else {
                std::string tmp_value;
                if (name_index >= 1 && name_index <= 61) {
                    if (!getStaticEntry(name_index, name, tmp_value)) return -5;
                } else {
                    if (!getDynamicEntry(name_index, name, tmp_value)) return -5;
                }
            }

            std::string value;
            size_t str_consumed = 0;
            if (decodeString(p_data + pos, size - pos, value, str_consumed) != 0) {
                return -6;
            }
            pos += str_consumed;

            addToDynamicTable(name, value);
            out.emplace_back(std::move(name), std::move(value));

        } else if ((first_byte & 0xF0) == 0x00) {
            // Literal without Indexing (RFC 7541 Section 6.2.2)
            size_t consumed = 0;
            uint32_t name_index = decodeInteger(p_data + pos, size - pos, 4, consumed);
            if (consumed == 0) return -7;
            pos += consumed;

            std::string name;
            if (name_index == 0) {
                size_t str_consumed = 0;
                if (decodeString(p_data + pos, size - pos, name, str_consumed) != 0) {
                    return -8;
                }
                pos += str_consumed;
            } else {
                std::string tmp_value;
                if (name_index >= 1 && name_index <= 61) {
                    if (!getStaticEntry(name_index, name, tmp_value)) return -9;
                } else {
                    if (!getDynamicEntry(name_index, name, tmp_value)) return -9;
                }
            }

            std::string value;
            size_t str_consumed = 0;
            if (decodeString(p_data + pos, size - pos, value, str_consumed) != 0) {
                return -10;
            }
            pos += str_consumed;

            out.emplace_back(std::move(name), std::move(value));

        } else if ((first_byte & 0xF0) == 0x10) {
            // Literal Never Indexed (RFC 7541 Section 6.2.3)
            size_t consumed = 0;
            uint32_t name_index = decodeInteger(p_data + pos, size - pos, 4, consumed);
            if (consumed == 0) return -11;
            pos += consumed;

            std::string name;
            if (name_index == 0) {
                size_t str_consumed = 0;
                if (decodeString(p_data + pos, size - pos, name, str_consumed) != 0) {
                    return -12;
                }
                pos += str_consumed;
            } else {
                std::string tmp_value;
                if (name_index >= 1 && name_index <= 61) {
                    if (!getStaticEntry(name_index, name, tmp_value)) return -13;
                } else {
                    if (!getDynamicEntry(name_index, name, tmp_value)) return -13;
                }
            }

            std::string value;
            size_t str_consumed = 0;
            if (decodeString(p_data + pos, size - pos, value, str_consumed) != 0) {
                return -14;
            }
            pos += str_consumed;

            out.emplace_back(std::move(name), std::move(value));

        } else if ((first_byte & 0xE0) == 0x20) {
            // Dynamic Table Size Update (RFC 7541 Section 6.3)
            size_t consumed = 0;
            uint32_t new_size = decodeInteger(p_data + pos, size - pos, 5, consumed);
            if (consumed == 0) return -15;
            pos += consumed;
            setMaxTableSize(new_size);

        } else {
            return -16;
        }
    }

    return 0;
}

// ============================================================================
// HPACK — Constructor / setMaxTableSize
// ============================================================================

HPACK::HPACK() {
    m_dynamic_table.reserve(32);
}

void HPACK::reset() {
    m_dynamic_table.clear();
    m_dynamic_table_size = 0;
    m_max_table_size = 4096;
}

void HPACK::setMaxTableSize(uint32_t size) {
    m_max_table_size = size;
    while (m_dynamic_table_size > m_max_table_size && !m_dynamic_table.empty()) {
        auto& entry = m_dynamic_table.back();
        uint32_t entry_size =
            static_cast<uint32_t>(entry.m_name.size() + entry.m_value.size() + 32);
        if (m_dynamic_table_size >= entry_size) {
            m_dynamic_table_size -= entry_size;
        } else {
            m_dynamic_table_size = 0;
        }
        m_dynamic_table.pop_back();
    }
}

// ============================================================================
// Frame Reader
// ============================================================================

int32_t FrameReader::readFrame(const uint8_t* p_data, size_t size,
                                FrameHeader& out, const uint8_t*& p_payload) {
    if (size < 9) {
        return 0;
    }

    uint32_t length = (static_cast<uint32_t>(p_data[0]) << 16) |
                      (static_cast<uint32_t>(p_data[1]) << 8) |
                      static_cast<uint32_t>(p_data[2]);
    FrameType type = static_cast<FrameType>(p_data[3]);
    uint8_t flags = p_data[4];
    uint32_t stream_id = (static_cast<uint32_t>(p_data[5]) << 24) |
                          (static_cast<uint32_t>(p_data[6]) << 16) |
                          (static_cast<uint32_t>(p_data[7]) << 8) |
                          static_cast<uint32_t>(p_data[8]);
    stream_id &= 0x7FFFFFFFu;

    if (length > m_max_frame_size) {
        return -1;
    }
    if (type == FrameType::SETTINGS && stream_id != 0) return -2;
    if (type == FrameType::PING && stream_id != 0) return -3;
    if (type == FrameType::GOAWAY && stream_id != 0) return -4;

    uint32_t frame_size = 9 + length;
    if (size < frame_size) {
        return 0;
    }

    out.m_length = length;
    out.m_type = type;
    out.m_flags = flags;
    out.m_stream_id = stream_id;
    p_payload = p_data + 9;

    return static_cast<int32_t>(frame_size);
}

// ============================================================================
// Connection — Preface
// ============================================================================

static const uint8_t k_client_preface[] =
    "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

static const size_t k_client_preface_len = 24;

const uint8_t* Connection::clientPreface() {
    return k_client_preface;
}

size_t Connection::clientPrefaceLen() {
    return k_client_preface_len;
}

// ============================================================================
// Connection — Constructor / Reset
// ============================================================================

Connection::Connection() {
    reset();
}

void Connection::reset() {
    m_preface_received = false;
    m_last_peer_stream_id = 0;
    m_last_local_stream_id = 0;
    m_settings_max_frame_size = 16384;
    m_hpack.reset();
    m_frame_reader = FrameReader();
    m_frame_reader.setMaxFrameSize(m_settings_max_frame_size);
}

// ============================================================================
// Connection — Feed
// ============================================================================

int32_t Connection::feed(const uint8_t* p_data, size_t size,
                          std::function<void(const FrameHeader&, const uint8_t*)> on_frame,
                          std::function<void(ErrorCode)> on_error) {
    size_t pos = 0;

    if (!m_preface_received) {
        if (size < kClientPrefaceLen) {
            return 0;
        }
        if (std::memcmp(p_data, k_client_preface, k_client_preface_len) != 0) {
            if (on_error) on_error(ErrorCode::PROTOCOL_ERROR);
            return -1;
        }
        m_preface_received = true;
        pos = k_client_preface_len;
    }

    while (pos < size) {
        FrameHeader hdr;
        const uint8_t* p_payload = nullptr;
        int32_t res = m_frame_reader.readFrame(p_data + pos, size - pos,
                                                hdr, p_payload);
        if (res < 0) {
            if (on_error) on_error(ErrorCode::FRAME_SIZE_ERROR);
            return -2;
        }
        if (res == 0) {
            break;
        }

        int32_t proc_res = processFrame(hdr, p_payload, on_error);
        if (proc_res != 0) {
            return proc_res;
        }

        if (on_frame) {
            on_frame(hdr, p_payload);
        }

        pos += static_cast<size_t>(res);
    }

    return 0;
}

// ============================================================================
// Connection — Process Frame
// ============================================================================

int32_t Connection::processFrame(const FrameHeader& hdr, const uint8_t* p_payload,
                                  std::function<void(ErrorCode)> on_error) {
    switch (hdr.m_type) {
        case FrameType::SETTINGS: {
            if (hdr.m_flags & FrameFlags::ACK) {
                if (hdr.m_length != 0) {
                    if (on_error) on_error(ErrorCode::FRAME_SIZE_ERROR);
                    return -3;
                }
                break;
            }
            if (hdr.m_length % 6 != 0) {
                if (on_error) on_error(ErrorCode::FRAME_SIZE_ERROR);
                return -4;
            }
            for (uint32_t i = 0; i < hdr.m_length; i += 6) {
                uint16_t id = (static_cast<uint16_t>(p_payload[i]) << 8) |
                               static_cast<uint16_t>(p_payload[i + 1]);
                uint32_t val = (static_cast<uint32_t>(p_payload[i + 2]) << 24) |
                                (static_cast<uint32_t>(p_payload[i + 3]) << 16) |
                                (static_cast<uint32_t>(p_payload[i + 4]) << 8) |
                                static_cast<uint32_t>(p_payload[i + 5]);
                switch (static_cast<SettingsId>(id)) {
                    case SettingsId::MAX_FRAME_SIZE:
                        if (val < 16384 || val > 16777215) {
                            if (on_error) on_error(ErrorCode::PROTOCOL_ERROR);
                            return -5;
                        }
                        m_settings_max_frame_size = val;
                        m_frame_reader.setMaxFrameSize(val);
                        break;
                    case SettingsId::HEADER_TABLE_SIZE:
                        m_hpack.setMaxTableSize(val);
                        break;
                    default:
                        break;
                }
            }
            break;
        }

        case FrameType::GOAWAY: {
            if (hdr.m_length < 8) {
                if (on_error) on_error(ErrorCode::FRAME_SIZE_ERROR);
                return -6;
            }
            break;
        }

        case FrameType::PING: {
            if (hdr.m_length != 8) {
                if (on_error) on_error(ErrorCode::FRAME_SIZE_ERROR);
                return -7;
            }
            break;
        }

        case FrameType::HEADERS: {
            if (hdr.m_stream_id == 0) {
                if (on_error) on_error(ErrorCode::PROTOCOL_ERROR);
                return -8;
            }
            break;
        }

        case FrameType::DATA: {
            if (hdr.m_stream_id == 0) {
                if (on_error) on_error(ErrorCode::PROTOCOL_ERROR);
                return -9;
            }
            break;
        }

        case FrameType::RST_STREAM: {
            if (hdr.m_length != 4) {
                if (on_error) on_error(ErrorCode::FRAME_SIZE_ERROR);
                return -10;
            }
            break;
        }

        default:
            break;
    }
    return 0;
}

// ============================================================================
// Connection — Build Frame Header
// ============================================================================

static uint32_t buildFrameHeader(uint8_t* p_buf, uint32_t length,
                                  FrameType type, uint8_t flags,
                                  uint32_t stream_id) {
    p_buf[0] = static_cast<uint8_t>((length >> 16) & 0xFF);
    p_buf[1] = static_cast<uint8_t>((length >> 8) & 0xFF);
    p_buf[2] = static_cast<uint8_t>(length & 0xFF);
    p_buf[3] = static_cast<uint8_t>(type);
    p_buf[4] = flags;
    p_buf[5] = static_cast<uint8_t>((stream_id >> 24) & 0x7F);
    p_buf[6] = static_cast<uint8_t>((stream_id >> 16) & 0xFF);
    p_buf[7] = static_cast<uint8_t>((stream_id >> 8) & 0xFF);
    p_buf[8] = static_cast<uint8_t>(stream_id & 0xFF);
    return 9;
}

// ============================================================================
// Connection — Build Settings
// ============================================================================

std::vector<uint8_t> Connection::buildSettings(
    const std::map<SettingsId, uint32_t>& settings) {
    uint32_t payload_len = static_cast<uint32_t>(settings.size() * 6);
    std::vector<uint8_t> buf(9 + payload_len);

    ::zane::http2::buildFrameHeader(buf.data(), payload_len,
                                    FrameType::SETTINGS, 0, 0);

    size_t pos = 9;
    for (const auto& [id, val] : settings) {
        buf[pos++] = static_cast<uint8_t>((static_cast<uint16_t>(id) >> 8) & 0xFF);
        buf[pos++] = static_cast<uint8_t>(static_cast<uint16_t>(id) & 0xFF);
        buf[pos++] = static_cast<uint8_t>((val >> 24) & 0xFF);
        buf[pos++] = static_cast<uint8_t>((val >> 16) & 0xFF);
        buf[pos++] = static_cast<uint8_t>((val >> 8) & 0xFF);
        buf[pos++] = static_cast<uint8_t>(val & 0xFF);
    }

    return buf;
}

// ============================================================================
// Connection — Build Goaway
// ============================================================================

std::vector<uint8_t> Connection::buildGoaway(uint32_t last_stream_id,
                                              ErrorCode error) {
    std::vector<uint8_t> buf(9 + 8);

    ::zane::http2::buildFrameHeader(buf.data(), 8, FrameType::GOAWAY, 0, 0);

    buf[9] = static_cast<uint8_t>((last_stream_id >> 24) & 0x7F);
    buf[10] = static_cast<uint8_t>((last_stream_id >> 16) & 0xFF);
    buf[11] = static_cast<uint8_t>((last_stream_id >> 8) & 0xFF);
    buf[12] = static_cast<uint8_t>(last_stream_id & 0xFF);

    uint32_t ec = static_cast<uint32_t>(error);
    buf[13] = static_cast<uint8_t>((ec >> 24) & 0xFF);
    buf[14] = static_cast<uint8_t>((ec >> 16) & 0xFF);
    buf[15] = static_cast<uint8_t>((ec >> 8) & 0xFF);
    buf[16] = static_cast<uint8_t>(ec & 0xFF);

    return buf;
}

// ============================================================================
// Connection — Build Response (HEADERS + optional DATA)
// ============================================================================

std::vector<uint8_t> Connection::buildResponse(
    uint32_t stream_id,
    const std::vector<std::pair<std::string, std::string>>& headers,
    const uint8_t* p_body, size_t body_len, bool end_stream) {
    std::vector<uint8_t> hpack_block = m_hpack.encode(headers);

    uint8_t hdr_flags = FrameFlags::END_HEADERS;
    if (end_stream && (p_body == nullptr || body_len == 0)) {
        hdr_flags |= FrameFlags::END_STREAM;
    }

    uint32_t headers_payload_len = static_cast<uint32_t>(hpack_block.size());
    size_t total = 9 + headers_payload_len;

    bool has_data = (p_body != nullptr && body_len > 0);
    if (has_data) {
        total += 9 + body_len;
    }

    std::vector<uint8_t> buf(total);
    size_t pos = 0;

    ::zane::http2::buildFrameHeader(buf.data() + pos, headers_payload_len,
                                     FrameType::HEADERS, hdr_flags, stream_id);
    pos += 9;
    if (headers_payload_len > 0) {
        std::memcpy(buf.data() + pos, hpack_block.data(), hpack_block.size());
    }
    pos += headers_payload_len;

    if (has_data) {
        uint8_t data_flags = 0;
        if (end_stream) {
            data_flags |= FrameFlags::END_STREAM;
        }
        ::zane::http2::buildFrameHeader(buf.data() + pos,
                                         static_cast<uint32_t>(body_len),
                                         FrameType::DATA, data_flags, stream_id);
        pos += 9;
        std::memcpy(buf.data() + pos, p_body, body_len);
        pos += body_len;
    }

    return buf;
}

} // namespace http2
} // namespace zane
