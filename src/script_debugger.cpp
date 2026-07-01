// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "kernel/bitcoinkernel_wrapper.h"

#include <array>
#include <cctype>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <optional>
#include <memory>
#include <optional>
#include <span>
#include <sstream>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <vector>

#include <unistd.h> // isatty, STDOUT_FILENO

namespace script_asm {

// ---------------------------------------------------------------------
// opcodes
// ---------------------------------------------------------------------

enum Opcode : uint8_t {
    OP_0 = 0x00,
    OP_PUSHDATA1 = 0x4c,
    OP_PUSHDATA2 = 0x4d,
    OP_PUSHDATA4 = 0x4e,
    OP_1NEGATE = 0x4f,
    OP_RESERVED = 0x50,
    OP_1 = 0x51,
    OP_16 = 0x60,
    OP_NOP = 0x61,
    OP_VER = 0x62,
    OP_IF = 0x63,
    OP_NOTIF = 0x64,
    OP_VERIF = 0x65,
    OP_VERNOTIF = 0x66,
    OP_ELSE = 0x67,
    OP_ENDIF = 0x68,
    OP_VERIFY = 0x69,
    OP_RETURN = 0x6a,
    OP_TOALTSTACK = 0x6b,
    OP_FROMALTSTACK = 0x6c,
    OP_2DROP = 0x6d,
    OP_2DUP = 0x6e,
    OP_3DUP = 0x6f,
    OP_2OVER = 0x70,
    OP_2ROT = 0x71,
    OP_2SWAP = 0x72,
    OP_IFDUP = 0x73,
    OP_DEPTH = 0x74,
    OP_DROP = 0x75,
    OP_DUP = 0x76,
    OP_NIP = 0x77,
    OP_OVER = 0x78,
    OP_PICK = 0x79,
    OP_ROLL = 0x7a,
    OP_ROT = 0x7b,
    OP_SWAP = 0x7c,
    OP_TUCK = 0x7d,
    OP_CAT = 0x7e,
    OP_SUBSTR = 0x7f,
    OP_LEFT = 0x80,
    OP_RIGHT = 0x81,
    OP_SIZE = 0x82,
    OP_INVERT = 0x83,
    OP_AND = 0x84,
    OP_OR = 0x85,
    OP_XOR = 0x86,
    OP_EQUAL = 0x87,
    OP_EQUALVERIFY = 0x88,
    OP_RESERVED1 = 0x89,
    OP_RESERVED2 = 0x8a,
    OP_1ADD = 0x8b,
    OP_1SUB = 0x8c,
    OP_2MUL = 0x8d,
    OP_2DIV = 0x8e,
    OP_NEGATE = 0x8f,
    OP_ABS = 0x90,
    OP_NOT = 0x91,
    OP_0NOTEQUAL = 0x92,
    OP_ADD = 0x93,
    OP_SUB = 0x94,
    OP_MUL = 0x95,
    OP_DIV = 0x96,
    OP_MOD = 0x97,
    OP_LSHIFT = 0x98,
    OP_RSHIFT = 0x99,
    OP_BOOLAND = 0x9a,
    OP_BOOLOR = 0x9b,
    OP_NUMEQUAL = 0x9c,
    OP_NUMEQUALVERIFY = 0x9d,
    OP_NUMNOTEQUAL = 0x9e,
    OP_LESSTHAN = 0x9f,
    OP_GREATERTHAN = 0xa0,
    OP_LESSTHANOREQUAL = 0xa1,
    OP_GREATERTHANOREQUAL = 0xa2,
    OP_MIN = 0xa3,
    OP_MAX = 0xa4,
    OP_WITHIN = 0xa5,
    OP_RIPEMD160 = 0xa6,
    OP_SHA1 = 0xa7,
    OP_SHA256 = 0xa8,
    OP_HASH160 = 0xa9,
    OP_HASH256 = 0xaa,
    OP_CODESEPARATOR = 0xab,
    OP_CHECKSIG = 0xac,
    OP_CHECKSIGVERIFY = 0xad,
    OP_CHECKMULTISIG = 0xae,
    OP_CHECKMULTISIGVERIFY = 0xaf,
    OP_NOP1 = 0xb0,
    OP_CHECKLOCKTIMEVERIFY = 0xb1,
    OP_CHECKSEQUENCEVERIFY = 0xb2,
    OP_NOP4 = 0xb3,
    OP_NOP5 = 0xb4,
    OP_NOP6 = 0xb5,
    OP_NOP7 = 0xb6,
    OP_NOP8 = 0xb7,
    OP_NOP9 = 0xb8,
    OP_NOP10 = 0xb9,
    OP_CHECKSIGADD = 0xba,
    OP_INVALIDOPCODE = 0xff,
};

namespace detail {

inline void InitTables(std::unordered_map<std::string, uint8_t>& name_to_op,
                        std::array<std::string, 256>& op_to_name) {
    auto add = [&](uint8_t op, const std::string& name) {
        name_to_op[name] = op;
        op_to_name[op] = name;
    };

    add(OP_0, "OP_0");
    name_to_op["OP_FALSE"] = OP_0;
    for (int i = 1; i <= 16; ++i) {
        add(static_cast<uint8_t>(OP_1 + i - 1), "OP_" + std::to_string(i));
    }
    name_to_op["OP_TRUE"] = OP_1;

    add(OP_PUSHDATA1, "OP_PUSHDATA1");
    add(OP_PUSHDATA2, "OP_PUSHDATA2");
    add(OP_PUSHDATA4, "OP_PUSHDATA4");
    add(OP_1NEGATE, "OP_1NEGATE");
    add(OP_RESERVED, "OP_RESERVED");
    add(OP_NOP, "OP_NOP");
    add(OP_VER, "OP_VER");
    add(OP_IF, "OP_IF");
    add(OP_NOTIF, "OP_NOTIF");
    add(OP_VERIF, "OP_VERIF");
    add(OP_VERNOTIF, "OP_VERNOTIF");
    add(OP_ELSE, "OP_ELSE");
    add(OP_ENDIF, "OP_ENDIF");
    add(OP_VERIFY, "OP_VERIFY");
    add(OP_RETURN, "OP_RETURN");
    add(OP_TOALTSTACK, "OP_TOALTSTACK");
    add(OP_FROMALTSTACK, "OP_FROMALTSTACK");
    add(OP_2DROP, "OP_2DROP");
    add(OP_2DUP, "OP_2DUP");
    add(OP_3DUP, "OP_3DUP");
    add(OP_2OVER, "OP_2OVER");
    add(OP_2ROT, "OP_2ROT");
    add(OP_2SWAP, "OP_2SWAP");
    add(OP_IFDUP, "OP_IFDUP");
    add(OP_DEPTH, "OP_DEPTH");
    add(OP_DROP, "OP_DROP");
    add(OP_DUP, "OP_DUP");
    add(OP_NIP, "OP_NIP");
    add(OP_OVER, "OP_OVER");
    add(OP_PICK, "OP_PICK");
    add(OP_ROLL, "OP_ROLL");
    add(OP_ROT, "OP_ROT");
    add(OP_SWAP, "OP_SWAP");
    add(OP_TUCK, "OP_TUCK");
    add(OP_CAT, "OP_CAT");
    add(OP_SUBSTR, "OP_SUBSTR");
    add(OP_LEFT, "OP_LEFT");
    add(OP_RIGHT, "OP_RIGHT");
    add(OP_SIZE, "OP_SIZE");
    add(OP_INVERT, "OP_INVERT");
    add(OP_AND, "OP_AND");
    add(OP_OR, "OP_OR");
    add(OP_XOR, "OP_XOR");
    add(OP_EQUAL, "OP_EQUAL");
    add(OP_EQUALVERIFY, "OP_EQUALVERIFY");
    add(OP_RESERVED1, "OP_RESERVED1");
    add(OP_RESERVED2, "OP_RESERVED2");
    add(OP_1ADD, "OP_1ADD");
    add(OP_1SUB, "OP_1SUB");
    add(OP_2MUL, "OP_2MUL");
    add(OP_2DIV, "OP_2DIV");
    add(OP_NEGATE, "OP_NEGATE");
    add(OP_ABS, "OP_ABS");
    add(OP_NOT, "OP_NOT");
    add(OP_0NOTEQUAL, "OP_0NOTEQUAL");
    add(OP_ADD, "OP_ADD");
    add(OP_SUB, "OP_SUB");
    add(OP_MUL, "OP_MUL");
    add(OP_DIV, "OP_DIV");
    add(OP_MOD, "OP_MOD");
    add(OP_LSHIFT, "OP_LSHIFT");
    add(OP_RSHIFT, "OP_RSHIFT");
    add(OP_BOOLAND, "OP_BOOLAND");
    add(OP_BOOLOR, "OP_BOOLOR");
    add(OP_NUMEQUAL, "OP_NUMEQUAL");
    add(OP_NUMEQUALVERIFY, "OP_NUMEQUALVERIFY");
    add(OP_NUMNOTEQUAL, "OP_NUMNOTEQUAL");
    add(OP_LESSTHAN, "OP_LESSTHAN");
    add(OP_GREATERTHAN, "OP_GREATERTHAN");
    add(OP_LESSTHANOREQUAL, "OP_LESSTHANOREQUAL");
    add(OP_GREATERTHANOREQUAL, "OP_GREATERTHANOREQUAL");
    add(OP_MIN, "OP_MIN");
    add(OP_MAX, "OP_MAX");
    add(OP_WITHIN, "OP_WITHIN");
    add(OP_RIPEMD160, "OP_RIPEMD160");
    add(OP_SHA1, "OP_SHA1");
    add(OP_SHA256, "OP_SHA256");
    add(OP_HASH160, "OP_HASH160");
    add(OP_HASH256, "OP_HASH256");
    add(OP_CODESEPARATOR, "OP_CODESEPARATOR");
    add(OP_CHECKSIG, "OP_CHECKSIG");
    add(OP_CHECKSIGVERIFY, "OP_CHECKSIGVERIFY");
    add(OP_CHECKMULTISIG, "OP_CHECKMULTISIG");
    add(OP_CHECKMULTISIGVERIFY, "OP_CHECKMULTISIGVERIFY");
    add(OP_NOP1, "OP_NOP1");
    add(OP_CHECKLOCKTIMEVERIFY, "OP_CHECKLOCKTIMEVERIFY");
    name_to_op["OP_NOP2"] = OP_CHECKLOCKTIMEVERIFY;
    add(OP_CHECKSEQUENCEVERIFY, "OP_CHECKSEQUENCEVERIFY");
    name_to_op["OP_NOP3"] = OP_CHECKSEQUENCEVERIFY;
    add(OP_NOP4, "OP_NOP4");
    add(OP_NOP5, "OP_NOP5");
    add(OP_NOP6, "OP_NOP6");
    add(OP_NOP7, "OP_NOP7");
    add(OP_NOP8, "OP_NOP8");
    add(OP_NOP9, "OP_NOP9");
    add(OP_NOP10, "OP_NOP10");
    add(OP_CHECKSIGADD, "OP_CHECKSIGADD");
}

inline const std::array<std::string, 256>& OpToNameTable() {
    static const std::array<std::string, 256> table = [] {
        std::array<std::string, 256> t{};
        std::unordered_map<std::string, uint8_t> dummy;
        InitTables(dummy, t);
        return t;
    }();
    return table;
}

inline const std::unordered_map<std::string, uint8_t>& NameToOpTable() {
    static const std::unordered_map<std::string, uint8_t> table = [] {
        std::unordered_map<std::string, uint8_t> m;
        std::array<std::string, 256> dummy{};
        InitTables(m, dummy);
        return m;
    }();
    return table;
}

} // namespace detail

inline std::string OpName(uint8_t op) {
    const std::string& name = detail::OpToNameTable()[op];
    if (!name.empty()) return name;
    std::ostringstream oss;
    oss << "OP_UNKNOWN(0x" << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(op) << ")";
    return oss.str();
}

inline std::optional<uint8_t> OpFromName(const std::string& name) {
    const auto& table = detail::NameToOpTable();
    auto it = table.find(name);
    if (it == table.end()) return std::nullopt;
    return it->second;
}

// ---------------------------------------------------------------------
// hex helpers
// ---------------------------------------------------------------------

inline std::string HexStr(const uint8_t* data, size_t len) {
    static const char* kHex = "0123456789abcdef";
    std::string s;
    s.reserve(len * 2);
    for (size_t i = 0; i < len; ++i) {
        s.push_back(kHex[data[i] >> 4]);
        s.push_back(kHex[data[i] & 0xf]);
    }
    return s;
}
inline std::string HexStr(const std::vector<uint8_t>& v) { return HexStr(v.data(), v.size()); }

inline std::string Trim(const std::string& s) {
    size_t b = s.find_first_not_of(" \t\r\n");
    if (b == std::string::npos) return "";
    size_t e = s.find_last_not_of(" \t\r\n");
    return s.substr(b, e - b + 1);
}

inline std::vector<uint8_t> ParseHexBytes(const std::string& hex) {
    if (hex.size() % 2 != 0) throw std::runtime_error("hex string has odd length: " + hex);
    auto hexval = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        throw std::runtime_error("invalid hex character in: " + std::string(1, c));
    };
    std::vector<uint8_t> out;
    out.reserve(hex.size() / 2);
    for (size_t i = 0; i < hex.size(); i += 2) {
        out.push_back(static_cast<uint8_t>((hexval(hex[i]) << 4) | hexval(hex[i + 1])));
    }
    return out;
}

// Trims whitespace and an optional 0x/0X prefix, then parses.
inline std::vector<uint8_t> ParseHexLenient(const std::string& raw) {
    std::string s = Trim(raw);
    if (s.size() >= 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) s = s.substr(2);
    return ParseHexBytes(s);
}

// ---------------------------------------------------------------------
// script-number (CScriptNum) encoding, matching Bitcoin Core's minimal
// sign-magnitude little-endian push encoding.
// ---------------------------------------------------------------------

inline std::vector<uint8_t> EncodeScriptNum(int64_t value) {
    if (value == 0) return {};
    std::vector<uint8_t> result;
    const bool neg = value < 0;
    uint64_t absvalue = neg ? (0ULL - static_cast<uint64_t>(value)) : static_cast<uint64_t>(value);
    while (absvalue) {
        result.push_back(static_cast<uint8_t>(absvalue & 0xff));
        absvalue >>= 8;
    }
    if (result.back() & 0x80) {
        result.push_back(neg ? 0x80 : 0x00);
    } else if (neg) {
        result.back() |= 0x80;
    }
    return result;
}

// Display-only inverse of EncodeScriptNum. Caller should only use this on
// short items (see FormatStackItem) to stay safely within int64_t range.
inline int64_t DecodeScriptNum(const std::vector<uint8_t>& v) {
    if (v.empty()) return 0;
    uint64_t result = 0;
    for (size_t i = 0; i < v.size(); ++i) {
        result |= static_cast<uint64_t>(v[i]) << (8 * i);
    }
    if (v.back() & 0x80) {
        result &= ~(static_cast<uint64_t>(0x80) << (8 * (v.size() - 1)));
        return -static_cast<int64_t>(result);
    }
    return static_cast<int64_t>(result);
}

inline std::vector<uint8_t> PushRawData(const std::vector<uint8_t>& data) {
    std::vector<uint8_t> out;
    const size_t n = data.size();
    if (n == 0) {
        out.push_back(OP_0);
    } else if (n < OP_PUSHDATA1) {
        out.push_back(static_cast<uint8_t>(n));
    } else if (n <= 0xff) {
        out.push_back(OP_PUSHDATA1);
        out.push_back(static_cast<uint8_t>(n));
    } else if (n <= 0xffff) {
        out.push_back(OP_PUSHDATA2);
        out.push_back(static_cast<uint8_t>(n & 0xff));
        out.push_back(static_cast<uint8_t>((n >> 8) & 0xff));
    } else {
        out.push_back(OP_PUSHDATA4);
        for (int i = 0; i < 4; ++i) out.push_back(static_cast<uint8_t>((n >> (8 * i)) & 0xff));
    }
    out.insert(out.end(), data.begin(), data.end());
    return out;
}

inline std::vector<uint8_t> PushNumber(int64_t n) {
    if (n == -1) return {static_cast<uint8_t>(OP_1NEGATE)};
    if (n >= 0 && n <= 16) return {n == 0 ? static_cast<uint8_t>(OP_0) : static_cast<uint8_t>(OP_1 + n - 1)};
    return PushRawData(EncodeScriptNum(n));
}

// ---------------------------------------------------------------------
// assembler / disassembler
// ---------------------------------------------------------------------

inline std::vector<std::string> Tokenize(const std::string& asm_str) {
    std::vector<std::string> tokens;
    std::istringstream iss(asm_str);
    std::string tok;
    while (iss >> tok) tokens.push_back(tok);
    return tokens;
}

inline bool IsAllHexDigits(const std::string& s) {
    if (s.empty()) return false;
    for (char c : s) if (!std::isxdigit(static_cast<unsigned char>(c))) return false;
    return true;
}

inline bool IsDecimalNumber(const std::string& s) {
    if (s.empty()) return false;
    size_t i = (s[0] == '-') ? 1 : 0;
    if (i == s.size()) return false;
    for (; i < s.size(); ++i) if (!std::isdigit(static_cast<unsigned char>(s[i]))) return false;
    return true;
}

// ASM tokens: OP_NAMES, decimal numbers (minimally encoded like Bitcoin
// Core's own CScript << operator), 'quoted'/"quoted" ASCII literals, and
// bare/0x-prefixed hex literals (pushed as literal data, NOT minimally
// re-encoded -- this matches Bitcoin Core's core_read.cpp ASM parser).
inline std::vector<uint8_t> AssembleScript(const std::string& asm_str) {
    std::vector<uint8_t> out;
    for (const auto& tok : Tokenize(asm_str)) {
        std::string upper = tok;
        for (auto& c : upper) c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));

        if (upper.rfind("OP_", 0) == 0) {
            auto op = OpFromName(upper);
            if (!op) throw std::runtime_error("unknown opcode: " + tok);
            out.push_back(*op);
            continue;
        }

        if (tok.size() >= 2 &&
            ((tok.front() == '\'' && tok.back() == '\'') || (tok.front() == '"' && tok.back() == '"'))) {
            std::string content = tok.substr(1, tok.size() - 2);
            auto push = PushRawData(std::vector<uint8_t>(content.begin(), content.end()));
            out.insert(out.end(), push.begin(), push.end());
            continue;
        }

        if (IsDecimalNumber(tok)) {
            auto push = PushNumber(std::stoll(tok));
            out.insert(out.end(), push.begin(), push.end());
            continue;
        }

        std::string hex = tok;
        if (hex.rfind("0x", 0) == 0 || hex.rfind("0X", 0) == 0) hex = hex.substr(2);
        if (hex.empty() || hex.size() % 2 != 0 || !IsAllHexDigits(hex)) {
            throw std::runtime_error("cannot parse token as opcode, number, quoted string, or hex data: " + tok);
        }
        auto push = PushRawData(ParseHexBytes(hex));
        out.insert(out.end(), push.begin(), push.end());
    }
    return out;
}

inline std::string DisassembleScript(const std::vector<uint8_t>& script) {
    std::ostringstream oss;
    size_t i = 0;
    bool first = true;
    while (i < script.size()) {
        if (!first) oss << ' ';
        first = false;
        uint8_t op = script[i++];

        if (op >= 0x01 && op <= 0x4b) {
            size_t len = op;
            if (i + len > script.size()) { oss << "[truncated push]"; break; }
            oss << HexStr(script.data() + i, len);
            i += len;
        } else if (op == OP_PUSHDATA1) {
            if (i + 1 > script.size()) { oss << "[truncated PUSHDATA1]"; break; }
            size_t len = script[i]; i += 1;
            if (i + len > script.size()) { oss << "[truncated push]"; break; }
            oss << HexStr(script.data() + i, len);
            i += len;
        } else if (op == OP_PUSHDATA2) {
            if (i + 2 > script.size()) { oss << "[truncated PUSHDATA2]"; break; }
            size_t len = static_cast<size_t>(script[i]) | (static_cast<size_t>(script[i + 1]) << 8);
            i += 2;
            if (i + len > script.size()) { oss << "[truncated push]"; break; }
            oss << HexStr(script.data() + i, len);
            i += len;
        } else if (op == OP_PUSHDATA4) {
            if (i + 4 > script.size()) { oss << "[truncated PUSHDATA4]"; break; }
            size_t len = static_cast<size_t>(script[i]) | (static_cast<size_t>(script[i + 1]) << 8) |
                         (static_cast<size_t>(script[i + 2]) << 16) | (static_cast<size_t>(script[i + 3]) << 24);
            i += 4;
            if (i + len > script.size()) { oss << "[truncated push]"; break; }
            oss << HexStr(script.data() + i, len);
            i += len;
        } else {
            oss << OpName(op);
        }
    }
    return oss.str();
}

inline std::string FormatStackItem(const std::vector<uint8_t>& item) {
    if (item.empty()) return "<empty>";
    std::ostringstream oss;
    oss << HexStr(item);
    if (item.size() <= 8) oss << " (" << DecodeScriptNum(item) << ")";
    return oss.str();
}

inline std::string DescribeOpAt(const std::vector<uint8_t>& script, size_t pos) {
    if (pos >= script.size()) return "<out of range>";
    uint8_t op = script[pos];
    size_t i = pos + 1;

    auto push_desc = [&](size_t len) -> std::string {
        if (i + len > script.size()) return "PUSH " + std::to_string(len) + " bytes [truncated]";
        std::ostringstream oss;
        oss << "PUSH " << len << (len == 1 ? " byte: " : " bytes: ") << HexStr(script.data() + i, len);
        return oss.str();
    };

    if (op >= 0x01 && op <= 0x4b) {
        return push_desc(op);
    } else if (op == OP_PUSHDATA1) {
        if (i >= script.size()) return "OP_PUSHDATA1 [truncated]";
        size_t len = script[i]; i += 1;
        return push_desc(len);
    } else if (op == OP_PUSHDATA2) {
        if (i + 2 > script.size()) return "OP_PUSHDATA2 [truncated]";
        size_t len = static_cast<size_t>(script[i]) | (static_cast<size_t>(script[i + 1]) << 8);
        i += 2;
        return push_desc(len);
    } else if (op == OP_PUSHDATA4) {
        if (i + 4 > script.size()) return "OP_PUSHDATA4 [truncated]";
        size_t len = static_cast<size_t>(script[i]) | (static_cast<size_t>(script[i + 1]) << 8) |
                     (static_cast<size_t>(script[i + 2]) << 16) | (static_cast<size_t>(script[i + 3]) << 24);
        i += 4;
        return push_desc(len);
    }
    return OpName(op);
}

} // namespace script_asm

namespace tx_builder {

inline void WriteLE16(std::vector<uint8_t>& out, uint16_t v) {
    out.push_back(static_cast<uint8_t>(v & 0xff));
    out.push_back(static_cast<uint8_t>((v >> 8) & 0xff));
}
inline void WriteLE32(std::vector<uint8_t>& out, uint32_t v) {
    for (int i = 0; i < 4; ++i) out.push_back(static_cast<uint8_t>((v >> (8 * i)) & 0xff));
}
inline void WriteLE64(std::vector<uint8_t>& out, uint64_t v) {
    for (int i = 0; i < 8; ++i) out.push_back(static_cast<uint8_t>((v >> (8 * i)) & 0xff));
}
inline void WriteCompactSize(std::vector<uint8_t>& out, uint64_t n) {
    if (n < 253) {
        out.push_back(static_cast<uint8_t>(n));
    } else if (n <= 0xffff) {
        out.push_back(253);
        WriteLE16(out, static_cast<uint16_t>(n));
    } else if (n <= 0xffffffffULL) {
        out.push_back(254);
        WriteLE32(out, static_cast<uint32_t>(n));
    } else {
        out.push_back(255);
        WriteLE64(out, n);
    }
}
inline void WriteVarBytes(std::vector<uint8_t>& out, const std::vector<uint8_t>& data) {
    WriteCompactSize(out, data.size());
    out.insert(out.end(), data.begin(), data.end());
}

struct TxIn {
    std::array<uint8_t, 32> prevout_hash{};   // internal byte order, i.e. what Txid::ToBytes() returns
    uint32_t prevout_index = 0;
    std::vector<uint8_t> script_sig;
    uint32_t sequence = 0xffffffffu;
    std::vector<std::vector<uint8_t>> witness; // stack items in push order (last = top)
};

struct TxOut {
    int64_t value = 0;
    std::vector<uint8_t> script_pubkey;
};

struct MutableTransaction {
    int32_t version = 2;
    std::vector<TxIn> vin;
    std::vector<TxOut> vout;
    uint32_t locktime = 0;

    bool HasWitness() const {
        for (const auto& in : vin) {
            if (!in.witness.empty()) return true;
        }
        return false;
    }

    std::vector<uint8_t> Serialize() const {
        std::vector<uint8_t> out;
        WriteLE32(out, static_cast<uint32_t>(version));

        const bool segwit = HasWitness();
        if (segwit) {
            out.push_back(0x00); // marker
            out.push_back(0x01); // flag
        }

        WriteCompactSize(out, vin.size());
        for (const auto& in : vin) {
            out.insert(out.end(), in.prevout_hash.begin(), in.prevout_hash.end());
            WriteLE32(out, in.prevout_index);
            WriteVarBytes(out, in.script_sig);
            WriteLE32(out, in.sequence);
        }

        WriteCompactSize(out, vout.size());
        for (const auto& o : vout) {
            WriteLE64(out, static_cast<uint64_t>(o.value));
            WriteVarBytes(out, o.script_pubkey);
        }

        if (segwit) {
            for (const auto& in : vin) {
                WriteCompactSize(out, in.witness.size());
                for (const auto& item : in.witness) WriteVarBytes(out, item);
            }
        }

        WriteLE32(out, locktime);
        return out;
    }
};

} // namespace tx_builder

namespace {

// ---------------------------------------------------------------------
// CLI options
// ---------------------------------------------------------------------

struct Options {
    std::string script_pubkey_asm;
    std::string script_pubkey_hex;
    std::string script_sig_asm;
    std::string script_sig_hex;
    std::vector<std::string> witness_hex;
    int64_t amount = 0;
    uint32_t sequence = 0xffffffffu;
    uint32_t locktime = 0;
    int32_t tx_version = 2;

    std::string raw_tx_hex;
    size_t input_index = 0;
    std::vector<std::string> prevouts;

    std::string flags_str = "ALL";
    bool step = false;
    bool no_color = false;
    bool help = false;
};

bool StartsWith(const std::string& s, const std::string& prefix) {
    return s.size() >= prefix.size() && s.compare(0, prefix.size(), prefix) == 0;
}

Options ParseArgs(int argc, char** argv) {
    Options o;
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];

        auto eat = [&](const std::string& key) -> std::optional<std::string> {
            if (a == key) {
                if (i + 1 >= argc) throw std::runtime_error(key + " requires a value");
                return std::string(argv[++i]);
            }
            std::string pref = key + "=";
            if (StartsWith(a, pref)) return a.substr(pref.size());
            return std::nullopt;
        };

        if (a == "--help" || a == "-h") { o.help = true; continue; }
        if (a == "--step" || a == "-s") { o.step = true; continue; }
        if (a == "--no-color") { o.no_color = true; continue; }

        if (auto v = eat("--script-pubkey"))     { o.script_pubkey_asm = *v; continue; }
        if (auto v = eat("--script-pubkey-hex")) { o.script_pubkey_hex = *v; continue; }
        if (auto v = eat("--script-sig"))        { o.script_sig_asm = *v; continue; }
        if (auto v = eat("--script-sig-hex"))    { o.script_sig_hex = *v; continue; }
        if (auto v = eat("--witness"))           { o.witness_hex.push_back(*v); continue; }
        if (auto v = eat("--amount"))            { o.amount = std::stoll(*v); continue; }
        if (auto v = eat("--sequence"))          { o.sequence = static_cast<uint32_t>(std::stoul(*v, nullptr, 0)); continue; }
        if (auto v = eat("--locktime"))          { o.locktime = static_cast<uint32_t>(std::stoul(*v, nullptr, 0)); continue; }
        if (auto v = eat("--tx-version"))        { o.tx_version = std::stoi(*v); continue; }
        if (auto v = eat("--raw-tx"))            { o.raw_tx_hex = *v; continue; }
        if (auto v = eat("--input"))             { o.input_index = static_cast<size_t>(std::stoul(*v)); continue; }
        if (auto v = eat("--prevout"))           { o.prevouts.push_back(*v); continue; }
        if (auto v = eat("--flags"))             { o.flags_str = *v; continue; }

        throw std::runtime_error("unknown argument: " + a);
    }
    return o;
}

btck::ScriptVerificationFlags ParseFlags(const std::string& s) {
    using F = btck::ScriptVerificationFlags;
    if (s == "ALL") return F::ALL;
    if (s == "NONE") return F::NONE;

    F result = F::NONE;
    std::istringstream iss(s);
    std::string tok;
    while (std::getline(iss, tok, ',')) {
        if (tok.empty()) continue;
        for (auto& c : tok) c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
        if (tok == "P2SH") result |= F::P2SH;
        else if (tok == "DERSIG") result |= F::DERSIG;
        else if (tok == "NULLDUMMY") result |= F::NULLDUMMY;
        else if (tok == "CHECKLOCKTIMEVERIFY" || tok == "CLTV") result |= F::CHECKLOCKTIMEVERIFY;
        else if (tok == "CHECKSEQUENCEVERIFY" || tok == "CSV") result |= F::CHECKSEQUENCEVERIFY;
        else if (tok == "WITNESS") result |= F::WITNESS;
        else if (tok == "TAPROOT") result |= F::TAPROOT;
        else if (tok == "ALL") result |= F::ALL;
        else throw std::runtime_error("unknown --flags entry: " + tok);
    }
    return result;
}

// ---------------------------------------------------------------------
// Tracer
// ---------------------------------------------------------------------

struct DisplayOptions {
    bool color = true;
    bool step = false;
};

class Tracer {
public:
    explicit Tracer(DisplayOptions opts) : m_opts(opts) {}

    void ScriptTrace(const btck::ScriptTraceState& t) {
        const bool is_final = (t.m_opcode == script_asm::OP_INVALIDOPCODE);

        if (m_pending_new_pass) {
            ++m_pass;
            if (t.m_sig_version != 0) m_saw_non_base_pass = true;
            PrintPassHeader(t);
            m_pending_new_pass = false;
        }
        ++m_global_step;

        if (is_final) {
            PrintFinalLine(t);
            m_pending_new_pass = true;
        } else {
            PrintOpcodeLine(t);
        }

        MaybePause();
    }

    // True once any pass ran with sigversion != BASE (i.e. a witness/tapscript
    // actually executed, as opposed to the mandatory-but-trivial scriptSig/
    // scriptPubKey BASE passes VerifyScript always performs first).
    bool SawNonBasePass() const { return m_saw_non_base_pass; }

private:
    DisplayOptions m_opts;
    bool m_quiet = false;
    int m_pass = 0;
    long m_global_step = 0;
    bool m_pending_new_pass = true;
    bool m_saw_non_base_pass = false;

    static const char* SigVersionName(uint8_t sv) {
        switch (sv) {
            case 0: return "BASE";
            case 1: return "WITNESS_V0";
            case 2: return "TAPROOT";
            case 3: return "TAPSCRIPT";
            default: return "UNKNOWN";
        }
    }

    std::string Color(const char* code, const std::string& s) const {
        if (!m_opts.color) return s;
        return std::string("\x1b[") + code + "m" + s + "\x1b[0m";
    }
    std::string Bold(const std::string& s)   const { return Color("1", s); }
    std::string Dim(const std::string& s)    const { return Color("2", s); }
    std::string Yellow(const std::string& s) const { return Color("33", s); }
    std::string Cyan(const std::string& s)   const { return Color("36", s); }
    std::string Green(const std::string& s)  const { return Color("32", s); }

    static std::string PadLeft(const std::string& s, size_t width) {
        return s.size() >= width ? s : std::string(width - s.size(), ' ') + s;
    }
    static std::string PadRight(const std::string& s, size_t width) {
        return s.size() >= width ? s : s + std::string(width - s.size(), ' ');
    }

    void PrintPassHeader(const btck::ScriptTraceState& t) {
        if (m_quiet) return;
        std::cout << "\n" << Bold("-- pass " + std::to_string(m_pass) + " ")
                  << Dim("[sigversion=") << Cyan(SigVersionName(t.m_sig_version)) << Dim("]")
                  << " " << std::string(48, '-') << "\n";
        std::cout << Dim("   script: ") << script_asm::DisassembleScript(t.m_script) << "\n";
        if (t.m_tapleaf_hash) {
            std::cout << Dim("   tapleaf hash: ")
                      << script_asm::HexStr(t.m_tapleaf_hash->data(), t.m_tapleaf_hash->size()) << "\n";
        }
    }

    void PrintOpcodeLine(const btck::ScriptTraceState& t) {
        if (m_quiet) return;
        std::string desc = script_asm::DescribeOpAt(t.m_script, t.m_opcode_pos);
        std::string shown = t.m_exec ? desc : ("(skipped) " + desc);
        std::string shown_padded = shown.size() < 26 ? PadRight(shown, 26) : shown;
        std::cout << Dim("[" + PadLeft(std::to_string(m_global_step), 4) + "] ")
                  << Dim("pos=" + PadLeft(std::to_string(t.m_opcode_pos), 3) + "  ")
                  << (t.m_exec ? Yellow(shown_padded) : Dim(shown_padded))
                  << Dim("  ops=" + std::to_string(t.m_op_count));
        if (t.m_codeseparator_pos != 0xFFFFFFFFu) {
            std::cout << Dim("  codesep@" + std::to_string(t.m_codeseparator_pos));
        }
        std::cout << "\n";
        PrintStack(t);
    }

    void PrintFinalLine(const btck::ScriptTraceState& t) {
        if (m_quiet) return;
        std::cout << Dim("[" + PadLeft(std::to_string(m_global_step), 4) + "] ")
                  << Green("-- EvalScript returned (final state) --") << "\n";
        PrintStack(t);
    }

    void PrintStack(const btck::ScriptTraceState& t) {
        std::cout << "         stack:    " << FormatStack(t.m_stack) << "\n";
        if (!t.m_altstack.empty()) {
            std::cout << "         altstack: " << FormatStack(t.m_altstack) << "\n";
        }
    }

    static std::string FormatStack(const std::vector<std::vector<unsigned char>>& stack) {
        if (stack.empty()) return "[]  (empty)";
        std::ostringstream oss;
        oss << "[ ";
        for (size_t i = 0; i < stack.size(); ++i) {
            oss << script_asm::FormatStackItem(stack[i]);
            if (i + 1 < stack.size()) oss << "  |  ";
        }
        oss << " ]  (top -> rightmost)";
        return oss.str();
    }

    void MaybePause() {
        if (!m_opts.step || m_quiet) return;
        std::cout << Dim("         [Enter]=step   c=continue   q=quiet-finish  ") << std::flush;
        std::string line;
        if (!std::getline(std::cin, line)) { m_opts.step = false; return; }
        if (line == "c" || line == "C") m_opts.step = false;
        else if (line == "q" || line == "Q") { m_opts.step = false; m_quiet = true; }
    }
};

// ---------------------------------------------------------------------
// misc helpers
// ---------------------------------------------------------------------

std::string Header(const std::string& s) { return "== " + s + " =="; }

std::string TxidDisplayHex(const std::array<std::byte, 32>& internal_order) {
    std::vector<uint8_t> reversed(32);
    for (size_t i = 0; i < 32; ++i) reversed[i] = static_cast<uint8_t>(internal_order[31 - i]);
    return script_asm::HexStr(reversed);
}

bool LooksLikeWitnessProgram(const std::vector<uint8_t>& script) {
    if (script.size() < 4 || script.size() > 42) return false;
    uint8_t v = script[0];
    bool version_ok = (v == script_asm::OP_0) || (v >= script_asm::OP_1 && v <= script_asm::OP_16);
    if (!version_ok) return false;
    return static_cast<size_t>(script[1]) == script.size() - 2;
}

void PrintUsage() {
    std::cout <<
"bitcoin script debugger\n"
"  Steps through Bitcoin Script execution using libbitcoinkernel's script-trace\n"
"  hooks. Requires the kernel to be built with -DENABLE_SCRIPT_TRACE=ON.\n"
"\n"
"SYNTHETIC MODE (test an arbitrary scriptPubKey/scriptSig/witness combo):\n"
"  --script-pubkey=<asm>        locking script, e.g. \"OP_DUP OP_HASH160 <hex> OP_EQUALVERIFY OP_CHECKSIG\"\n"
"  --script-pubkey-hex=<hex>    locking script as raw hex, instead of asm\n"
"  --script-sig=<asm>           unlocking script (asm), default empty\n"
"  --script-sig-hex=<hex>       unlocking script as raw hex\n"
"  --witness=<hex>              one witness stack item (repeatable, push order -- last = top)\n"
"  --amount=<sats>              value of the coin being spent (default 0)\n"
"  --sequence=<n>               nSequence of the spending input (default 0xffffffff; accepts 0x.. hex)\n"
"  --locktime=<n>               nLockTime of the spending tx (default 0)\n"
"  --tx-version=<n>             version of the spending tx (default 2)\n"
"\n"
"REAL-TX MODE (debug an actual, fully-formed transaction):\n"
"  --raw-tx=<hex>                the spending transaction (already has scriptSig/witness set)\n"
"  --input=<n>                   which input to debug (default 0)\n"
"  --prevout=<sats>:<scriptHex>  prevout for one input; repeat once per input, in tx order\n"
"\n"
"ASM TOKENS: OP_NAMES, decimal numbers (minimally encoded), 0x<hex> literal data pushes,\n"
"            and 'quoted' / \"quoted\" ASCII literals.\n"
"\n"
"COMMON:\n"
"  --flags=<list>     comma list from P2SH,DERSIG,NULLDUMMY,CHECKLOCKTIMEVERIFY,\n"
"                      CHECKSEQUENCEVERIFY,WITNESS,TAPROOT, or ALL / NONE (default ALL)\n"
"  --step              pause after each traced opcode (Enter=step, c=continue, q=quiet-finish)\n"
"  --no-color          disable ANSI colors\n"
"  --help              show this message\n";
}

void PrintResult(bool ok, btck::ScriptVerifyStatus status) {
    using S = btck::ScriptVerifyStatus;
    std::cout << Header("result") << "\n";
    if (status == S::ERROR_INVALID_FLAGS_COMBINATION) {
        std::cout << "  status: ERROR_INVALID_FLAGS_COMBINATION\n"
                     "  (the requested --flags combination isn't valid -- e.g. TAPROOT without WITNESS)\n";
        return;
    }
    if (status == S::ERROR_SPENT_OUTPUTS_REQUIRED) {
        std::cout << "  status: ERROR_SPENT_OUTPUTS_REQUIRED\n"
                     "  (the active flags need spent-output data this run didn't supply)\n";
        return;
    }
    if (ok) {
        std::cout << "  PASS -- script verification succeeded\n";
    } else {
        std::cout << "  FAIL -- script verification failed\n"
                     "  (the kernel API only reports pass/fail, not a specific error code --\n"
                     "   scroll back through the trace above to see the stack at the opcode\n"
                     "   where things diverged from what you expected)\n";
    }
}

} // namespace

int main(int argc, char** argv) {
    Options o;
    try {
        o = ParseArgs(argc, argv);
    } catch (const std::exception& e) {
        std::cerr << "argument error: " << e.what() << "\n\n";
        PrintUsage();
        return 2;
    }

    if (o.help) { PrintUsage(); return 0; }

    DisplayOptions dopts;
    dopts.step = o.step;
    dopts.color = !o.no_color && isatty(STDOUT_FILENO);

    btck::logging_disable();

    try {
        std::vector<uint8_t> spend_tx_raw;
        std::vector<std::vector<uint8_t>> prevout_scripts;
        std::vector<int64_t> prevout_amounts;
        size_t input_index = 0;

        if (!o.raw_tx_hex.empty()) {
            input_index = o.input_index;
            spend_tx_raw = script_asm::ParseHexLenient(o.raw_tx_hex);

            if (o.prevouts.empty()) {
                throw std::runtime_error(
                    "--raw-tx requires one --prevout=<sats>:<scriptHex> per input, in tx order");
            }
            for (const auto& pv : o.prevouts) {
                auto colon = pv.find(':');
                if (colon == std::string::npos) {
                    throw std::runtime_error("--prevout must look like <sats>:<scriptHex>, got: " + pv);
                }
                int64_t amt = std::stoll(pv.substr(0, colon));
                auto script = script_asm::ParseHexLenient(pv.substr(colon + 1));
                prevout_amounts.push_back(amt);
                prevout_scripts.push_back(std::move(script));
            }
        } else {
            if (o.script_pubkey_asm.empty() && o.script_pubkey_hex.empty()) {
                throw std::runtime_error(
                    "must supply --script-pubkey=<asm>, --script-pubkey-hex=<hex>, or use --raw-tx mode");
            }
            if (!o.script_pubkey_asm.empty() && !o.script_pubkey_hex.empty()) {
                throw std::runtime_error("supply only one of --script-pubkey / --script-pubkey-hex");
            }
            if (!o.script_sig_asm.empty() && !o.script_sig_hex.empty()) {
                throw std::runtime_error("supply only one of --script-sig / --script-sig-hex");
            }

            std::vector<uint8_t> script_pubkey = !o.script_pubkey_hex.empty()
                ? script_asm::ParseHexLenient(o.script_pubkey_hex)
                : script_asm::AssembleScript(o.script_pubkey_asm);

            std::vector<uint8_t> script_sig = !o.script_sig_hex.empty()
                ? script_asm::ParseHexLenient(o.script_sig_hex)
                : (o.script_sig_asm.empty() ? std::vector<uint8_t>{} : script_asm::AssembleScript(o.script_sig_asm));

            std::vector<std::vector<uint8_t>> witness;
            witness.reserve(o.witness_hex.size());
            for (const auto& w : o.witness_hex) witness.push_back(script_asm::ParseHexLenient(w));

            tx_builder::MutableTransaction credit;
            credit.version = 1;
            credit.locktime = 0;
            {
                tx_builder::TxIn cin;
                cin.prevout_hash.fill(0);
                cin.prevout_index = 0xffffffffu;
                cin.script_sig = {0x00, 0x00};
                cin.sequence = 0xffffffffu;
                credit.vin.push_back(std::move(cin));
            }
            {
                tx_builder::TxOut cout_;
                cout_.value = o.amount;
                cout_.script_pubkey = script_pubkey;
                credit.vout.push_back(std::move(cout_));
            }

            auto credit_raw = credit.Serialize();
            btck::Transaction credit_tx{std::as_bytes(std::span(credit_raw))};
            auto txid_bytes = credit_tx.Txid().ToBytes();

            tx_builder::MutableTransaction spend;
            spend.version = o.tx_version;
            spend.locktime = o.locktime;
            {
                tx_builder::TxIn sin;
                for (size_t i = 0; i < 32; ++i) sin.prevout_hash[i] = static_cast<uint8_t>(txid_bytes[i]);
                sin.prevout_index = 0;
                sin.script_sig = script_sig;
                sin.sequence = o.sequence;
                sin.witness = witness;
                spend.vin.push_back(std::move(sin));
            }
            {
                tx_builder::TxOut sout;
                sout.value = o.amount;
                spend.vout.push_back(std::move(sout));
            }

            spend_tx_raw = spend.Serialize();
            prevout_scripts.push_back(script_pubkey);
            prevout_amounts.push_back(o.amount);
            input_index = 0;
        }

        btck::Transaction tx_to{std::as_bytes(std::span(spend_tx_raw))};

        if (tx_to.CountInputs() != prevout_scripts.size()) {
            throw std::runtime_error(
                "number of --prevout entries (" + std::to_string(prevout_scripts.size()) +
                ") does not match the spending transaction's input count (" +
                std::to_string(tx_to.CountInputs()) + ")");
        }
        if (input_index >= tx_to.CountInputs()) {
            throw std::runtime_error("--input is out of range for the spending transaction");
        }

        std::vector<btck::ScriptPubkey> spk_storage;
        spk_storage.reserve(prevout_scripts.size());
        for (const auto& s : prevout_scripts) spk_storage.emplace_back(std::as_bytes(std::span(s)));

        std::vector<btck::TransactionOutput> spent_outputs;
        spent_outputs.reserve(prevout_scripts.size());
        for (size_t i = 0; i < prevout_scripts.size(); ++i) {
            spent_outputs.emplace_back(spk_storage[i], prevout_amounts[i]);
        }

        btck::PrecomputedTransactionData txdata{tx_to, spent_outputs};
        auto flags = ParseFlags(o.flags_str);

        std::cout << Header("bitcoin script debugger") << "\n";
        std::cout << "  input:  #" << input_index << "   amount=" << prevout_amounts[input_index] << " sat\n";
        std::cout << "  flags:  " << o.flags_str << "\n";
        std::cout << "  spends:\n";
        for (size_t i = 0; i < tx_to.CountInputs(); ++i) {
            auto op = tx_to.GetInput(i).OutPoint();
            std::cout << "    #" << i << (i == input_index ? " (debugging this one)" : "") << "  "
                      << TxidDisplayHex(op.Txid().ToBytes()) << ":" << op.index() << "\n";
        }

        auto tracer = std::make_unique<Tracer>(dopts);
        Tracer* tracer_raw = tracer.get();
        btck::ScriptTraceSetCallback(std::move(tracer));

        btck::ScriptVerifyStatus status = btck::ScriptVerifyStatus::OK;
        bool ok = spk_storage[input_index].Verify(
            prevout_amounts[input_index], tx_to, &txdata,
            static_cast<unsigned int>(input_index), flags, status);

        bool saw_non_base = tracer_raw->SawNonBasePass(); // query before unregister destroys it
        btck::ScriptTraceUnsetCallback();

        std::cout << "\n";
        PrintResult(ok, status);

        if (!ok && !saw_non_base && LooksLikeWitnessProgram(prevout_scripts[input_index])) {
            std::cout << "\n  hint: this scriptPubKey looks like a witness program, but no WITNESS_V0/\n"
                         "        TAPROOT/TAPSCRIPT pass ever ran -- verification most likely failed the\n"
                         "        witness-program version/hash check *before* your actual witness script\n"
                         "        got a chance to execute. Double check --prevout above really is the\n"
                         "        scriptPubKey of the outpoint printed under \"spends:\".\n";
        }

        return ok ? 0 : 1;

    } catch (const std::exception& e) {
        btck::ScriptTraceUnsetCallback();
        std::cerr << "error: " << e.what() << "\n";
        return 2;
    }
}
