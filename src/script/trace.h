// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_SCRIPT_TRACE_H
#define BITCOIN_SCRIPT_TRACE_H

#include <script/script.h>

#include <functional>
#include <span>
#include <vector>

using TraceScriptCallback = std::function<void(std::span<const std::vector<unsigned char>>, const CScript&, uint32_t, std::span<const std::vector<unsigned char>>, bool, uint8_t, int, uint8_t, const unsigned char*, uint32_t)>;

void TraceScript(std::span<const std::vector<unsigned char>> stack, const CScript& script, uint32_t opcode_pos, std::span<const std::vector<unsigned char>> altstack, bool fExec, uint8_t opcode, int nOpCount, uint8_t sigversion, const unsigned char* tapleaf_hash, uint32_t codeseparator_pos);

void RegisterTraceScriptCallback(TraceScriptCallback func);

#ifdef ENABLE_SCRIPT_TRACE
#define TRACE_SCRIPT(stack, script, opcode_pos, altstack, fExec, opcode, nOpCount, sigversion, tapleaf_hash, codeseparator_pos) \
    TraceScript(stack, script, opcode_pos, altstack, fExec, opcode, nOpCount, sigversion, tapleaf_hash, codeseparator_pos);

struct ScriptTraceFinalGuard
{
    std::vector<std::vector<unsigned char>>& m_stack;
    const CScript& m_script;
    uint32_t& m_opcode_pos;
    std::vector<std::vector<unsigned char>>& m_altstack;
    bool m_fExec;
    uint8_t m_opcode;
    int& m_nOpCount;
    uint8_t m_sigversion;
    const unsigned char* m_tapleaf_hash;
    uint32_t& m_codeseparator_pos;

    ScriptTraceFinalGuard(std::vector<std::vector<unsigned char>>& stack, const CScript& script, uint32_t& opcode_pos,
                          std::vector<std::vector<unsigned char>>& altstack, bool fExec, uint8_t opcode,
                          int& nOpCount, uint8_t sigversion, const unsigned char* tapleaf_hash, uint32_t& codeseparator_pos) :
        m_stack{stack},
        m_script{script},
        m_opcode_pos{opcode_pos},
        m_altstack{altstack},
        m_fExec{fExec},
        m_opcode{opcode},
        m_nOpCount{nOpCount},
        m_sigversion{sigversion},
        m_tapleaf_hash{tapleaf_hash},
        m_codeseparator_pos{codeseparator_pos} {}

    ~ScriptTraceFinalGuard()
    {
        TraceScript(m_stack, m_script, m_opcode_pos, m_altstack,
            m_fExec, m_opcode, m_nOpCount, m_sigversion, m_tapleaf_hash, m_codeseparator_pos);
    }
};

#define TRACE_SCRIPT_FINAL_GUARD(stack, script, opcode_pos, altstack, fExec, opcode, nOpCount, sigversion, tapleaf_hash, codeseparator_pos) \
    ScriptTraceFinalGuard script_trace_final_guard{stack, script, opcode_pos, altstack, fExec, opcode, nOpCount, sigversion, tapleaf_hash, codeseparator_pos};

#else
#define TRACE_SCRIPT(stack, script, opcode_pos, altstack, fExec, opcode, nOpCount, sigversion, tapleaf_hash, codeseparator_pos)
#define TRACE_SCRIPT_FINAL_GUARD(stack, script, opcode_pos, altstack, fExec, opcode, nOpCount, sigversion, tapleaf_hash, codeseparator_pos)
#endif // ENABLE_SCRIPT_TRACE

#endif // BITCOIN_SCRIPT_TRACE_H
