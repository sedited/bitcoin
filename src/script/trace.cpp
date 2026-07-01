// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <script/trace.h>

#include <mutex>
#include <span>
#include <vector>

static std::mutex g_script_trace_mutex;
static TraceScriptCallback g_script_trace_callback{nullptr};

void TraceScript(std::span<const std::vector<unsigned char>> stack, const CScript& script, uint32_t opcode_pos, std::span<const std::vector<unsigned char>> altstack, bool fExec, uint8_t opcode, int nOpCount, uint8_t sigversion, const unsigned char* tapleaf_hash, uint32_t codeseparator_pos)
{
    std::lock_guard<std::mutex> lock(g_script_trace_mutex);
    if (g_script_trace_callback)
        g_script_trace_callback(stack, script, opcode_pos, altstack, fExec, opcode, nOpCount, sigversion, tapleaf_hash, codeseparator_pos);
}

void RegisterTraceScriptCallback(TraceScriptCallback func)
{
    std::lock_guard<std::mutex> lock(g_script_trace_mutex);
    g_script_trace_callback = func;
}
