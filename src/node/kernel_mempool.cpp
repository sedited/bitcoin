// Copyright (c) 2025 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/kernel_mempool.h>

#include <primitives/transaction.h>
#include <txmempool.h>

#include <cstddef>
#include <cstdint>

class CCoinsViewCache;

namespace node {

void KernelMempool::removeRecursive(const CTransaction& tx)
{
    LOCK(m_mempool.cs);
    m_mempool.removeRecursive(tx, MemPoolRemovalReason::REORG);
}

void KernelMempool::removeForBlock(const CBlock& block, unsigned int block_height)
{
    LOCK(m_mempool.cs);
    m_mempool.removeForBlock(block.vtx, block_height);
}

size_t KernelMempool::measureExternalDynamicMemoryUsage()
{
    return m_mempool.DynamicMemoryUsage();
}

void KernelMempool::addTransactionsUpdated(uint32_t n)
{
    m_mempool.AddTransactionsUpdated(n);
}

void KernelMempool::check(const CCoinsViewCache& active_coins_tip, int64_t spendheight)
{
    LOCK(::cs_main);
    m_mempool.check(active_coins_tip, spendheight);
}

} // namespace node
