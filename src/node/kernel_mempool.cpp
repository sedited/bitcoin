// Copyright (c) 2025 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/kernel_mempool.h>

#include <primitives/transaction.h>
#include <txmempool.h>

namespace node {

void KernelMempool::removeRecursive(const CTransaction& tx)
{
    LOCK(m_mempool.cs);
    m_mempool.removeRecursive(tx, MemPoolRemovalReason::REORG);
}

} // namespace node
