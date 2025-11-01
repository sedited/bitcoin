// Copyright (c) 2025 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NODE_KERNEL_MEMPOOL_H
#define BITCOIN_NODE_KERNEL_MEMPOOL_H

#include <kernel/mempool_interface.h>

#include <cstddef>
#include <cstdint>

class CBlock;
class CCoinsViewCache;
class CTransaction;
class CTxMemPool;

namespace node {

class KernelMempool: public kernel::Mempool
{
public:
    KernelMempool(CTxMemPool& mempool)
        : m_mempool{mempool} {}

    void removeRecursive(const CTransaction& tx) override;
    void removeForBlock(const CBlock& block, unsigned int nBlockHeight) override;
    size_t measureExternalDynamicMemoryUsage() override;
    void addTransactionsUpdated(uint32_t n) override;
    void check(const CCoinsViewCache& active_coins_tip, int64_t spendheight) override;

private:
    CTxMemPool& m_mempool;
};

} // namespace node

#endif // BITCOIN_NODE_KERNEL_MEMPOOL_H
