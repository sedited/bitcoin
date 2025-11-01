// Copyright (c) 2025 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_KERNEL_MEMPOOL_INTERFACE_H
#define BITCOIN_KERNEL_MEMPOOL_INTERFACE_H

#include <cstddef>
#include <cstdint>

class CBlock;
class CTransaction;

namespace kernel {

/**
 * A base class defining functions for notifying about certain kernel
 * events.
 */
class Mempool
{
public:
    virtual ~Mempool() = default;

    virtual void removeRecursive(const CTransaction& tx) {}
    virtual void removeForBlock(const CBlock& block, unsigned int block_height) {}
    virtual size_t measureExternalDynamicMemoryUsage() { return 0; }
    virtual void addTransactionsUpdated(uint32_t n) {}
};

} // namespace kernel

#endif // BITCOIN_KERNEL_MEMPOOL_INTERFACE_H
