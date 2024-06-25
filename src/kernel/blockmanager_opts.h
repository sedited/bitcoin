// Copyright (c) 2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_KERNEL_BLOCKMANAGER_OPTS_H
#define BITCOIN_KERNEL_BLOCKMANAGER_OPTS_H

#include <dbwrapper.h>
#include <kernel/notifications_interface.h>
#include <util/fs.h>

#include <cstdint>

class CChainParams;

namespace kernel {

static constexpr bool DEFAULT_XOR_BLOCKSDIR{true};

/** The maximum size of a blk?????.dat file (since 0.8) */
static const uint64_t MAX_BLOCKFILE_SIZE = 0x8000000; // 128 MiB

/**
 * An options struct for `BlockManager`, more ergonomically referred to as
 * `BlockManager::Options` due to the using-declaration in `BlockManager`.
 */
struct BlockManagerOpts {
    const CChainParams& chainparams;
    bool use_xor{DEFAULT_XOR_BLOCKSDIR};
    uint64_t prune_target{0};
    bool fast_prune{false};
    const fs::path blocks_dir;
    Notifications& notifications;
    DBParams block_tree_db_params;
    uint64_t max_blockfile_size{MAX_BLOCKFILE_SIZE};
};

} // namespace kernel

#endif // BITCOIN_KERNEL_BLOCKMANAGER_OPTS_H
