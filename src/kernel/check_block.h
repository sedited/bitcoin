// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef KERNEL_CHECK_BLOCK_H
#define KERNEL_CHECK_BLOCK_H

#include <primitives/block.h>

#include <optional>

class BlockValidationState;
class CBlockHeader;
namespace Consensus {
    struct Params;
} // namespace Consensus

class CheckedBlock {
    CBlock m_block;

    explicit CheckedBlock(CBlock block) : m_block(std::move(block)) {}
    friend std::optional<CheckedBlock> CheckBlockSafe(CBlock, BlockValidationState&, const Consensus::Params&);

public:
    const CBlock& block() const { return m_block; }
};

bool CheckBlockHeader(const CBlockHeader& block, BlockValidationState& state, const Consensus::Params& consensusParams, bool fCheckPOW = true);
bool CheckMerkleRoot(const CBlock& block, BlockValidationState& state);
bool CheckBlock(const CBlock& block, BlockValidationState& state, const Consensus::Params& consensusParams, bool fCheckPOW = true, bool fCheckMerkleRoot = true);
std::optional<CheckedBlock> CheckBlockSafe(CBlock block, BlockValidationState& state, const Consensus::Params& consensusParams);

#endif // KERNEL_CHECK_BLOCK_H
