#include <chain.h>
#include <kernel/blocktreestorage.h>
#include <node/blockstorage.h>
#include <util/fs.h>
#include <pow.h>

#include <cstdint>

using kernel::BlockTreeStore;
using kernel::CBlockFileInfo;

static std::vector<CBlockFileInfo> CreateUniqueFileInfo(int32_t count)
{
    std::vector<CBlockFileInfo> infos;
    kernel::CBlockFileInfo info;
    info.nBlocks = count;
    info.nSize = count + 1;
    info.nUndoSize = count + 2;
    info.nHeightFirst = count + 3;
    info.nHeightLast = count + 4;
    info.nTimeFirst = count + 5;
    info.nTimeLast = count + 6;
    infos.emplace_back(info);
    return infos;
}

static auto BuildFileInfo(std::span<CBlockFileInfo> infos)
{
    std::vector<std::pair<int, const CBlockFileInfo*>> file_info;
    file_info.reserve(infos.size());
for (uint32_t i = 0; i < infos.size(); ++i) {
        file_info.emplace_back(i, &infos[i]);
    }
    return file_info;
}

static void BuildBlockIndex(node::BlockMap& block_map, const CChainParams& params)
{
    LOCK(cs_main);
    CBlockIndex* prev{nullptr};
    CBlockHeader header;
    header.nVersion = 1;
    header.hashPrevBlock = uint256{};
    header.hashMerkleRoot = uint256{};
    header.nTime = 0;
    header.nBits = 0x207fffff;
    while (!CheckProofOfWork(header.GetHash(), header.nBits, params.GetConsensus())) {
        ++header.nNonce;
    }
    header.nNonce = 0;
    const auto [it, inserted]{block_map.try_emplace(header.GetHash(), header)};
    assert(inserted); // unique nNonce/nTime/hashPrev => unique hash
    CBlockIndex* pindex{&it->second};
    pindex->phashBlock = &it->first;
    pindex->pprev = prev;
    pindex->nHeight = 0;
    pindex->nStatus = BLOCK_HAVE_DATA;
    pindex->nTx = 1;
    pindex->nFile = 0;
    pindex->nDataPos = 0;
    pindex->nUndoPos = 0;
    prev = pindex;
}

int main() {
    uint64_t i = 0;
    auto file_info = CreateUniqueFileInfo(0);
    auto file_info_pointers = BuildFileInfo(file_info);
    node::BlockMap block_map;
    std::vector<CBlockIndex*> blocks;
    auto params{CChainParams::RegTest()};
    BuildBlockIndex(block_map, *params);
    for (auto& entry : block_map) {
        blocks.push_back(&entry.second);
    }

    while (true) {
        BlockTreeStore store{fs::path{"/home/drgrid/testy_dir"}};
        ++i;
        if (i % 1'000 == 0) std::cout << "writer still alive: " << i << std::endl;
        if (i == 10'000'000) break;
        LOCK(cs_main);
        store.WriteBatchSync(file_info_pointers, blocks);
    }
}
