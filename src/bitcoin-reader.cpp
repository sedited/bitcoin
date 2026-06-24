#include <kernel/blocktreestorage.h>
#include <node/blockstorage.h>
#include <util/fs.h>
#include <util/signalinterrupt.h>

#include <cassert>
#include <cstdint>
#include <iostream>

using kernel::BlockTreeStore;

CBlockIndex* InsertBlockIndex(std::unordered_map<uint256, CBlockIndex, BlockHasher>& block_map, const uint256& hash)
{
    if (hash.IsNull()) {
        return nullptr;
    }
    const auto [mi, inserted]{block_map.try_emplace(hash)};
    CBlockIndex* pindex = &(*mi).second;
    if (inserted) {
        pindex->phashBlock = &((*mi).first);
    }
    return pindex;
}

int main() {
    uint64_t i = 0;
    node::BlockMap block_map;
    kernel::CBlockFileInfo info;
    int32_t last_block_file = 0;
    util::SignalInterrupt interrupt;
    auto params{CChainParams::RegTest()};

    while (true) {
        BlockTreeStore store{fs::path{"/home/drgrid/testy_dir"}, BlockTreeStore::OpenMode::READ};
        ++i;
        if (i % 10'000 == 0) std::cout << "reader still alive: " << i << std::endl;
        if (i == 10'000'000) break;
        assert(store.ReadBlockFileInfo(0, info));

        store.ReadLastBlockFile(last_block_file);
        assert(last_block_file == 0);

        assert(store.LoadBlockIndexGuts(
            params->GetConsensus(),
            [&](const uint256& hash) { return InsertBlockIndex(block_map, hash); },
            interrupt));
    }
}
