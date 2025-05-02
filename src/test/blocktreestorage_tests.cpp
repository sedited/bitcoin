// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include <kernel/blocktreestorage.h>
#include <logging.h>
#include <node/blockstorage.h>
#include <pow.h>
#include <primitives/block.h>
#include <streams.h>
#include <test/util/setup_common.h>
#include <util/fs_helpers.h>
#include <util/hasher.h>

#include <boost/test/unit_test.hpp>

using kernel::BLOCK_FILES_FILE_MAGIC;
using kernel::BLOCK_FILES_FILE_NAME;
using kernel::BLOCK_FILES_FILE_VERSION;
using kernel::BlockTreeStore;
using kernel::BlockTreeStoreError;
using kernel::CBlockFileInfo;
using kernel::HEADER_FILE_DATA_START_POSITION;
using kernel::HEADER_FILE_MAGIC;
using kernel::HEADER_FILE_NAME;
using kernel::HEADER_FILE_VERSION;
using kernel::LOG_FILE_NAME;

BOOST_FIXTURE_TEST_SUITE(blocktreestorage_tests, BasicTestingSetup)

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

CBlockFileInfo CreateUniqueFileInfo(int32_t& seed)
{
    CBlockFileInfo info;
    info.nBlocks = seed;
    info.nSize = seed + 1;
    info.nUndoSize = seed + 2;
    info.nHeightFirst = seed + 3;
    info.nHeightLast = seed + 4;
    info.nTimeFirst = seed + 5;
    info.nTimeLast = seed + 6;
    seed += 1;
    return info;
}

void CheckBlockFileInfo(uint32_t file, CBlockFileInfo& file_info, BlockTreeStore& store)
{
    CBlockFileInfo retrieved_info;
    BOOST_CHECK(store.ReadBlockFileInfo(file, retrieved_info));
    BOOST_CHECK_EQUAL(file_info.nBlocks, retrieved_info.nBlocks);
    BOOST_CHECK_EQUAL(file_info.nSize, retrieved_info.nSize);
    BOOST_CHECK_EQUAL(file_info.nUndoSize, retrieved_info.nUndoSize);
    BOOST_CHECK_EQUAL(file_info.nHeightFirst, retrieved_info.nHeightFirst);
    BOOST_CHECK_EQUAL(file_info.nHeightLast, retrieved_info.nHeightLast);
    BOOST_CHECK_EQUAL(file_info.nTimeFirst, retrieved_info.nTimeFirst);
    BOOST_CHECK_EQUAL(file_info.nTimeLast, retrieved_info.nTimeLast);

    DataStream a, b;
    a << file_info;
    b << retrieved_info;
    BOOST_CHECK_EQUAL(a.str(), b.str());
}

void CheckBlockMap(const std::unordered_map<uint256, CBlockIndex, BlockHasher>& block_map, const std::vector<CBlockIndex*>& blocks)
{
    LOCK(::cs_main);
    BOOST_CHECK_EQUAL(block_map.size(), blocks.size());
    for (const auto& block : blocks) {
        auto hash{block->GetBlockHeader().GetHash()};
        auto it = block_map.find(hash);
        BOOST_CHECK(it != block_map.end());
        const auto& index = it->second;

        BOOST_CHECK_EQUAL(index.nHeight, block->nHeight);
        BOOST_CHECK_EQUAL(index.nStatus, block->nStatus);
        BOOST_CHECK_EQUAL(index.nTx, block->nTx);
        BOOST_CHECK_EQUAL(index.nFile, block->nFile);
        BOOST_CHECK_EQUAL(index.nDataPos, block->nDataPos);
        BOOST_CHECK_EQUAL(index.nUndoPos, block->nUndoPos);
        BOOST_CHECK_EQUAL(index.header_pos, block->header_pos);

        BOOST_CHECK_EQUAL(index.nVersion, block->nVersion);
        if (index.pprev == nullptr || block->pprev == nullptr) {
            BOOST_CHECK_EQUAL(index.pprev, block->pprev);
        } else {
            BOOST_CHECK_EQUAL(Assert(index.pprev)->GetBlockHeader().GetHash().ToString(), Assert(block->pprev)->GetBlockHeader().GetHash().ToString());
        }
        BOOST_CHECK_EQUAL(index.hashMerkleRoot.ToString(), block->hashMerkleRoot.ToString());
        BOOST_CHECK_EQUAL(index.nTime, block->nTime);
        BOOST_CHECK_EQUAL(index.nBits, block->nBits);
        BOOST_CHECK_EQUAL(index.nNonce, block->nNonce);

        DataStream a, b;
        a << CDiskBlockIndex{&it->second};
        b << CDiskBlockIndex{block};
        BOOST_CHECK_EQUAL(a.str(), b.str());
    }
}

BOOST_AUTO_TEST_CASE(HeaderFilesFormat)
{
    fs::path block_tree_store_dir{m_args.GetDataDirBase()};
    auto header_file_path{block_tree_store_dir / HEADER_FILE_NAME};
    auto block_files_file_path{block_tree_store_dir / BLOCK_FILES_FILE_NAME};
    BlockTreeStore store{block_tree_store_dir};

    AutoFile header_file{fsbridge::fopen(header_file_path, "rb")};
    uint32_t magic;
    header_file >> magic;
    BOOST_CHECK_EQUAL(magic, HEADER_FILE_MAGIC);
    uint32_t version;
    header_file >> version;
    BOOST_CHECK_EQUAL(version, HEADER_FILE_VERSION);
    header_file.seek(0, SEEK_END);
    long filesize = header_file.tell();
    BOOST_CHECK_EQUAL(filesize, kernel::HEADER_FILE_DATA_START_POSITION);
    (void)header_file.fclose();

    AutoFile block_files_file{fsbridge::fopen(block_files_file_path, "rb")};
    block_files_file >> magic;
    BOOST_CHECK_EQUAL(magic, BLOCK_FILES_FILE_MAGIC);
    block_files_file >> version;
    BOOST_CHECK_EQUAL(version, BLOCK_FILES_FILE_VERSION);
    block_files_file.seek(0, SEEK_END);
    filesize = block_files_file.tell();
    BOOST_CHECK_EQUAL(filesize, kernel::BLOCK_FILES_FILE_DATA_START_POSITION);
    (void)block_files_file.fclose();
}

BOOST_AUTO_TEST_CASE(BlockTreeStoreInvalidFiles)
{
    fs::path block_tree_store_dir{m_args.GetDataDirBase()};
    auto params{CreateChainParams(gArgs, ChainType::REGTEST)};

    auto header_file_path{block_tree_store_dir / HEADER_FILE_NAME};
    auto block_files_file_path{block_tree_store_dir / BLOCK_FILES_FILE_NAME};

    BlockTreeStore{block_tree_store_dir};
    fs::remove(header_file_path);
    BOOST_CHECK_THROW(BlockTreeStore{block_tree_store_dir}, BlockTreeStoreError);

    // If both files are gone, a new store may be created
    fs::remove(block_files_file_path);
    BlockTreeStore{block_tree_store_dir};
    BOOST_CHECK(fs::exists(header_file_path));
    BOOST_CHECK(fs::exists(block_files_file_path));

    fs::remove(block_files_file_path);
    BOOST_CHECK_THROW(BlockTreeStore{block_tree_store_dir}, BlockTreeStoreError);
    fs::remove(header_file_path);

    auto write_magic_and_version{[](const fs::path& path, uint32_t magic, uint32_t version) {
        AutoFile file{fsbridge::fopen(path, "rb+")};
        file.seek(0, SEEK_SET);
        file << magic;
        file << version;
        (void)file.fclose();
    }};
    BlockTreeStore{block_tree_store_dir};
    write_magic_and_version(header_file_path, 0, 0);
    BOOST_CHECK_THROW(BlockTreeStore{block_tree_store_dir}, BlockTreeStoreError);
    write_magic_and_version(header_file_path, HEADER_FILE_MAGIC, 0);
    BOOST_CHECK_THROW(BlockTreeStore{block_tree_store_dir}, BlockTreeStoreError);
    write_magic_and_version(header_file_path, HEADER_FILE_MAGIC, HEADER_FILE_VERSION);
    BlockTreeStore{block_tree_store_dir};
}

BOOST_AUTO_TEST_CASE(BlockTreeStoreIncompleteWrites)
{
    LOCK(::cs_main);
    fs::path block_tree_store_dir{m_args.GetDataDirBase()};
    auto header_file{block_tree_store_dir / HEADER_FILE_NAME};
    auto block_files_file{block_tree_store_dir / BLOCK_FILES_FILE_NAME};
    auto log_file{block_tree_store_dir / LOG_FILE_NAME};
    auto params{CreateChainParams(gArgs, ChainType::REGTEST)};
    auto store{std::make_unique<BlockTreeStore>(block_tree_store_dir)};

    std::unordered_map<uint256, CBlockIndex, BlockHasher> block_map;
    std::vector<std::pair<int, const CBlockFileInfo*>> fileinfo;

    // Write and read a CBlockFileInfo and a CBlockIndex
    CBlockFileInfo info{};
    info.nBlocks = 1;
    info.nSize = 2;
    info.nUndoSize = 3;
    info.nHeightFirst = 4;
    info.nHeightLast = 5;
    info.nTimeFirst = 6;
    info.nTimeLast = 7;
    fileinfo.emplace_back(0, &info);
    std::vector<CBlockIndex*> blockinfo;
    auto block_index = std::make_unique<CBlockIndex>(params->GenesisBlock());
    BOOST_CHECK_EQUAL(block_index->header_pos, CBlockIndex::UNSET_HEADER_POS);
    blockinfo.emplace_back(block_index.get());

    store->SetSimulateIncompleteLogWrite(true);

    // The log file should exist in an unclean state if we abort in the middle of writing to it
    BOOST_CHECK_THROW(store->WriteBatchSync(fileinfo, blockinfo), std::runtime_error);
    BOOST_CHECK(fs::exists(log_file));
    BOOST_CHECK(store->LoadBlockIndexGuts(
        params->GetConsensus(),
        [&](const uint256& hash) { return InsertBlockIndex(block_map, hash); },
        m_interrupt));
    BOOST_CHECK(block_map.empty());

    // The constructor should cleanup the log file and not apply any new state to the data files
    store = std::make_unique<BlockTreeStore>(block_tree_store_dir);
    BOOST_CHECK(!fs::exists(log_file));
    BOOST_CHECK(store->LoadBlockIndexGuts(
        params->GetConsensus(),
        [&](const uint256& hash) { return InsertBlockIndex(block_map, hash); },
        m_interrupt));
    BOOST_CHECK(block_map.empty());

    // Now simulate a crash in the middle of writing the data.
    store->SetSimulateIncompleteLogApply(true);
    BOOST_CHECK_THROW(store->WriteBatchSync(fileinfo, blockinfo), std::runtime_error);
    BOOST_CHECK(fs::exists(log_file));
    BOOST_CHECK(store->LoadBlockIndexGuts(
        params->GetConsensus(),
        [&](const uint256& hash) { return InsertBlockIndex(block_map, hash); },
        m_interrupt));
    BOOST_CHECK(block_map.empty());

    // The constructor should now cleanup the log file and apply new state to the data files
    store = std::make_unique<BlockTreeStore>(block_tree_store_dir);
    BOOST_CHECK(!fs::exists(log_file));
    BOOST_CHECK(store->LoadBlockIndexGuts(
        params->GetConsensus(),
        [&](const uint256& hash) { return InsertBlockIndex(block_map, hash); },
        m_interrupt));
    BOOST_CHECK_EQUAL(block_index->header_pos, HEADER_FILE_DATA_START_POSITION);
    CheckBlockMap(block_map, blockinfo);
    CheckBlockFileInfo(0, info, *store);

    // Simulate a write application failure and subsequent write application
    store->SetSimulateIncompleteLogApply(true);
    fileinfo.clear();
    info.nBlocks += 1;
    fileinfo.emplace_back(1, &info);
    BOOST_CHECK_THROW(store->WriteBatchSync(fileinfo, blockinfo), std::runtime_error);
    BOOST_CHECK(fs::exists(log_file));
    store->SetSimulateIncompleteLogApply(false);
    store->WriteBatchSync({}, {});
    BOOST_CHECK(!fs::exists(log_file));
    CheckBlockFileInfo(1, info, *store);
}

BOOST_AUTO_TEST_CASE(BlockTreeStoreFlags)
{
    auto store{std::make_unique<BlockTreeStore>(m_args.GetDataDirBase())};
    bool reindexing = true;
    store->ReadReindexing(reindexing);
    BOOST_CHECK(!reindexing);
    store->WriteReindexing(true);
    store->ReadReindexing(reindexing);
    BOOST_CHECK(reindexing);
    store->WriteReindexing(false);
    store->ReadReindexing(reindexing);
    BOOST_CHECK(!reindexing);

    int last_block;
    store->ReadLastBlockFile(last_block);
    BOOST_CHECK_EQUAL(last_block, 0);

    bool pruned = false;
    store->ReadPruned(pruned);
    BOOST_CHECK(!pruned);
    store->WritePruned(true);
    store->ReadPruned(pruned);
    BOOST_CHECK(pruned);
    store->WritePruned(false);
    store->ReadPruned(pruned);
    BOOST_CHECK(!pruned);

    // Re-create the store and check that the data was persisted
    store->WritePruned(true);
    store->WriteReindexing(true);
    store = std::make_unique<BlockTreeStore>(m_args.GetDataDirBase());
    store->ReadPruned(pruned);
    store->ReadReindexing(reindexing);
    BOOST_CHECK(pruned);
    BOOST_CHECK(reindexing);
}

CBlockIndex* AddTestBlockIndex(node::BlockMap& test_block_map, const CBlockHeader& header, CBlockIndex* prev)
{
    LOCK(::cs_main);
    const auto [mi, inserted]{test_block_map.try_emplace(header.GetHash(), header)};
    CBlockIndex* pindex{&mi->second};
    pindex->phashBlock = &mi->first;
    pindex->pprev = prev;
    pindex->nHeight = prev ? prev->nHeight + 1 : 0;
    pindex->nStatus = prev ? prev->nStatus ^ BLOCK_FAILED_VALID : 0;
    pindex->nTx = prev ? prev->nTx + 3 : 0;
    pindex->nFile = prev ? prev->nFile + 4 : 0;
    pindex->nDataPos = prev ? prev->nDataPos + 100 : 0;
    pindex->nUndoPos = prev ? prev->nUndoPos + 101 : 0;
    return pindex;
}

std::vector<CBlockIndex*> BlockMapToVector(node::BlockMap& test_block_map)
{
    std::vector<CBlockIndex*> blocks;
    blocks.reserve(test_block_map.size());
    for (auto& [hash, index] : test_block_map) {
        blocks.push_back(&index);
    }
    return blocks;
}

void WriteAndCheckBlockIndex(BlockTreeStore& store, node::BlockMap& test_block_map,
        const std::vector<std::pair<int, const CBlockFileInfo*>>& fileinfo, util::SignalInterrupt& interrupt,
        const CChainParams& params)
{
    LOCK(::cs_main);
    const auto blocks{BlockMapToVector(test_block_map)};
    store.WriteBatchSync(fileinfo, blocks);
    node::BlockMap block_map;
    BOOST_CHECK(store.LoadBlockIndexGuts(
        params.GetConsensus(),
        [&](const uint256& hash) { return InsertBlockIndex(block_map, hash); },
        interrupt));
    CheckBlockMap(block_map, blocks);
}

BOOST_AUTO_TEST_CASE(BlockTreeStoreRW)
{
    LOCK(::cs_main);
    fs::path block_tree_store_dir{m_args.GetDataDirBase()};
    auto header_file{block_tree_store_dir / HEADER_FILE_NAME};
    auto block_files_file{block_tree_store_dir / BLOCK_FILES_FILE_NAME};
    auto params{CreateChainParams(gArgs, ChainType::REGTEST)};
    auto store_ptr{std::make_unique<BlockTreeStore>(block_tree_store_dir)};
    auto& store = *store_ptr;
    int32_t last_block{0};

    std::vector<std::pair<int, const CBlockFileInfo*>> fileinfo;
    node::BlockMap test_map;

    // Check that the store is empty
    BOOST_CHECK(store.LoadBlockIndexGuts(
        params->GetConsensus(),
        [&](const uint256& hash) { return InsertBlockIndex(test_map, hash); },
        m_interrupt));
    BOOST_CHECK(test_map.empty());
    CBlockFileInfo info;
    BOOST_CHECK(!store.ReadBlockFileInfo(0, info));

    // Write and read a CBlockFileInfo and a CBlockIndex
    int32_t counter = 0;
    info = CreateUniqueFileInfo(counter);
    fileinfo.emplace_back(0, &info);
    CBlockIndex* block_index = AddTestBlockIndex(test_map, params->GenesisBlock(), /*prev=*/nullptr);
    BOOST_CHECK_EQUAL(block_index->header_pos, CBlockIndex::UNSET_HEADER_POS);
    WriteAndCheckBlockIndex(store, test_map, fileinfo, m_interrupt, *params);
    BOOST_CHECK_EQUAL(block_index->header_pos, HEADER_FILE_DATA_START_POSITION);
    CheckBlockFileInfo(0, info, store);
    store.ReadLastBlockFile(last_block);
    BOOST_CHECK_EQUAL(last_block, 0);

    // Write another CBlockFileInfo and update the CBlockIndex
    info = CreateUniqueFileInfo(counter);
    CBlockFileInfo info_two = CreateUniqueFileInfo(counter);
    fileinfo.emplace_back(1, &info_two);
    block_index->nStatus = 120;
    block_index->nFile = 1;
    WriteAndCheckBlockIndex(store, test_map, fileinfo, m_interrupt, *params);
    CheckBlockFileInfo(0, info, store);
    store.ReadLastBlockFile(last_block);
    BOOST_CHECK_EQUAL(last_block, 1);

    // Update the new CBlockFileInfo and the CBlockIndex and check that the file sizes are unchanged
    block_index->nStatus = 99;
    block_index->nFile = 50;
    info_two.nBlocks = 2;
    info_two.nSize = 3;
    info_two.nUndoSize = 4;
    info_two.nHeightFirst = 5;
    info_two.nHeightLast = 6;
    info_two.nTimeFirst = 7;
    info_two.nTimeLast = 8;
    auto header_file_size{fs::file_size(header_file)};
    auto block_files_file_size{fs::file_size(block_files_file)};
    WriteAndCheckBlockIndex(store, test_map, fileinfo, m_interrupt, *params);
    CheckBlockFileInfo(0, info, store);
    CheckBlockFileInfo(1, info_two, store);
    BOOST_CHECK_EQUAL(header_file_size, fs::file_size(header_file));
    BOOST_CHECK_EQUAL(block_files_file_size, fs::file_size(block_files_file));

    // Add more CBlockIndex entries to the store
    BOOST_CHECK_EQUAL(test_map.size(), 1);
    for (uint8_t i = 0; i < 10; ++i) {
        CBlockHeader header;
        header.hashPrevBlock = block_index->GetBlockHash();
        header.nBits = params->GenesisBlock().nBits;
        header.nTime = block_index->nTime + 1;
        header.hashMerkleRoot = uint256{i};
        while (!CheckProofOfWork(header.GetHash(), header.nBits, params->GetConsensus())) {
            ++header.nNonce;
        }
        block_index = AddTestBlockIndex(test_map, header, /*prev=*/block_index);
        // Add a couple of forks too
        if (i % 3 == 0) {
            block_index = block_index->pprev;
        }
    }
    BOOST_CHECK_EQUAL(test_map.size(), 11);
    WriteAndCheckBlockIndex(store, test_map, fileinfo, m_interrupt, *params);
    CheckBlockFileInfo(0, info, store);

    // Read and write back the same data and check that the file sizes are unchanged
    header_file_size = fs::file_size(header_file);
    node::BlockMap loaded_block_map;
    BOOST_CHECK(store.LoadBlockIndexGuts(
        params->GetConsensus(),
        [&](const uint256& hash) { return InsertBlockIndex(loaded_block_map, hash); },
        m_interrupt));
    WriteAndCheckBlockIndex(store, loaded_block_map, fileinfo, m_interrupt, *params);
    BOOST_CHECK_EQUAL(header_file_size, fs::file_size(header_file));
    store.ReadLastBlockFile(last_block);
    BOOST_CHECK_EQUAL(last_block, 1);

    // Writing an invalid CBlockIndex (with invalid PoW) should fail to load
    test_map.begin()->second.nBits = 0;
    loaded_block_map.clear();
    store.WriteBatchSync(fileinfo, BlockMapToVector(test_map));
    BOOST_CHECK(!store.LoadBlockIndexGuts(
        params->GetConsensus(),
        [&](const uint256& hash) { return InsertBlockIndex(loaded_block_map, hash); },
        m_interrupt));
}

BOOST_AUTO_TEST_SUITE_END()
