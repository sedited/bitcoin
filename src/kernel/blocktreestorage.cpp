// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <kernel/blocktreestorage.h>

#include <chain.h>
#include <crc32c/include/crc32c/crc32c.h>
#include <crypto/common.h>
#include <kernel/cs_main.h>
#include <logging.h>
#include <pow.h>
#include <serialize.h>
#include <span.h>
#include <streams.h>
#include <sync.h>
#include <tinyformat.h>
#include <uint256.h>
#include <util/check.h>
#include <util/fs.h>
#include <util/fs_helpers.h>
#include <util/signalinterrupt.h>
#include <util/time.h>

#include <array>
#include <cstddef>
#include <cstdio>
#include <ios>
#include <span>
#include <system_error>
#include <type_traits>
#include <utility>

namespace kernel {

static constexpr uint8_t BLOCK_FILE_INFO_WRAPPER_SIZE{36};
static constexpr uint8_t DISK_BLOCK_INDEX_WRAPPER_SIZE{104};
static constexpr size_t CHECKSUM_SIZE{sizeof(uint32_t)};
static constexpr size_t FILE_POSITION_SIZE{sizeof(int64_t)};

/** A wrapper for creating a constant-sized serialization without varint encoding */
struct BlockFileInfoWrapper : CBlockFileInfo {
    BlockFileInfoWrapper() = default;

    explicit BlockFileInfoWrapper(const CBlockFileInfo* info) : CBlockFileInfo(*info)
    {
    }

    SERIALIZE_METHODS(BlockFileInfoWrapper, obj)
    {
        READWRITE(obj.nBlocks);
        READWRITE(obj.nSize);
        READWRITE(obj.nUndoSize);
        READWRITE(obj.nHeightFirst);
        READWRITE(obj.nHeightLast);
        READWRITE(obj.nTimeFirst);
        READWRITE(obj.nTimeLast);
    }
};

std::string CBlockFileInfo::ToString() const
{
    return strprintf("CBlockFileInfo(blocks=%u, size=%u, heights=%u...%u, time=%s...%s)", nBlocks, nSize, nHeightFirst, nHeightLast, FormatISO8601Date(nTimeFirst), FormatISO8601Date(nTimeLast));
}

static int64_t CalculateBlockFileInfoPosition(int file_index)
{
    Assume(file_index >= 0);
    return BLOCK_FILES_FILE_DATA_START_POSITION + file_index * (BLOCK_FILE_INFO_WRAPPER_SIZE + CHECKSUM_SIZE);
}

const fs::path& BlockTreeStore::GetDataFilePath(ValueType value_type) const
{
    switch (value_type) {
    case ValueType::BLOCK_FILE_INFO:
        return m_block_files_file_path;
    case ValueType::DISK_BLOCK_INDEX:
        return m_header_file_path;
    }
    throw BlockTreeStoreError(strprintf("Unrecognized value type (%u) in block tree store", static_cast<std::underlying_type_t<ValueType>>(value_type)));
}

static uint8_t ValueSize(const ValueType value_type)
{
    switch (value_type) {
    case ValueType::BLOCK_FILE_INFO:
        return BLOCK_FILE_INFO_WRAPPER_SIZE;
    case ValueType::DISK_BLOCK_INDEX:
        return DISK_BLOCK_INDEX_WRAPPER_SIZE;
    }
    throw BlockTreeStoreError(strprintf("Unrecognized value type (%u) in block tree store", static_cast<std::underlying_type_t<ValueType>>(value_type)));
}

static ValueType ReadValueType(AutoFile& file)
{
    std::underlying_type_t<ValueType> raw;
    file >> raw;
    return static_cast<ValueType>(raw);
}

static void WriteMagicAndVersion(AutoFile& file, uint32_t magic, uint32_t version)
{
    file << magic;
    file << version;
}

static void ReadAndCheckMagicAndVersion(AutoFile& file, const fs::path& path, uint32_t magic_expected, uint32_t version_expected)
{
    if (auto magic{ser_readdata32(file)}; magic != magic_expected) {
        throw BlockTreeStoreError(strprintf("Invalid magic in %s: 0x%08x (expected: 0x%08x)", fs::PathToString(path), magic, magic_expected));
    }
    if (auto version{ser_readdata32(file)}; version != version_expected) {
        throw BlockTreeStoreError(strprintf("Invalid version in %s: 0x%08x (expected: 0x%08x)", fs::PathToString(path), version, version_expected));
    }
}

static AutoFile OpenFile(const fs::path& path, const std::string& mode)
{
    AutoFile file{fsbridge::fopen(path, mode.c_str())};
    if (file.IsNull()) {
        throw BlockTreeStoreError(strprintf("Unable to open file %s", fs::PathToString(path)));
    }
    return AutoFile{file.release()};
}

static void CreateDataFile(const fs::path& path, uint32_t magic, uint32_t version)
{
    auto file{OpenFile(path, "wb")};

    WriteMagicAndVersion(file, magic, version);

    if (!file.Commit()) {
        throw BlockTreeStoreError(strprintf("Failed to write file %s", fs::PathToString(path)));
    }
    if (file.fclose() != 0) {
        throw BlockTreeStoreError(strprintf("Failed to close after write to file %s", fs::PathToString(path)));
    }
}

void BlockTreeStore::OpenAndCheckMagicAndVersion(const fs::path& path, uint32_t magic_expected, uint32_t version_expected) const
{
    auto file{OpenFile(path, "rb")};
    ReadAndCheckMagicAndVersion(file, path, magic_expected, version_expected);
}

BlockTreeStore::BlockTreeStore(const fs::path& path, bool wipe_data)
    : m_header_file_path{path / HEADER_FILE_NAME},
      m_log_file_path{path / LOG_FILE_NAME},
      m_log_flag_file_path{path / LOG_FLAG_FILE_NAME},
      m_block_files_file_path{path / BLOCK_FILES_FILE_NAME},
      m_reindex_flag_file_path{path / REINDEX_FLAG_FILE_NAME},
      m_prune_flag_file_path{path / PRUNE_FLAG_FILE_NAME}
{
    assert(GetSerializeSize(DiskBlockIndexWrapper{}) == DISK_BLOCK_INDEX_WRAPPER_SIZE);
    assert(GetSerializeSize(BlockFileInfoWrapper{}) == BLOCK_FILE_INFO_WRAPPER_SIZE);
    LOCK(m_mutex);
    fs::create_directories(path);
    if (wipe_data) {
        fs::remove(m_header_file_path);
        fs::remove(m_block_files_file_path);
        fs::remove(m_log_file_path);
        fs::remove(m_log_flag_file_path);
        fs::remove(m_reindex_flag_file_path);
        fs::remove(m_prune_flag_file_path);
    }
    bool header_file_exists{fs::exists(m_header_file_path)};
    bool block_files_file_exists{fs::exists(m_block_files_file_path)};
    if (header_file_exists != block_files_file_exists) {
        throw BlockTreeStoreError("Block tree store is in an inconsistent state");
    }
    if (!header_file_exists && !block_files_file_exists) {
        CreateDataFile(m_header_file_path, HEADER_FILE_MAGIC, HEADER_FILE_VERSION);
        CreateDataFile(m_block_files_file_path, BLOCK_FILES_FILE_MAGIC, BLOCK_FILES_FILE_VERSION);
    }
    OpenAndCheckMagicAndVersion(m_header_file_path, HEADER_FILE_MAGIC, HEADER_FILE_VERSION);
    OpenAndCheckMagicAndVersion(m_block_files_file_path, BLOCK_FILES_FILE_MAGIC, BLOCK_FILES_FILE_VERSION);
    (void)ApplyLog(); // Missing or incomplete logs are safe to ignore; apply failures throw.
}

void BlockTreeStore::WriteFlag(const fs::path& path, bool value) const
{
    if (value) {
        if (auto file{AutoFile{fsbridge::fopen(path, "w")}}; file.IsNull() || file.fclose()) {
            throw BlockTreeStoreError(strprintf("Could not create flag file %s", fs::PathToString(path)));
        }
    } else {
        std::error_code ec;
        fs::remove(path, ec);
        if (ec && ec != std::errc::no_such_file_or_directory) {
            throw BlockTreeStoreError(strprintf("Could not remove flag file %s", fs::PathToString(path)));
        }
    }
    DirectoryCommit(path.parent_path());
}

void BlockTreeStore::ReadReindexing(bool& reindexing) const
{
    reindexing = fs::exists(m_reindex_flag_file_path);
}

void BlockTreeStore::WriteReindexing(bool reindexing) const
{
    WriteFlag(m_reindex_flag_file_path, reindexing);
}

void BlockTreeStore::ReadLastBlockFile(int32_t& last_block_file) const
{
    LOCK(m_mutex);
    auto file{OpenFile(m_block_files_file_path, "rb")};

    constexpr int64_t entry_size = BLOCK_FILE_INFO_WRAPPER_SIZE + CHECKSUM_SIZE;
    const int64_t file_data_size{file.size() - BLOCK_FILES_FILE_DATA_START_POSITION};
    if (file_data_size < 0 || file_data_size % entry_size != 0) {
        throw BlockTreeStoreError("Invalid block files file data");
    }
    last_block_file = file_data_size == 0 ? 0 : file_data_size / entry_size - 1;
}

void BlockTreeStore::ReadPruned(bool& pruned) const
{
    pruned = fs::exists(m_prune_flag_file_path);
}

void BlockTreeStore::WritePruned(bool pruned) const
{
    WriteFlag(m_prune_flag_file_path, pruned);
}

static uint32_t ExtendChecksum(uint32_t checksum, std::span<const std::byte> value_data, int64_t position)
{
    checksum = crc32c::Extend(checksum, UCharCast(value_data.data()), value_data.size());
    std::array<std::byte, FILE_POSITION_SIZE> position_bytes;
    WriteLE64(UCharCast(position_bytes.data()), static_cast<uint64_t>(position));
    return crc32c::Extend(checksum, UCharCast(position_bytes.data()), position_bytes.size());
}

static uint32_t Checksum(std::span<const std::byte> value_data, int64_t position)
{
    return ExtendChecksum(0, value_data, position);
}

static void WriteLogFileSectionHeader(AutoFile& log_file, ValueType value_type, uint64_t record_count)
{
    log_file << static_cast<std::underlying_type_t<ValueType>>(value_type);
    log_file << record_count;
}

static std::pair<ValueType, uint64_t> ReadLogFileSectionHeader(AutoFile& log_file)
{
    const ValueType value_type{ReadValueType(log_file)};
    uint64_t record_count;
    log_file >> record_count;
    return {value_type, record_count};
}

struct LogFileRecord {
    std::vector<std::byte> m_value_buffer;
    int64_t m_position;
    uint32_t m_checksum;

    LogFileRecord(ValueType value_type) : m_value_buffer(ValueSize(value_type)) {}
};

static void ReadLogFileRecord(AutoFile& log_file, LogFileRecord& record, uint32_t& rolling_checksum)
{
    log_file.read(record.m_value_buffer);
    log_file >> record.m_position;

    record.m_checksum = Checksum(record.m_value_buffer, record.m_position);
    rolling_checksum = ExtendChecksum(rolling_checksum, record.m_value_buffer, record.m_position);

    uint32_t stored_checksum;
    log_file >> stored_checksum;
    if (stored_checksum != record.m_checksum) {
        throw BlockTreeStoreError("Detected on-disk log file corruption: Checksum mismatch");
    }
}

template <typename Wrapper>
static void WriteLogFileRecord(AutoFile& log_file, std::span<std::byte> value_buffer, const Wrapper& wrapper, int64_t position, uint32_t& rolling_checksum)
{
    SpanWriter{value_buffer} << wrapper;
    const uint32_t checksum{Checksum(value_buffer, position)};
    rolling_checksum = ExtendChecksum(rolling_checksum, value_buffer, position);
    log_file.write(value_buffer);
    log_file << position;
    log_file << checksum;
}

static void ReadDataValue(AutoFile& file, std::span<std::byte> value_buffer)
{
    const int64_t position{file.tell()};
    file.read(value_buffer);
    uint32_t checksum;
    file >> checksum;
    if (Checksum(value_buffer, position) != checksum) {
        throw BlockTreeStoreError("Record data failed integrity check");
    }
}

bool BlockTreeStore::ReadBlockFileInfo(int file_index, CBlockFileInfo& info)
{
    LOCK(m_mutex);
    auto file{OpenFile(m_block_files_file_path, "rb")};
    file.seek(CalculateBlockFileInfoPosition(file_index), SEEK_SET);

    BlockFileInfoWrapper info_wrapper;
    std::array<std::byte, BLOCK_FILE_INFO_WRAPPER_SIZE> buffer;

    try {
        ReadDataValue(file, buffer);
        SpanReader{buffer} >> info_wrapper;
    } catch (std::ios_base::failure&) {
        return false;
    }

    info = info_wrapper;
    return true;
}

bool BlockTreeStore::ApplyLog() const
{
    AssertLockHeld(m_mutex);

    if (!fs::exists(m_log_file_path)) {
        return false;
    }

    // If this is a torn log, indicated by the flag not being set, remove it and return.
    if (!fs::exists(m_log_flag_file_path)) {
        fs::remove(m_log_file_path);
        return false;
    }

    auto log_file{OpenFile(m_log_file_path, "rb")};

    ReadAndCheckMagicAndVersion(log_file, m_log_file_path, LOG_FILE_MAGIC, LOG_FILE_VERSION);

    uint32_t rolling_checksum = 0;
    uint32_t stored_rolling_checksum = 0;
    uint32_t number_of_types = 0;

    // Do a dry run to check the integrity of the log file. This should help prevent cascading errors in case of log file corruption.
    try {
        log_file >> number_of_types;
        for (uint32_t i = 0; i < number_of_types; i++) {
            const auto [value_type, record_count] = ReadLogFileSectionHeader(log_file);
            LogFileRecord record{value_type};

            for (uint64_t j = 0; j < record_count; j++) {
                ReadLogFileRecord(log_file, record, rolling_checksum);
            }
        }

        log_file >> stored_rolling_checksum;
        if (rolling_checksum != stored_rolling_checksum) {
            throw BlockTreeStoreError("Detected on-disk log file corruption: Rolling checksum mismatch");
        }
    } catch (const std::ios_base::failure& e) {
        throw BlockTreeStoreError(strprintf("Encountered exception while checking log file: %s", e.what()));
    }

    rolling_checksum = 0;
    stored_rolling_checksum = 0;
    // Seek back to the start of the log file data, but skip reading the number of types again
    log_file.seek(LOG_FILE_DATA_START_POSITION + sizeof(number_of_types), SEEK_SET);

    // Run through the file again, but this time write it to the target data files.
    for (uint32_t i = 0; i < number_of_types; ++i) {
        const auto [value_type, record_count] = ReadLogFileSectionHeader(log_file);
        auto data_file_path{GetDataFilePath(value_type)};
        auto data_file{OpenFile(data_file_path, "rb+")};
        LogFileRecord record{value_type};

        for (uint64_t j = 0; j < record_count; ++j) {
            ReadLogFileRecord(log_file, record, rolling_checksum);

            if (data_file.tell() != record.m_position) {
                data_file.seek(record.m_position, SEEK_SET);
            }

            data_file.write(record.m_value_buffer);
            data_file << record.m_checksum;

            // TEST ONLY
            if (m_incomplete_log_apply) {
                (void)data_file.fclose();
                return false;
            }
        }

        if (!data_file.Commit()) {
            throw BlockTreeStoreError(strprintf("Failed to commit write to data file %s", PathToString(data_file_path)));
        }
        if (data_file.fclose() != 0) {
            throw BlockTreeStoreError(strprintf("Failed to close after write to data file %s", PathToString(data_file_path)));
        }
    }

    log_file >> stored_rolling_checksum;
    if (rolling_checksum != stored_rolling_checksum) {
        throw BlockTreeStoreError("Detected on-disk log file corruption: Rolling checksum mismatch");
    }

    (void)log_file.fclose();
    WriteFlag(m_log_flag_file_path, false);
    fs::remove(m_log_file_path);
    return true;
}

void BlockTreeStore::WriteBatchSync(const std::vector<std::pair<int, const CBlockFileInfo*>>& file_info, const std::vector<CBlockIndex*>& block_info)
{
    AssertLockHeld(::cs_main);
    LOCK(m_mutex);

    // If there is a complete log waiting to be applied, write that first. An incomplete log is discarded.
    // This may occur if a previous write threw an exception when writing the logged data to the .dat files.
    (void)ApplyLog();

    if (file_info.empty() && block_info.empty()) return;

    std::vector<std::pair<CBlockIndex*, int64_t>> pending_header_positions;
    pending_header_positions.reserve(block_info.size());

    // Use a write-ahead log file that gets atomically flushed to the target files.

    { // start log_file scope
    auto log_file{OpenFile(m_log_file_path, "wb")};
    WriteMagicAndVersion(log_file, LOG_FILE_MAGIC, LOG_FILE_VERSION);
    constexpr uint32_t log_num_types{2}; // We are writing two different types to the log file.
    log_file << log_num_types;

    std::array<std::byte, BLOCK_FILE_INFO_WRAPPER_SIZE> block_file_info_value_buffer;
    uint32_t rolling_checksum = 0;

    // Write the file_info entries to the log
    WriteLogFileSectionHeader(log_file, ValueType::BLOCK_FILE_INFO, file_info.size());
    for (const auto& [file, info] : file_info) {
        WriteLogFileRecord(log_file, block_file_info_value_buffer, BlockFileInfoWrapper{info}, CalculateBlockFileInfoPosition(file), rolling_checksum);
    }

    // TEST ONLY
    if (m_incomplete_log_write) {
        (void)log_file.fclose();
        throw std::runtime_error("failed to write file");
    }

    // Read the header data end position
    int64_t header_data_end;
    {
        auto header_file{OpenFile(m_header_file_path, "rb")};
        header_data_end = header_file.size();
    }

    // Write the block_info data to the log
    WriteLogFileSectionHeader(log_file, ValueType::DISK_BLOCK_INDEX, block_info.size());
    std::array<std::byte, DISK_BLOCK_INDEX_WRAPPER_SIZE> block_index_value_buffer;
    for (CBlockIndex* block_index : block_info) {
        int64_t position = block_index->header_pos == CBlockIndex::UNSET_HEADER_POS ? header_data_end : block_index->header_pos;
        auto disk_index{CDiskBlockIndex{block_index}};
        WriteLogFileRecord(log_file, block_index_value_buffer, DiskBlockIndexWrapper{&disk_index}, position, rolling_checksum);
        if (block_index->header_pos == CBlockIndex::UNSET_HEADER_POS) {
            pending_header_positions.emplace_back(block_index, header_data_end);
            header_data_end += DISK_BLOCK_INDEX_WRAPPER_SIZE + CHECKSUM_SIZE;
        }
    }

    // Finally write the rolling checksum and commit.
    log_file << rolling_checksum;
    if (!log_file.Commit()) {
        throw BlockTreeStoreError(strprintf("Failed to commit write to log file %s", PathToString(m_log_file_path)));
    }
    WriteFlag(m_log_flag_file_path, true);

    // Once committed, apply the header positions to the index and close the file.
    for (const auto& [block_index, header_pos] : pending_header_positions) {
        block_index->header_pos = header_pos;
    }
    if (log_file.fclose() != 0) {
        throw BlockTreeStoreError(strprintf("Failed to close after write to log file %s", PathToString(m_log_file_path)));
    }

    } // end log_file scope

    if (!ApplyLog()) {
        throw BlockTreeStoreError("Failed to apply write-ahead log to data files");
    }
}

bool BlockTreeStore::LoadBlockIndexGuts(
    const Consensus::Params& consensus_params,
    std::function<CBlockIndex*(const uint256&)> insert_block_index,
    const util::SignalInterrupt& interrupt)
{
    AssertLockHeld(::cs_main);
    LOCK(m_mutex);

    auto file{OpenFile(m_header_file_path, "rb")};

    int64_t data_end_position = file.size();
    file.seek(HEADER_FILE_DATA_START_POSITION, SEEK_SET);

    DiskBlockIndexWrapper disk_index;
    std::array<std::byte, DISK_BLOCK_INDEX_WRAPPER_SIZE> buffer;

    while (file.tell() < data_end_position) {
        if (interrupt) return false;

        auto record_start{file.tell()};
        ReadDataValue(file, buffer);
        SpanReader{buffer} >> disk_index;

        // Construct block index object
        CBlockIndex* block_index = insert_block_index(disk_index.ConstructBlockHash());
        block_index->pprev = insert_block_index(disk_index.hashPrev);
        block_index->header_pos = record_start;
        block_index->nHeight = disk_index.nHeight;
        block_index->nFile = disk_index.nFile;
        block_index->nDataPos = disk_index.nDataPos;
        block_index->nUndoPos = disk_index.nUndoPos;
        block_index->nVersion = disk_index.nVersion;
        block_index->hashMerkleRoot = disk_index.hashMerkleRoot;
        block_index->nTime = disk_index.nTime;
        block_index->nBits = disk_index.nBits;
        block_index->nNonce = disk_index.nNonce;
        block_index->nStatus = disk_index.nStatus;
        block_index->nTx = disk_index.nTx;

        if (!CheckProofOfWork(block_index->GetBlockHash(), block_index->nBits, consensus_params)) {
            LogError("CheckProofOfWork failed: %s", block_index->ToString());
            return false;
        }
    }

    return true;
}

} // namespace kernel
