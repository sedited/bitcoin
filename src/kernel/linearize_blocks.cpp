// Copyright (c) 2024-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <kernel/bitcoinkernel.h>
#include <kernel/bitcoinkernel_wrapper.h>

#include <util/fs.h>

#include <cassert>
#include <charconv>
#include <iostream>
#include <string>
#include <string_view>

using namespace btck;

class TestLog
{
public:
    void LogMessage(std::string_view message)
    {
        std::cout << "kernel: " << message;
    }
};

class LinearizeKernelNotifications : public KernelNotifications
{
public:
    void FlushErrorHandler(std::string_view error) override
    {
        std::cout << error << std::endl;
        assert(0);
    }

    void FatalErrorHandler(std::string_view error) override
    {
        std::cout << error << std::endl;
        assert(0);
    }
};

Context create_context(std::shared_ptr<LinearizeKernelNotifications> notifications, ChainType chain_type)
{
    ContextOptions options{};
    ChainParams params{chain_type};
    options.SetChainParams(params);
    options.SetNotifications(notifications);
    return Context{options};
}

std::unique_ptr<ChainMan> create_chainman(fs::path path_root,
                                          fs::path path_blocks,
                                          bool block_tree_db_in_memory,
                                          bool chainstate_db_in_memory,
                                          std::optional<uint64_t> max_blockfile_size,
                                          Context& context)
{
    ChainstateManagerOptions chainman_opts{context, fs::PathToString(path_root), fs::PathToString(path_blocks)};
    if (max_blockfile_size.has_value()) {
        chainman_opts.SetMaxBlockfileSize(max_blockfile_size.value());
    }
    if (block_tree_db_in_memory) {
        chainman_opts.UpdateBlockTreeDbInMemory(block_tree_db_in_memory);
    }
    if (chainstate_db_in_memory) {
        chainman_opts.UpdateChainstateDbInMemory(chainstate_db_in_memory);
    }

    return std::make_unique<ChainMan>(context, chainman_opts);
}

std::optional<ChainType> string_to_chain_type(const std::string& chainTypeStr) {
    if (chainTypeStr == "mainnet") {
        return ChainType::MAINNET;
    } else if (chainTypeStr == "testnet") {
        return ChainType::TESTNET;
    } else if (chainTypeStr == "signet") {
        return ChainType::SIGNET;
    } else if (chainTypeStr == "regtest") {
        return ChainType::REGTEST;
    } else {
        return std::nullopt;
    }
}

template<typename T>
std::optional<T> parse_arg(const char* arg) {
    T value;
    std::string_view sv{arg};
    auto [ptr, ec] = std::from_chars(sv.data(), sv.data() + sv.size(), value);
    if (ec == std::errc()) {
        return value;
    }
    std::cerr << "Error: invalid numeric argument" << std::endl;
    return std::nullopt;
}

int main(int argc, char* argv[]) {
    if (argc != 7) {
        std::cout << "Usage: <in_path> <out_path> <chain_type> <start_height> <end_height> <max_file_size>" << std::endl;
        return 1;
    }

    std::string in_path_raw{argv[1]};
    std::string out_path_raw{argv[2]};
    std::string chain_type_raw{argv[3]};
    int32_t start_height{*parse_arg<int32_t>(argv[4])};
    int32_t end_height{*parse_arg<int32_t>(argv[5])};
    uint64_t max_blockfile_size{*parse_arg<uint64_t>(argv[6])};

    auto in_path{fs::u8path(in_path_raw)};

    ChainType chain_type;
    if (auto maybe_chain_type{string_to_chain_type(chain_type_raw)}) {
        chain_type = *maybe_chain_type;
    } else {
        std::cout << "Error: invalid chain type string. Valid values are \"mainnet\", \"testnet\", \"signet\", \"regtest\"" << std::endl;
        return 1;
    }

    if (max_blockfile_size < 0x8000000) {
        std::cout << "Error: max blockfile size has to be at least: " << 0x8000000 << " (128 MiB)" << std::endl;
        return 1;
    }

    btck_LoggingOptions logging_options = {
        .log_timestamps = true,
        .log_time_micros = true,
        .log_threadnames = false,
        .log_sourcelocations = false,
        .always_print_category_levels = true,
    };

    logging_set_options(logging_options);
    logging_enable_category(LogCategory::REINDEX);
    Logger logger{std::make_unique<TestLog>()};

    auto notifications{std::make_shared<LinearizeKernelNotifications>()};
    auto context = create_context(notifications, chain_type);

    auto chainman_in = create_chainman(in_path, in_path / "blocks", false, false, std::nullopt, context);

    auto tip_height = chainman_in->GetChain().Height();
    if (start_height < 0 || start_height > tip_height) {
        std::cout << "Invalid start height range, needs to be between 0 and the current tip, which is: " << tip_height;
    }
    if (end_height < start_height || end_height < 0) {
        std::cout << "Invalid end height range, needs to be greater than start height and greater than 0.";
    }

    auto out_path = fs::u8path(out_path_raw);
    auto chainman_out = create_chainman(out_path, out_path / "blocks", true, true, max_blockfile_size, context);

    std::cout << "In path: " << in_path
              << " , out path: " << out_path
              << " , start height: " << start_height
              << " , end height: " << end_height
              << " , max block file size: " << max_blockfile_size
              << std::endl;

    auto chain = chainman_in->GetChain();
    for (const auto entry : chain.Entries()) {
        auto height = entry.GetHeight();
        if (height > end_height) {
            break;
        }
        auto block = chainman_in->ReadBlock(entry).value();

        if (height % 100 == 0) std::cout << "Writing block at height: " << height << std::endl;
        chainman_out->WriteBlockToDisk(block, height);
    }

    return 0;
}
