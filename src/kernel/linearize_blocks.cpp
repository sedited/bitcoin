// Copyright (c) 2024-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <kernel/bitcoinkernel.h>
#include <kernel/bitcoinkernel_wrapper.h>

#include <common/args.h>
#include <util/fs.h>

#include <cassert>
#include <charconv>
#include <iostream>
#include <string>
#include <string_view>

using btck::Context;
using btck::ContextOptions;
using btck::ChainMan;
using btck::ChainstateManagerOptions;
using btck::ChainParams;
using btck::KernelNotifications;

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

Context create_context(std::shared_ptr<LinearizeKernelNotifications> notifications, btck::ChainType chain_type)
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

std::optional<btck::ChainType> string_to_chain_type(const std::string& chainTypeStr) {
    if (chainTypeStr == "mainnet") {
        return btck::ChainType::MAINNET;
    } else if (chainTypeStr == "testnet") {
        return btck::ChainType::TESTNET;
    } else if (chainTypeStr == "signet") {
        return btck::ChainType::SIGNET;
    } else if (chainTypeStr == "regtest") {
        return btck::ChainType::REGTEST;
    } else {
        return std::nullopt;
    }
}

int main(int argc, char* argv[]) {
    ArgsManager args;
    SetupHelpOptions(args);

    args.AddArg("-indir=<path>", "Path to the block directory to be linearized", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    args.AddArg("-outdir=<path>", "Path to the output block data directory", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    args.AddArg("-chain=<chain>", "Chain type: mainnet, testnet, signet, regtest (default: mainnet)", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    args.AddArg("-startheight=<n>", "Start height (default: 0)", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    args.AddArg("-endheight=<n>", "End height (default: chain tip)", ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);
    args.AddArg("-maxblockfilesize=<n>", "Max block file size in bytes (default: 128 MiB)",                           ArgsManager::ALLOW_ANY, OptionsCategory::OPTIONS);

    std::string error;
    if (!args.ParseParameters(argc, argv, error)) {
        std::cerr << "Error: " << error << std::endl;
        return 1;
    }

    if (HelpRequested(args)) {
        std::cerr << args.GetHelpMessage();
        return 0;
    }

    if (!args.IsArgSet("-indir")) {
        std::cerr << "Error: -indir is required." << std::endl;
        return 1;
    }
    if (!args.IsArgSet("-outdir")) {
        std::cerr << "Error: -outdir is required." << std::endl;
        return 1;
    }

    auto in_path = fs::PathFromString(args.GetArg("-indir").value());
    auto out_path = fs::PathFromString(args.GetArg("-outdir").value());
    auto chain_type_str = args.GetArg("-chain").value_or("mainnet");
    auto maybe_chain_type = string_to_chain_type(chain_type_str);
    if (!maybe_chain_type) {
        std::cerr << "Error: invalid chain type '" << chain_type_str << "'. Valid values: mainnet, testnet, signet, regtest" << std::endl;
        return 1;
    }

    int32_t start_height = args.GetIntArg("-startheight", 0);
    int32_t end_height = args.GetIntArg("-endheight", -1);

    constexpr uint64_t MAX_BLOCKFILE_SIZE{0x8000000}; // 128 MiB
    uint64_t max_blockfile_size = (uint64_t)args.GetIntArg("-maxblockfilesize", 0x8000000);
    if (max_blockfile_size < MAX_BLOCKFILE_SIZE) {
        std::cerr << "Error: -maxblockfilesize must be at least " << MAX_BLOCKFILE_SIZE << " (128 MiB)" << std::endl;
        return 1;
    }

    btck_LoggingOptions logging_options = {
        .log_timestamps = true,
        .log_time_micros = true,
        .log_threadnames = false,
        .log_sourcelocations = false,
        .always_print_category_levels = true,
    };

    btck::logging_set_options(logging_options);
    btck::logging_enable_category(btck::LogCategory::REINDEX);
    btck::Logger logger{std::make_unique<TestLog>()};

    auto notifications{std::make_shared<LinearizeKernelNotifications>()};
    auto context = create_context(notifications, *maybe_chain_type);

    auto chainman_in = create_chainman(in_path, in_path / "blocks", false, false, std::nullopt, context);

    auto tip_height = chainman_in->GetChain().Height();
    if (start_height < 0 || start_height > tip_height) {
        std::cerr << "Invalid start height range, needs to be between 0 and the current tip, which is: " << tip_height;
        return 1;
    }
    if (end_height == -1) {
        end_height = tip_height;
    }

    if (end_height < start_height || end_height < 0) {
        std::cerr << "Invalid end height range, needs to be greater than start height and greater than 0.";
        return 1;
    }

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
