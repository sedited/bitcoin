// Copyright (c) 2019-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
#include <chainparams.h>
#include <consensus/validation.h>
#include <kernel/disconnected_transactions.h>
#include <node/block_template_manager.h>
#include <node/chainstatemanager_args.h>
#include <node/kernel_notifications.h>
#include <random.h>
#include <rpc/blockchain.h>
#include <sync.h>
#include <test/util/common.h>
#include <test/util/logging.h>
#include <test/util/random.h>
#include <test/util/setup_common.h>
#include <test/util/validation.h>
#include <uint256.h>
#include <util/byte_units.h>
#include <util/result.h>
#include <util/vector.h>
#include <validation.h>
#include <validationinterface.h>

#include <tinyformat.h>

#include <vector>

#include <boost/test/unit_test.hpp>


BOOST_FIXTURE_TEST_SUITE(validation_chainstatemanager_tests, TestingSetup)

//! Basic tests for ChainstateManager.
BOOST_FIXTURE_TEST_CASE(chainstatemanager, TestChain100Setup)
{
    ChainstateManager& manager = *m_node.chainman;

    Chainstate& c1 = manager.ActiveChainstate();

    auto& active_chain = WITH_LOCK(manager.GetMutex(), return manager.ActiveChain());
    BOOST_CHECK_EQUAL(&active_chain, &c1.m_chain);

    mineBlocks(10);
    BOOST_CHECK_EQUAL(WITH_LOCK(manager.GetMutex(), return manager.ActiveHeight()), 110);
    auto active_tip = WITH_LOCK(manager.GetMutex(), return manager.ActiveTip());
    auto exp_tip = c1.m_chain.Tip();
    BOOST_CHECK_EQUAL(active_tip, exp_tip);

    // Let scheduler events finish running to avoid accessing memory that is going to be unloaded
    m_node.validation_signals->SyncWithValidationInterfaceQueue();
}

BOOST_FIXTURE_TEST_CASE(chainstatemanager_ibd_exit_after_loading_blocks, ChainTestingSetup)
{
    CBlockIndex tip;
    ChainstateManager& chainman{*Assert(m_node.chainman)};
    auto apply{[&](bool cached_is_ibd, bool loading_blocks, bool tip_exists, bool enough_work, bool tip_recent) {
        LOCK(::cs_main);
        chainman.ResetChainstate();
        chainman.InitializeChainstate(m_node.mempool.get());

        const auto recent_time{Now<NodeSeconds>() - chainman.m_options.max_tip_age};

        chainman.m_cached_is_ibd.store(cached_is_ibd, std::memory_order_relaxed);
        chainman.m_blockman.m_importing = loading_blocks;
        if (tip_exists) {
            tip.nChainWork = chainman.MinimumChainWork() - (enough_work ? 0 : 1);
            tip.nTime = (recent_time - (tip_recent ? 0h : 100h)).time_since_epoch().count();
            chainman.ActiveChain().SetTip(tip);
        } else {
            assert(!chainman.ActiveChain().Tip());
        }
        chainman.UpdateIBDStatus();
    }};

    for (const bool cached_is_ibd : {false, true}) {
        for (const bool loading_blocks : {false, true}) {
            for (const bool tip_exists : {false, true}) {
                for (const bool enough_work : {false, true}) {
                    for (const bool tip_recent : {false, true}) {
                        apply(cached_is_ibd, loading_blocks, tip_exists, enough_work, tip_recent);
                        const bool expected_ibd = cached_is_ibd && (loading_blocks || !tip_exists || !enough_work || !tip_recent);
                        BOOST_CHECK_EQUAL(chainman.IsInitialBlockDownload(), expected_ibd);
                    }
                }
            }
        }
    }
}

//! Test LoadBlockIndex behavior.
//!
//! - First, verify that setBlockIndexCandidates is as expected for a fully
//!   synced chain.
//!
//! - Then mark a region of the chain as missing data, run LoadBlockIndex() and
//!   ensure that setBlockIndexCandidates only contains the fully validated tip,
//!   since the blocks past the missing region cannot be connected.
//!
BOOST_FIXTURE_TEST_CASE(chainstatemanager_loadblockindex, TestChain100Setup)
{
    ChainstateManager& chainman = *Assert(m_node.chainman);
    Chainstate& cs1 = chainman.ActiveChainstate();

    int num_indexes{0};
    // Blocks in range [missing_start_idx, last_missing_idx) will be
    // marked as not having data.
    const int expected_missing{20};
    const int last_missing_idx{111};
    const int missing_start_idx = last_missing_idx - expected_missing;

    mineBlocks(20);

    CBlockIndex* validated_tip{nullptr};
    CBlockIndex* orig_tip{WITH_LOCK(chainman.GetMutex(), return chainman.ActiveChain().Tip())};
    BOOST_CHECK_EQUAL(orig_tip->nHeight, 120);

    auto reload_block_index = [&]() {
        LOCK(chainman.GetMutex());
        // For completeness, we also reset the block sequence counters to
        // ensure that no state which affects the ranking of tip-candidates is
        // retained (even though this isn't strictly necessary).
        chainman.ResetBlockSequenceCounters();
        cs1.ClearBlockIndexCandidates();
        BOOST_CHECK(cs1.setBlockIndexCandidates.empty());
        chainman.LoadBlockIndex();
        cs1.PopulateBlockIndexCandidates();
    };

    // Ensure that without any missing BlockIndex entries, only the current tip is
    // considered as a candidate.
    reload_block_index();
    BOOST_CHECK_EQUAL(cs1.setBlockIndexCandidates.size(), 1);

    // Reset some region of the chain's nStatus, removing the HAVE_DATA flag.
    for (int i = 0; i <= cs1.m_chain.Height(); ++i) {
        LOCK(::cs_main);
        auto index = cs1.m_chain[i];

        // Blocks with heights in range [91, 110] are marked as missing data.
        if (i < last_missing_idx && i >= missing_start_idx) {
            index->nStatus = BlockStatus::BLOCK_VALID_TREE;
            index->nTx = 0;
            index->m_chain_tx_count = 0;
        }

        ++num_indexes;

        // Note the last fully-validated block as the expected validated tip.
        if (i == (missing_start_idx - 1)) {
            validated_tip = index;
        }
    }

    // Set tip of the chain to be the validated tip
    cs1.m_chain.SetTip(*validated_tip);

    // Sanity check test variables.
    BOOST_CHECK_EQUAL(num_indexes, 121); // 121 total blocks, including genesis
    BOOST_CHECK_EQUAL(orig_tip->nHeight, 120);  // original chain has height 120
    BOOST_CHECK_EQUAL(validated_tip->nHeight, 90); // current cs1 chain has height 90

    // Regenerate cs1.setBlockIndexCandidates and check contents below.
    reload_block_index();

    // The chain should only have the current validated tip as a candidate
    // (block 90). Specifically:
    //
    // - It does not have blocks 0-89 because they contain less work than the
    //   chain tip.
    //
    // - It has block 90 because it has data and equal work to the chain tip,
    //   (since it is the chain tip).
    //
    // - It does not have blocks 91-110 because they do not contain data.
    //
    // - It does not have blocks 111-120 because their ancestors do not all
    //   have data, so their transaction counts are unknown.
    BOOST_CHECK_EQUAL(cs1.setBlockIndexCandidates.size(), 1);
    BOOST_CHECK_EQUAL(cs1.setBlockIndexCandidates.count(validated_tip), 1);
    BOOST_CHECK_EQUAL(cs1.setBlockIndexCandidates.count(orig_tip), 0);
}

BOOST_FIXTURE_TEST_CASE(loadblockindex_invalid_descendants, TestChain100Setup)
{
    LOCK(Assert(m_node.chainman)->GetMutex());
    // consider the chain of blocks grand_parent <- parent <- child
    // intentionally mark:
    //   - grand_parent: BLOCK_FAILED_VALID
    //   - parent: BLOCK_FAILED_CHILD
    //   - child: not invalid
    // Test that when the block index is loaded, all blocks are marked as BLOCK_FAILED_VALID
    auto* child{m_node.chainman->ActiveChain().Tip()};
    auto* parent{child->pprev};
    auto* grand_parent{parent->pprev};
    grand_parent->nStatus = (grand_parent->nStatus | BLOCK_FAILED_VALID);
    parent->nStatus = (parent->nStatus & ~BLOCK_FAILED_VALID) | BLOCK_FAILED_CHILD;
    child->nStatus = (child->nStatus & ~BLOCK_FAILED_VALID);

    // Reload block index to recompute block status validity flags.
    m_node.chainman->LoadBlockIndex();

    // check grand_parent, parent, child is marked as BLOCK_FAILED_VALID after reloading the block index
    BOOST_CHECK(grand_parent->nStatus & BLOCK_FAILED_VALID);
    BOOST_CHECK(parent->nStatus & BLOCK_FAILED_VALID);
    BOOST_CHECK(child->nStatus & BLOCK_FAILED_VALID);
}

//! Verify that ReconsiderBlock clears failure flags for the target block, its ancestors, and descendants,
//! but not for sibling forks that diverge from a shared ancestor.
BOOST_FIXTURE_TEST_CASE(invalidate_block_and_reconsider_fork, TestChain100Setup)
{
    ChainstateManager& chainman = *Assert(m_node.chainman);
    Chainstate& chainstate = chainman.ActiveChainstate();

    // we have a chain of 100 blocks: genesis(0) <- ... <- block98 <- block99 <- block100
    CBlockIndex* block98;
    CBlockIndex* block99;
    CBlockIndex* block100;
    {
        LOCK(chainman.GetMutex());
        block98 = chainman.ActiveChain()[98];
        block99 = chainman.ActiveChain()[99];
        block100 = chainman.ActiveChain()[100];
    }

    // create the following block constellation:
    // genesis(0) <- ... <- block98 <- block99  <- block100
    //                              <- block99' <- block100'
    // by temporarily invalidating block99. the chain tip now falls to block98,
    // mine 2 new blocks on top of block 98 (block99' and block100') and then restore block99 and block 100.
    BlockValidationState state;
    BOOST_REQUIRE(chainstate.InvalidateBlock(state, block99));
    BOOST_REQUIRE(WITH_LOCK(cs_main, return chainman.ActiveChain().Tip()) == block98);
    CScript coinbase_script = CScript() << ToByteVector(coinbaseKey.GetPubKey()) << OP_CHECKSIG;
    for (int i = 0; i < 2; ++i) {
        CreateAndProcessBlock({}, coinbase_script);
    }
    const CBlockIndex* fork_block99;
    const CBlockIndex* fork_block100;
    {
        LOCK(chainman.GetMutex());
        fork_block99 = chainman.ActiveChain()[99];
        BOOST_REQUIRE(fork_block99->pprev == block98);
        fork_block100 = chainman.ActiveChain()[100];
        BOOST_REQUIRE(fork_block100->pprev == fork_block99);
    }
    // Restore original block99 and block100
    {
        LOCK(chainman.GetMutex());
        chainstate.ResetBlockFailureFlags(block99);
        chainman.RecalculateBestHeader();
    }
    chainstate.ActivateBestChain(state);
    BOOST_REQUIRE(WITH_LOCK(cs_main, return chainman.ActiveChain().Tip()) == block100);

    {
        LOCK(chainman.GetMutex());
        BOOST_CHECK(!(block100->nStatus & BLOCK_FAILED_VALID));
        BOOST_CHECK(!(block99->nStatus & BLOCK_FAILED_VALID));
        BOOST_CHECK(!(fork_block100->nStatus & BLOCK_FAILED_VALID));
        BOOST_CHECK(!(fork_block99->nStatus & BLOCK_FAILED_VALID));
    }

    // Invalidate block98
    BOOST_REQUIRE(chainstate.InvalidateBlock(state, block98));

    {
        LOCK(chainman.GetMutex());
        // block98 and all descendants of block98 are marked BLOCK_FAILED_VALID
        BOOST_CHECK(block98->nStatus & BLOCK_FAILED_VALID);
        BOOST_CHECK(block99->nStatus & BLOCK_FAILED_VALID);
        BOOST_CHECK(block100->nStatus & BLOCK_FAILED_VALID);
        BOOST_CHECK(fork_block99->nStatus & BLOCK_FAILED_VALID);
        BOOST_CHECK(fork_block100->nStatus & BLOCK_FAILED_VALID);
    }

    // Reconsider block99. ResetBlockFailureFlags clears BLOCK_FAILED_VALID from
    // block99 and its ancestors (block98) and descendants (block100)
    // but NOT from block99' and block100' (not a direct ancestor/descendant)
    {
        LOCK(chainman.GetMutex());
        chainstate.ResetBlockFailureFlags(block99);
        chainman.RecalculateBestHeader();
    }
    chainstate.ActivateBestChain(state);
    {
        LOCK(chainman.GetMutex());
        BOOST_CHECK(!(block98->nStatus & BLOCK_FAILED_VALID));
        BOOST_CHECK(!(block99->nStatus & BLOCK_FAILED_VALID));
        BOOST_CHECK(!(block100->nStatus & BLOCK_FAILED_VALID));
        BOOST_CHECK(fork_block99->nStatus & BLOCK_FAILED_VALID);
        BOOST_CHECK(fork_block100->nStatus & BLOCK_FAILED_VALID);
    }
}

/** Helper function to parse args into args_man and return the result of applying them to opts */
template <typename Options>
util::Result<Options> SetOptsFromArgs(ArgsManager& args_man, Options opts,
                                      const std::vector<const char*>& args)
{
    const auto argv{Cat({"ignore"}, args)};
    std::string error{};
    if (!args_man.ParseParameters(argv.size(), argv.data(), error)) {
        return util::Error{Untranslated("ParseParameters failed with error: " + error)};
    }
    const auto result{node::ApplyArgsManOptions(args_man, opts)};
    if (!result) return util::Error{util::ErrorString(result)};
    return opts;
}

BOOST_FIXTURE_TEST_CASE(chainstatemanager_args, BasicTestingSetup)
{
    //! Try to apply the provided args to a ChainstateManager::Options
    auto get_opts = [&](const std::vector<const char*>& args) {
        static kernel::Notifications notifications{};
        static const ChainstateManager::Options options{
            .chainparams = ::Params(),
            .datadir = {},
            .notifications = notifications};
        return SetOptsFromArgs(*this->m_node.args, options, args);
    };
    //! Like get_opts, but requires the provided args to be valid and unwraps the result
    auto get_valid_opts = [&](const std::vector<const char*>& args) {
        const auto result{get_opts(args)};
        BOOST_REQUIRE_MESSAGE(result, util::ErrorString(result).original);
        return *result;
    };

    // test -assumevalid
    BOOST_CHECK(!get_valid_opts({}).assumed_valid_block);
    BOOST_CHECK_EQUAL(get_valid_opts({"-assumevalid="}).assumed_valid_block, uint256::ZERO);
    BOOST_CHECK_EQUAL(get_valid_opts({"-assumevalid=0"}).assumed_valid_block, uint256::ZERO);
    BOOST_CHECK_EQUAL(get_valid_opts({"-noassumevalid"}).assumed_valid_block, uint256::ZERO);
    BOOST_CHECK_EQUAL(get_valid_opts({"-assumevalid=0x12"}).assumed_valid_block, uint256{0x12});

    std::string assume_valid{"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"};
    BOOST_CHECK_EQUAL(get_valid_opts({("-assumevalid=" + assume_valid).c_str()}).assumed_valid_block, uint256::FromHex(assume_valid));

    BOOST_CHECK(!get_opts({"-assumevalid=xyz"}));                                                               // invalid hex characters
    BOOST_CHECK(!get_opts({"-assumevalid=01234567890123456789012345678901234567890123456789012345678901234"})); // > 64 hex chars

    // test -minimumchainwork
    BOOST_CHECK(!get_valid_opts({}).minimum_chain_work);
    BOOST_CHECK_EQUAL(get_valid_opts({"-minimumchainwork=0"}).minimum_chain_work, arith_uint256());
    BOOST_CHECK_EQUAL(get_valid_opts({"-nominimumchainwork"}).minimum_chain_work, arith_uint256());
    BOOST_CHECK_EQUAL(get_valid_opts({"-minimumchainwork=0x1234"}).minimum_chain_work, arith_uint256{0x1234});

    std::string minimum_chainwork{"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"};
    BOOST_CHECK_EQUAL(get_valid_opts({("-minimumchainwork=" + minimum_chainwork).c_str()}).minimum_chain_work, UintToArith256(uint256::FromHex(minimum_chainwork).value()));

    BOOST_CHECK(!get_opts({"-minimumchainwork=xyz"}));                                                               // invalid hex characters
    BOOST_CHECK(!get_opts({"-minimumchainwork=01234567890123456789012345678901234567890123456789012345678901234"})); // > 64 hex chars

    BOOST_CHECK_EQUAL(get_valid_opts({}).prevoutfetch_threads_num, DEFAULT_PREVOUTFETCH_THREADS);
    BOOST_CHECK_EQUAL(get_valid_opts({"-prevoutfetchthreads=0"}).prevoutfetch_threads_num, 0);
    BOOST_CHECK_EQUAL(get_valid_opts({"-prevoutfetchthreads=3"}).prevoutfetch_threads_num, 3);
    BOOST_CHECK_EQUAL(get_valid_opts({"-prevoutfetchthreads=100"}).prevoutfetch_threads_num, MAX_PREVOUTFETCH_THREADS);
    BOOST_CHECK(!get_opts({"-prevoutfetchthreads=-1"}));
}

BOOST_AUTO_TEST_SUITE_END()
