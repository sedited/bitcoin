// Copyright (c) 2020-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
#include <chain.h>
#include <chainparams.h>
#include <coins.h>
#include <consensus/amount.h>
#include <consensus/validation.h>
#include <node/blockstorage.h>
#include <node/kernel_notifications.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <random.h>
#include <script/script.h>
#include <sync.h>
#include <test/util/coins.h>
#include <test/util/common.h>
#include <test/util/setup_common.h>
#include <tinyformat.h>
#include <uint256.h>
#include <util/check.h>
#include <validation.h>

#include <boost/test/unit_test.hpp>

#include <memory>
#include <optional>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(validation_chainstate_tests, ChainTestingSetup)

BOOST_FIXTURE_TEST_CASE(connect_tip_does_not_cache_inputs_on_failed_connect, TestChain100Setup)
{
    Chainstate& chainstate{Assert(m_node.chainman)->ActiveChainstate()};

    COutPoint outpoint;
    {
        LOCK(cs_main);
        outpoint = AddTestCoin(m_rng, chainstate.CoinsTip());
        chainstate.CoinsTip().Flush(/*reallocate_cache=*/false);
    }

    CMutableTransaction tx;
    tx.vin.emplace_back(outpoint);
    tx.vout.emplace_back(MAX_MONEY, CScript{} << OP_TRUE);

    const auto tip{WITH_LOCK(cs_main, return chainstate.m_chain.Tip()->GetBlockHash())};
    const CBlock block{CreateBlock({tx}, CScript{} << OP_TRUE)};
    BOOST_CHECK(Assert(m_node.chainman)->ProcessNewBlock(std::make_shared<CBlock>(block), true, true, nullptr));

    LOCK(cs_main);
    BOOST_CHECK_EQUAL(tip, chainstate.m_chain.Tip()->GetBlockHash()); // block rejected
    BOOST_CHECK(!chainstate.CoinsTip().HaveCoinInCache(outpoint));    // input not cached
}

//! Test that UpdateTip notifies about the new tip.
BOOST_FIXTURE_TEST_CASE(chainstate_update_tip, TestChain100Setup)
{
    const auto get_notify_tip{[&]() {
        LOCK(m_node.notifications->m_tip_block_mutex);
        BOOST_REQUIRE(m_node.notifications->TipBlock());
        return *m_node.notifications->TipBlock();
    }};
    uint256 curr_tip = get_notify_tip();

    mineBlocks(10);

    // After adding some blocks to the tip, best block should have changed.
    BOOST_CHECK(get_notify_tip() != curr_tip);
}

BOOST_AUTO_TEST_SUITE_END()
