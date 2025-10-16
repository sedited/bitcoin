// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <txmempool.h>

#include <chain.h>
#include <coins.h>
#include <common/system.h>
#include <consensus/consensus.h>
#include <consensus/tx_check.h>
#include <consensus/tx_verify.h>
#include <consensus/validation.h>
#include <kernel/disconnected_transactions.h>
#include <logging.h>
#include <policy/ephemeral_policy.h>
#include <policy/policy.h>
#include <policy/rbf.h>
#include <policy/settings.h>
#include <policy/truc_policy.h>
#include <random.h>
#include <tinyformat.h>
#include <util/check.h>
#include <util/feefrac.h>
#include <util/moneystr.h>
#include <util/overflow.h>
#include <util/result.h>
#include <util/time.h>
#include <util/trace.h>
#include <util/translation.h>
#include <validation.h>
#include <validationinterface.h>

#include <algorithm>
#include <cmath>
#include <numeric>
#include <optional>
#include <ranges>
#include <string_view>
#include <utility>

TRACEPOINT_SEMAPHORE(mempool, added);
TRACEPOINT_SEMAPHORE(mempool, removed);
TRACEPOINT_SEMAPHORE(mempool, replaced);
TRACEPOINT_SEMAPHORE(mempool, rejected);

/** Maximum age of our tip for us to be considered current for fee estimation */
static constexpr std::chrono::hours MAX_FEE_ESTIMATION_TIP_AGE{3};

bool TestLockPointValidity(CChain& active_chain, const LockPoints& lp)
{
    AssertLockHeld(cs_main);
    // If there are relative lock times then the maxInputBlock will be set
    // If there are no relative lock times, the LockPoints don't depend on the chain
    if (lp.maxInputBlock) {
        // Check whether active_chain is an extension of the block at which the LockPoints
        // calculation was valid.  If not LockPoints are no longer valid
        if (!active_chain.Contains(lp.maxInputBlock)) {
            return false;
        }
    }

    // LockPoints still valid
    return true;
}

std::vector<CTxMemPoolEntry::CTxMemPoolEntryRef> CTxMemPool::GetChildren(const CTxMemPoolEntry& entry) const
{
    LOCK(cs);
    std::vector<CTxMemPoolEntry::CTxMemPoolEntryRef> ret;
    setEntries children;
    auto iter = mapNextTx.lower_bound(COutPoint(entry.GetTx().GetHash(), 0));
    for (; iter != mapNextTx.end() && iter->first->hash == entry.GetTx().GetHash(); ++iter) {
        children.insert(iter->second);
    }
    for (const auto& child : children) {
        ret.emplace_back(*child);
    }
    return ret;
}

std::vector<CTxMemPoolEntry::CTxMemPoolEntryRef> CTxMemPool::GetParents(const CTxMemPoolEntry& entry) const
{
    LOCK(cs);
    std::vector<CTxMemPoolEntry::CTxMemPoolEntryRef> ret;
    std::set<Txid> inputs;
    for (const auto& txin : entry.GetTx().vin) {
        inputs.insert(txin.prevout.hash);
    }
    for (const auto& hash : inputs) {
        std::optional<txiter> piter = GetIter(hash);
        if (piter) {
            ret.emplace_back(**piter);
        }
    }
    return ret;
}

void CTxMemPool::UpdateTransactionsFromBlock(const std::vector<Txid>& vHashesToUpdate)
{
    AssertLockHeld(cs);

    // Iterate in reverse, so that whenever we are looking at a transaction
    // we are sure that all in-mempool descendants have already been processed.
    for (const Txid& hash : vHashesToUpdate | std::views::reverse) {
        // calculate children from mapNextTx
        txiter it = mapTx.find(hash);
        if (it == mapTx.end()) {
            continue;
        }
        auto iter = mapNextTx.lower_bound(COutPoint(hash, 0));
        {
            for (; iter != mapNextTx.end() && iter->first->hash == hash; ++iter) {
                txiter childIter = iter->second;
                assert(childIter != mapTx.end());
                // Add dependencies that are discovered between transactions in the
                // block and transactions that were in the mempool to txgraph.
                m_txgraph->AddDependency(/*parent=*/*it, /*child=*/*childIter);
            }
        }
    }

    auto txs_to_remove = m_txgraph->Trim(); // Enforce cluster size limits.
    for (auto txptr : txs_to_remove) {
        const CTxMemPoolEntry& entry = *(static_cast<const CTxMemPoolEntry*>(txptr));
        removeUnchecked(mapTx.iterator_to(entry), MemPoolRemovalReason::SIZELIMIT);
    }
}

bool CTxMemPool::HasDescendants(const Txid& txid) const
{
    LOCK(cs);
    auto entry = GetEntry(txid);
    if (!entry) return false;
    return m_txgraph->GetDescendants(*entry, TxGraph::Level::MAIN).size() > 1;
}

CTxMemPool::setEntries CTxMemPool::CalculateMemPoolAncestors(const CTxMemPoolEntry &entry) const
{
    auto ancestors = m_txgraph->GetAncestors(entry, TxGraph::Level::MAIN);
    setEntries ret;
    if (ancestors.size() > 0) {
        for (auto ancestor : ancestors) {
            if (ancestor != &entry) {
                ret.insert(mapTx.iterator_to(static_cast<const CTxMemPoolEntry&>(*ancestor)));
            }
        }
        return ret;
    }

    // If we didn't get anything back, the transaction is not in the graph.
    // Find each parent and call GetAncestors on each.
    setEntries staged_parents;
    const CTransaction &tx = entry.GetTx();

    // Get parents of this transaction that are in the mempool
    for (unsigned int i = 0; i < tx.vin.size(); i++) {
        std::optional<txiter> piter = GetIter(tx.vin[i].prevout.hash);
        if (piter) {
            staged_parents.insert(*piter);
        }
    }

    for (const auto& parent : staged_parents) {
        auto parent_ancestors = m_txgraph->GetAncestors(*parent, TxGraph::Level::MAIN);
        for (auto ancestor : parent_ancestors) {
            ret.insert(mapTx.iterator_to(static_cast<const CTxMemPoolEntry&>(*ancestor)));
        }
    }

    return ret;
}

static CTxMemPool::Options&& Flatten(CTxMemPool::Options&& opts, bilingual_str& error)
{
    opts.check_ratio = std::clamp<int>(opts.check_ratio, 0, 1'000'000);
    int64_t cluster_limit_bytes = opts.limits.cluster_size_vbytes * 40;
    if (opts.max_size_bytes < 0 || (opts.max_size_bytes > 0 && opts.max_size_bytes < cluster_limit_bytes)) {
        error = strprintf(_("-maxmempool must be at least %d MB"), std::ceil(cluster_limit_bytes / 1'000'000.0));
    }
    return std::move(opts);
}

CTxMemPool::CTxMemPool(Options opts, bilingual_str& error)
    : m_opts{Flatten(std::move(opts), error)}
{
    m_txgraph = MakeTxGraph(m_opts.limits.cluster_count, m_opts.limits.cluster_size_vbytes * WITNESS_SCALE_FACTOR, ACCEPTABLE_ITERS);
}

bool CTxMemPool::isSpent(const COutPoint& outpoint) const
{
    LOCK(cs);
    return mapNextTx.count(outpoint);
}

unsigned int CTxMemPool::GetTransactionsUpdated() const
{
    return nTransactionsUpdated;
}

void CTxMemPool::AddTransactionsUpdated(unsigned int n)
{
    nTransactionsUpdated += n;
}

void CTxMemPool::Apply(ChangeSet* changeset)
{
    AssertLockHeld(cs);
    m_txgraph->CommitStaging();

    RemoveStaged(changeset->m_to_remove, false, MemPoolRemovalReason::REPLACED);

    for (size_t i=0; i<changeset->m_entry_vec.size(); ++i) {
        auto tx_entry = changeset->m_entry_vec[i];
        // First splice this entry into mapTx.
        auto node_handle = changeset->m_to_add.extract(tx_entry);
        auto result = mapTx.insert(std::move(node_handle));

        Assume(result.inserted);
        txiter it = result.position;

        addNewTransaction(it);
    }
    m_txgraph->DoWork(POST_CHANGE_WORK);
}

void CTxMemPool::addNewTransaction(CTxMemPool::txiter newit)
{
    const CTxMemPoolEntry& entry = *newit;

    // Update cachedInnerUsage to include contained transaction's usage.
    // (When we update the entry for in-mempool parents, memory usage will be
    // further updated.)
    cachedInnerUsage += entry.DynamicMemoryUsage();

    const CTransaction& tx = newit->GetTx();
    for (unsigned int i = 0; i < tx.vin.size(); i++) {
        mapNextTx.insert(std::make_pair(&tx.vin[i].prevout, newit));
    }
    // Don't bother worrying about child transactions of this one.
    // Normal case of a new transaction arriving is that there can't be any
    // children, because such children would be orphans.
    // An exception to that is if a transaction enters that used to be in a block.
    // In that case, our disconnect block logic will call UpdateTransactionsFromBlock
    // to clean up the mess we're leaving here.

    nTransactionsUpdated++;
    totalTxSize += entry.GetTxSize();
    m_total_fee += entry.GetFee();

    txns_randomized.emplace_back(tx.GetWitnessHash(), newit);
    newit->idx_randomized = txns_randomized.size() - 1;

    TRACEPOINT(mempool, added,
        entry.GetTx().GetHash().data(),
        entry.GetTxSize(),
        entry.GetFee()
    );
}

void CTxMemPool::removeUnchecked(txiter it, MemPoolRemovalReason reason)
{
    // We increment mempool sequence value no matter removal reason
    // even if not directly reported below.
    uint64_t mempool_sequence = GetAndIncrementSequence();

    if (reason != MemPoolRemovalReason::BLOCK && m_opts.signals) {
        // Notify clients that a transaction has been removed from the mempool
        // for any reason except being included in a block. Clients interested
        // in transactions included in blocks can subscribe to the BlockConnected
        // notification.
        m_opts.signals->TransactionRemovedFromMempool(it->GetSharedTx(), reason, mempool_sequence);
    }
    TRACEPOINT(mempool, removed,
        it->GetTx().GetHash().data(),
        RemovalReasonToString(reason).c_str(),
        it->GetTxSize(),
        it->GetFee(),
        std::chrono::duration_cast<std::chrono::duration<std::uint64_t>>(it->GetTime()).count()
    );

    for (const CTxIn& txin : it->GetTx().vin)
        mapNextTx.erase(txin.prevout);

    RemoveUnbroadcastTx(it->GetTx().GetHash(), true /* add logging because unchecked */);

    if (txns_randomized.size() > 1) {
        // Remove entry from txns_randomized by replacing it with the back and deleting the back.
        txns_randomized[it->idx_randomized] = std::move(txns_randomized.back());
        txns_randomized[it->idx_randomized].second->idx_randomized = it->idx_randomized;
        txns_randomized.pop_back();
        if (txns_randomized.size() * 2 < txns_randomized.capacity()) {
            txns_randomized.shrink_to_fit();
        }
    } else {
        txns_randomized.clear();
    }

    totalTxSize -= it->GetTxSize();
    m_total_fee -= it->GetFee();
    cachedInnerUsage -= it->DynamicMemoryUsage();
    mapTx.erase(it);
    nTransactionsUpdated++;
}

// Calculates descendants of given entry and adds to setDescendants.
void CTxMemPool::CalculateDescendants(txiter entryit, setEntries& setDescendants) const
{
    (void)CalculateDescendants(*entryit, setDescendants);
    return;
}

CTxMemPool::txiter CTxMemPool::CalculateDescendants(const CTxMemPoolEntry& entry, setEntries& setDescendants) const
{
    for (auto tx : m_txgraph->GetDescendants(entry, TxGraph::Level::MAIN)) {
        setDescendants.insert(mapTx.iterator_to(static_cast<const CTxMemPoolEntry&>(*tx)));
    }
    return mapTx.iterator_to(entry);
}

void CTxMemPool::removeRecursive(const CTransaction &origTx, MemPoolRemovalReason reason)
{
    // Remove transaction from memory pool
    AssertLockHeld(cs);
    Assume(!m_have_changeset);
        setEntries txToRemove;
        txiter origit = mapTx.find(origTx.GetHash());
        if (origit != mapTx.end()) {
            txToRemove.insert(origit);
        } else {
            // When recursively removing but origTx isn't in the mempool
            // be sure to remove any children that are in the pool. This can
            // happen during chain re-orgs if origTx isn't re-accepted into
            // the mempool for any reason.
            for (unsigned int i = 0; i < origTx.vout.size(); i++) {
                auto it = mapNextTx.find(COutPoint(origTx.GetHash(), i));
                if (it == mapNextTx.end())
                    continue;
                txiter nextit = it->second;
                assert(nextit != mapTx.end());
                txToRemove.insert(nextit);
            }
        }
        setEntries setAllRemoves;
        for (txiter it : txToRemove) {
            CalculateDescendants(it, setAllRemoves);
        }

        RemoveStaged(setAllRemoves, false, reason);
}

void CTxMemPool::removeForReorg(CChain& chain, std::function<bool(txiter)> check_final_and_mature)
{
    // Remove transactions spending a coinbase which are now immature and no-longer-final transactions
    AssertLockHeld(cs);
    AssertLockHeld(::cs_main);
    Assume(!m_have_changeset);

    setEntries txToRemove;
    for (indexed_transaction_set::const_iterator it = mapTx.begin(); it != mapTx.end(); it++) {
        if (check_final_and_mature(it)) txToRemove.insert(it);
    }
    setEntries setAllRemoves;
    for (txiter it : txToRemove) {
        CalculateDescendants(it, setAllRemoves);
    }
    RemoveStaged(setAllRemoves, false, MemPoolRemovalReason::REORG);
    for (indexed_transaction_set::const_iterator it = mapTx.begin(); it != mapTx.end(); it++) {
        assert(TestLockPointValidity(chain, it->GetLockPoints()));
    }
    m_txgraph->DoWork(POST_CHANGE_WORK);
}

void CTxMemPool::removeConflicts(const CTransaction &tx)
{
    // Remove transactions which depend on inputs of tx, recursively
    AssertLockHeld(cs);
    for (const CTxIn &txin : tx.vin) {
        auto it = mapNextTx.find(txin.prevout);
        if (it != mapNextTx.end()) {
            const CTransaction &txConflict = it->second->GetTx();
            if (Assume(txConflict.GetHash() != tx.GetHash()))
            {
                ClearPrioritisation(txConflict.GetHash());
                removeRecursive(txConflict, MemPoolRemovalReason::CONFLICT);
            }
        }
    }
}

void CTxMemPool::removeForBlock(const std::vector<CTransactionRef>& vtx, unsigned int nBlockHeight)
{
    // Remove confirmed txs and conflicts when a new block is connected, updating the fee logic
    AssertLockHeld(cs);
    Assume(!m_have_changeset);
    std::vector<RemovedMempoolTransactionInfo> txs_removed_for_block;
    if (mapTx.size() || mapNextTx.size() || mapDeltas.size()) {
        txs_removed_for_block.reserve(vtx.size());
        for (const auto& tx : vtx) {
            txiter it = mapTx.find(tx->GetHash());
            if (it != mapTx.end()) {
                setEntries stage;
                stage.insert(it);
                txs_removed_for_block.emplace_back(*it);
                RemoveStaged(stage, true, MemPoolRemovalReason::BLOCK);
            }
            removeConflicts(*tx);
            ClearPrioritisation(tx->GetHash());
        }
    }
    if (m_opts.signals) {
        m_opts.signals->MempoolTransactionsRemovedForBlock(txs_removed_for_block, nBlockHeight);
    }
    lastRollingFeeUpdate = GetTime();
    blockSinceLastRollingFeeBump = true;
    m_txgraph->DoWork(POST_CHANGE_WORK);
}

void CTxMemPool::check(const CCoinsViewCache& active_coins_tip, int64_t spendheight) const
{
    if (m_opts.check_ratio == 0) return;

    if (FastRandomContext().randrange(m_opts.check_ratio) >= 1) return;

    AssertLockHeld(::cs_main);
    LOCK(cs);
    LogDebug(BCLog::MEMPOOL, "Checking mempool with %u transactions and %u inputs\n", (unsigned int)mapTx.size(), (unsigned int)mapNextTx.size());

    uint64_t checkTotal = 0;
    CAmount check_total_fee{0};
    uint64_t innerUsage = 0;

    assert(!m_txgraph->IsOversized(TxGraph::Level::MAIN));
    m_txgraph->SanityCheck();

    CCoinsViewCache mempoolDuplicate(const_cast<CCoinsViewCache*>(&active_coins_tip));

    const auto score_with_topo{GetSortedScoreWithTopology()};

    // Number of chunks is bounded by number of transactions.
    const auto diagram{GetFeerateDiagram()};
    Assume(diagram.size() <= score_with_topo.size() + 1);

    std::optional<Wtxid> last_wtxid = std::nullopt;

    for (const auto& it : score_with_topo) {
        checkTotal += it->GetTxSize();
        check_total_fee += it->GetFee();
        innerUsage += it->DynamicMemoryUsage();
        const CTransaction& tx = it->GetTx();

        // CompareMiningScoreWithTopology should agree with GetSortedScoreWithTopology()
        if (last_wtxid) {
            assert(CompareMiningScoreWithTopology(*last_wtxid, tx.GetWitnessHash()));
        }
        last_wtxid = tx.GetWitnessHash();

        std::set<CTxMemPoolEntry::CTxMemPoolEntryRef, CompareIteratorByHash> setParentCheck;
        std::set<CTxMemPoolEntry::CTxMemPoolEntryRef, CompareIteratorByHash> setParentsStored;
        for (const CTxIn &txin : tx.vin) {
            // Check that every mempool transaction's inputs refer to available coins, or other mempool tx's.
            indexed_transaction_set::const_iterator it2 = mapTx.find(txin.prevout.hash);
            if (it2 != mapTx.end()) {
                const CTransaction& tx2 = it2->GetTx();
                assert(tx2.vout.size() > txin.prevout.n && !tx2.vout[txin.prevout.n].IsNull());
                setParentCheck.insert(*it2);
            }
            // We are iterating through the mempool entries sorted
            // topologically and by mining score. All parents must have been
            // checked before their children and their coins added to the
            // mempoolDuplicate coins cache.
            assert(mempoolDuplicate.HaveCoin(txin.prevout));
            // Check whether its inputs are marked in mapNextTx.
            auto it3 = mapNextTx.find(txin.prevout);
            assert(it3 != mapNextTx.end());
            assert(it3->first == &txin.prevout);
            assert(&it3->second->GetTx() == &tx);
        }
        auto comp = [](const CTxMemPoolEntry& a, const CTxMemPoolEntry& b) -> bool {
            return a.GetTx().GetHash() == b.GetTx().GetHash();
        };
        for (auto &txentry : GetParents(*it)) {
            setParentsStored.insert(dynamic_cast<const CTxMemPoolEntry&>(txentry.get()));
        }
        assert(setParentCheck.size() == setParentsStored.size());
        assert(std::equal(setParentCheck.begin(), setParentCheck.end(), setParentsStored.begin(), comp));

        // Check children against mapNextTx
        std::set<CTxMemPoolEntry::CTxMemPoolEntryRef, CompareIteratorByHash> setChildrenCheck;
        std::set<CTxMemPoolEntry::CTxMemPoolEntryRef, CompareIteratorByHash> setChildrenStored;
        auto iter = mapNextTx.lower_bound(COutPoint(it->GetTx().GetHash(), 0));
        for (; iter != mapNextTx.end() && iter->first->hash == it->GetTx().GetHash(); ++iter) {
            txiter childit = iter->second;
            assert(childit != mapTx.end()); // mapNextTx points to in-mempool transactions
            setChildrenCheck.insert(*childit);
        }
        for (auto &txentry : GetChildren(*it)) {
            setChildrenStored.insert(dynamic_cast<const CTxMemPoolEntry&>(txentry.get()));
        }
        assert(setChildrenCheck.size() == setChildrenStored.size());
        assert(std::equal(setChildrenCheck.begin(), setChildrenCheck.end(), setChildrenStored.begin(), comp));

        TxValidationState dummy_state; // Not used. CheckTxInputs() should always pass
        CAmount txfee = 0;
        assert(!tx.IsCoinBase());
        assert(Consensus::CheckTxInputs(tx, dummy_state, mempoolDuplicate, spendheight, txfee));
        for (const auto& input: tx.vin) mempoolDuplicate.SpendCoin(input.prevout);
        AddCoins(mempoolDuplicate, tx, std::numeric_limits<int>::max());
    }
    for (auto it = mapNextTx.cbegin(); it != mapNextTx.cend(); it++) {
        indexed_transaction_set::const_iterator it2 = it->second;
        assert(it2 != mapTx.end());
    }

    assert(totalTxSize == checkTotal);
    assert(m_total_fee == check_total_fee);
    assert(innerUsage == cachedInnerUsage);
}

bool CTxMemPool::CompareMiningScoreWithTopology(const Wtxid& hasha, const Wtxid& hashb) const
{
    /* Return `true` if hasha should be considered sooner than hashb, namely when:
     *     a is not in the mempool but b is, or
     *     both are in the mempool but a is sorted before b in the total mempool ordering
     *     (which takes dependencies and (chunk) feerates into account).
     */
    LOCK(cs);
    auto j{GetIter(hashb)};
    if (!j.has_value()) return false;
    auto i{GetIter(hasha)};
    if (!i.has_value()) return true;

    return m_txgraph->CompareMainOrder(*i.value(), *j.value()) < 0;
}

std::vector<CTxMemPool::indexed_transaction_set::const_iterator> CTxMemPool::GetSortedScoreWithTopology() const
{
    std::vector<indexed_transaction_set::const_iterator> iters;
    AssertLockHeld(cs);

    iters.reserve(mapTx.size());

    for (indexed_transaction_set::iterator mi = mapTx.begin(); mi != mapTx.end(); ++mi) {
        iters.push_back(mi);
    }
    std::sort(iters.begin(), iters.end(), [this](const auto& a, const auto& b) EXCLUSIVE_LOCKS_REQUIRED(cs) noexcept {
        return m_txgraph->CompareMainOrder(*a, *b) < 0;
    });
    return iters;
}

std::vector<CTxMemPoolEntryRef> CTxMemPool::entryAll() const
{
    AssertLockHeld(cs);

    std::vector<CTxMemPoolEntryRef> ret;
    ret.reserve(mapTx.size());
    for (const auto& it : GetSortedScoreWithTopology()) {
        ret.emplace_back(*it);
    }
    return ret;
}

std::vector<TxMempoolInfo> CTxMemPool::infoAll() const
{
    LOCK(cs);
    auto iters = GetSortedScoreWithTopology();

    std::vector<TxMempoolInfo> ret;
    ret.reserve(mapTx.size());
    for (auto it : iters) {
        ret.push_back(GetInfo(it));
    }

    return ret;
}

const CTxMemPoolEntry* CTxMemPool::GetEntry(const Txid& txid) const
{
    AssertLockHeld(cs);
    const auto i = mapTx.find(txid);
    return i == mapTx.end() ? nullptr : &(*i);
}

CTransactionRef CTxMemPool::get(const Txid& hash) const
{
    LOCK(cs);
    indexed_transaction_set::const_iterator i = mapTx.find(hash);
    if (i == mapTx.end())
        return nullptr;
    return i->GetSharedTx();
}

void CTxMemPool::PrioritiseTransaction(const Txid& hash, const CAmount& nFeeDelta)
{
    {
        LOCK(cs);
        CAmount &delta = mapDeltas[hash];
        delta = SaturatingAdd(delta, nFeeDelta);
        txiter it = mapTx.find(hash);
        if (it != mapTx.end()) {
            // PrioritiseTransaction calls stack on previous ones. Set the new
            // transaction fee to be current modified fee + feedelta.
            mapTx.modify(it, [&nFeeDelta](CTxMemPoolEntry& e) { e.UpdateModifiedFee(nFeeDelta); });
            m_txgraph->SetTransactionFee(*it, it->GetModifiedFee());
            ++nTransactionsUpdated;
        }
        if (delta == 0) {
            mapDeltas.erase(hash);
            LogPrintf("PrioritiseTransaction: %s (%sin mempool) delta cleared\n", hash.ToString(), it == mapTx.end() ? "not " : "");
        } else {
            LogPrintf("PrioritiseTransaction: %s (%sin mempool) fee += %s, new delta=%s\n",
                      hash.ToString(),
                      it == mapTx.end() ? "not " : "",
                      FormatMoney(nFeeDelta),
                      FormatMoney(delta));
        }
    }
}

void CTxMemPool::ApplyDelta(const Txid& hash, CAmount &nFeeDelta) const
{
    AssertLockHeld(cs);
    std::map<Txid, CAmount>::const_iterator pos = mapDeltas.find(hash);
    if (pos == mapDeltas.end())
        return;
    const CAmount &delta = pos->second;
    nFeeDelta += delta;
}

void CTxMemPool::ClearPrioritisation(const Txid& hash)
{
    AssertLockHeld(cs);
    mapDeltas.erase(hash);
}

std::vector<CTxMemPool::delta_info> CTxMemPool::GetPrioritisedTransactions() const
{
    AssertLockNotHeld(cs);
    LOCK(cs);
    std::vector<delta_info> result;
    result.reserve(mapDeltas.size());
    for (const auto& [txid, delta] : mapDeltas) {
        const auto iter{mapTx.find(txid)};
        const bool in_mempool{iter != mapTx.end()};
        std::optional<CAmount> modified_fee;
        if (in_mempool) modified_fee = iter->GetModifiedFee();
        result.emplace_back(delta_info{in_mempool, delta, modified_fee, txid});
    }
    return result;
}

const CTransaction* CTxMemPool::GetConflictTx(const COutPoint& prevout) const
{
    const auto it = mapNextTx.find(prevout);
    return it == mapNextTx.end() ? nullptr : &(it->second->GetTx());
}

std::optional<CTxMemPool::txiter> CTxMemPool::GetIter(const Txid& txid) const
{
    AssertLockHeld(cs);
    auto it = mapTx.find(txid);
    return it != mapTx.end() ? std::make_optional(it) : std::nullopt;
}

std::optional<CTxMemPool::txiter> CTxMemPool::GetIter(const Wtxid& wtxid) const
{
    AssertLockHeld(cs);
    auto it{mapTx.project<0>(mapTx.get<index_by_wtxid>().find(wtxid))};
    return it != mapTx.end() ? std::make_optional(it) : std::nullopt;
}

CTxMemPool::setEntries CTxMemPool::GetIterSet(const std::set<Txid>& hashes) const
{
    CTxMemPool::setEntries ret;
    for (const auto& h : hashes) {
        const auto mi = GetIter(h);
        if (mi) ret.insert(*mi);
    }
    return ret;
}

std::vector<CTxMemPool::txiter> CTxMemPool::GetIterVec(const std::vector<Txid>& txids) const
{
    AssertLockHeld(cs);
    std::vector<txiter> ret;
    ret.reserve(txids.size());
    for (const auto& txid : txids) {
        const auto it{GetIter(txid)};
        if (!it) return {};
        ret.push_back(*it);
    }
    return ret;
}

bool CTxMemPool::HasNoInputsOf(const CTransaction &tx) const
{
    for (unsigned int i = 0; i < tx.vin.size(); i++)
        if (exists(tx.vin[i].prevout.hash))
            return false;
    return true;
}

CCoinsViewMemPool::CCoinsViewMemPool(CCoinsView* baseIn, const CTxMemPool& mempoolIn) : CCoinsViewBacked(baseIn), mempool(mempoolIn) { }

std::optional<Coin> CCoinsViewMemPool::GetCoin(const COutPoint& outpoint) const
{
    // Check to see if the inputs are made available by another tx in the package.
    // These Coins would not be available in the underlying CoinsView.
    if (auto it = m_temp_added.find(outpoint); it != m_temp_added.end()) {
        return it->second;
    }

    // If an entry in the mempool exists, always return that one, as it's guaranteed to never
    // conflict with the underlying cache, and it cannot have pruned entries (as it contains full)
    // transactions. First checking the underlying cache risks returning a pruned entry instead.
    CTransactionRef ptx = mempool.get(outpoint.hash);
    if (ptx) {
        if (outpoint.n < ptx->vout.size()) {
            Coin coin(ptx->vout[outpoint.n], MEMPOOL_HEIGHT, false);
            m_non_base_coins.emplace(outpoint);
            return coin;
        }
        return std::nullopt;
    }
    return base->GetCoin(outpoint);
}

void CCoinsViewMemPool::PackageAddTransaction(const CTransactionRef& tx)
{
    for (unsigned int n = 0; n < tx->vout.size(); ++n) {
        m_temp_added.emplace(COutPoint(tx->GetHash(), n), Coin(tx->vout[n], MEMPOOL_HEIGHT, false));
        m_non_base_coins.emplace(tx->GetHash(), n);
    }
}
void CCoinsViewMemPool::Reset()
{
    m_temp_added.clear();
    m_non_base_coins.clear();
}

size_t CTxMemPool::DynamicMemoryUsage() const {
    LOCK(cs);
    // Estimate the overhead of mapTx to be 9 pointers (3 pointers per index) + an allocation, as no exact formula for boost::multi_index_contained is implemented.
    return memusage::MallocUsage(sizeof(CTxMemPoolEntry) + 9 * sizeof(void*)) * mapTx.size() + memusage::DynamicUsage(mapNextTx) + memusage::DynamicUsage(mapDeltas) + memusage::DynamicUsage(txns_randomized) + m_txgraph->GetMainMemoryUsage() + cachedInnerUsage;
}

void CTxMemPool::RemoveUnbroadcastTx(const Txid& txid, const bool unchecked) {
    LOCK(cs);

    if (m_unbroadcast_txids.erase(txid))
    {
        LogDebug(BCLog::MEMPOOL, "Removed %i from set of unbroadcast txns%s\n", txid.GetHex(), (unchecked ? " before confirmation that txn was sent out" : ""));
    }
}

void CTxMemPool::RemoveStaged(setEntries &stage, bool updateDescendants, MemPoolRemovalReason reason) {
    AssertLockHeld(cs);
    for (txiter it : stage) {
        removeUnchecked(it, reason);
    }
}

bool CTxMemPool::CheckPolicyLimits(const CTransactionRef& tx)
{
    LOCK(cs);
    // Use ChangeSet interface to check whether the chain
    // limits would be violated. Note that the changeset will be destroyed
    // when it goes out of scope.
    auto changeset = GetChangeSet();
    (void) changeset->StageAddition(tx, /*fee=*/0, /*time=*/0, /*entry_height=*/0, /*entry_sequence=*/0, /*spends_coinbase=*/false, /*sigops_cost=*/0, LockPoints{});
    return changeset->CheckMemPoolPolicyLimits();
}

int CTxMemPool::Expire(std::chrono::seconds time)
{
    AssertLockHeld(cs);
    Assume(!m_have_changeset);
    indexed_transaction_set::index<entry_time>::type::iterator it = mapTx.get<entry_time>().begin();
    setEntries toremove;
    while (it != mapTx.get<entry_time>().end() && it->GetTime() < time) {
        toremove.insert(mapTx.project<0>(it));
        it++;
    }
    setEntries stage;
    for (txiter removeit : toremove) {
        CalculateDescendants(removeit, stage);
    }
    RemoveStaged(stage, false, MemPoolRemovalReason::EXPIRY);
    return stage.size();
}

CFeeRate CTxMemPool::GetMinFee(size_t sizelimit) const {
    LOCK(cs);
    if (!blockSinceLastRollingFeeBump || rollingMinimumFeeRate == 0)
        return CFeeRate(llround(rollingMinimumFeeRate));

    int64_t time = GetTime();
    if (time > lastRollingFeeUpdate + 10) {
        double halflife = ROLLING_FEE_HALFLIFE;
        if (DynamicMemoryUsage() < sizelimit / 4)
            halflife /= 4;
        else if (DynamicMemoryUsage() < sizelimit / 2)
            halflife /= 2;

        rollingMinimumFeeRate = rollingMinimumFeeRate / pow(2.0, (time - lastRollingFeeUpdate) / halflife);
        lastRollingFeeUpdate = time;

        if (rollingMinimumFeeRate < (double)m_opts.incremental_relay_feerate.GetFeePerK() / 2) {
            rollingMinimumFeeRate = 0;
            return CFeeRate(0);
        }
    }
    return std::max(CFeeRate(llround(rollingMinimumFeeRate)), m_opts.incremental_relay_feerate);
}

void CTxMemPool::trackPackageRemoved(const CFeeRate& rate) {
    AssertLockHeld(cs);
    if (rate.GetFeePerK() > rollingMinimumFeeRate) {
        rollingMinimumFeeRate = rate.GetFeePerK();
        blockSinceLastRollingFeeBump = false;
    }
}

void CTxMemPool::TrimToSize(size_t sizelimit, std::vector<COutPoint>* pvNoSpendsRemaining) {
    AssertLockHeld(cs);
    Assume(!m_have_changeset);

    unsigned nTxnRemoved = 0;
    CFeeRate maxFeeRateRemoved(0);

    while (!mapTx.empty() && DynamicMemoryUsage() > sizelimit) {
        const auto &[worst_chunk, feeperweight] = m_txgraph->GetWorstMainChunk();
        FeePerVSize feerate = ToFeePerVSize(feeperweight);
        CFeeRate removed{feerate.fee, feerate.size};

        // We set the new mempool min fee to the feerate of the removed set, plus the
        // "minimum reasonable fee rate" (ie some value under which we consider txn
        // to have 0 fee). This way, we don't allow txn to enter mempool with feerate
        // equal to txn which were removed with no block in between.
        removed += m_opts.incremental_relay_feerate;
        trackPackageRemoved(removed);
        maxFeeRateRemoved = std::max(maxFeeRateRemoved, removed);

        nTxnRemoved += worst_chunk.size();

        std::vector<CTransaction> txn;
        if (pvNoSpendsRemaining) {
            txn.reserve(worst_chunk.size());
            for (auto ref : worst_chunk) {
                txn.emplace_back(static_cast<const CTxMemPoolEntry&>(*ref).GetTx());
            }
        }

        setEntries stage;
        for (auto ref : worst_chunk) {
            stage.insert(mapTx.iterator_to(static_cast<const CTxMemPoolEntry&>(*ref)));
        }
        for (auto e : stage) {
            removeUnchecked(e, MemPoolRemovalReason::SIZELIMIT);
        }
        if (pvNoSpendsRemaining) {
            for (const CTransaction& tx : txn) {
                for (const CTxIn& txin : tx.vin) {
                    if (exists(txin.prevout.hash)) continue;
                    pvNoSpendsRemaining->push_back(txin.prevout);
                }
            }
        }
    }

    if (maxFeeRateRemoved > CFeeRate(0)) {
        LogDebug(BCLog::MEMPOOL, "Removed %u txn, rolling minimum fee bumped to %s\n", nTxnRemoved, maxFeeRateRemoved.ToString());
    }
}

std::tuple<size_t, size_t, CAmount> CTxMemPool::CalculateAncestorData(const CTxMemPoolEntry& entry) const
{
    auto ancestors = m_txgraph->GetAncestors(entry, TxGraph::Level::MAIN);

    size_t ancestor_count = ancestors.size();
    size_t ancestor_size = 0;
    CAmount ancestor_fees = 0;
    for (auto tx: ancestors) {
        const CTxMemPoolEntry& anc = static_cast<const CTxMemPoolEntry&>(*tx);
        ancestor_size += anc.GetTxSize();
        ancestor_fees += anc.GetModifiedFee();
    }
    return {ancestor_count, ancestor_size, ancestor_fees};
}

std::tuple<size_t, size_t, CAmount> CTxMemPool::CalculateDescendantData(const CTxMemPoolEntry& entry) const
{
    auto descendants = m_txgraph->GetDescendants(entry, TxGraph::Level::MAIN);
    size_t descendant_count = descendants.size();
    size_t descendant_size = 0;
    CAmount descendant_fees = 0;

    for (auto tx: descendants) {
        const CTxMemPoolEntry &desc = static_cast<const CTxMemPoolEntry&>(*tx);
        descendant_size += desc.GetTxSize();
        descendant_fees += desc.GetModifiedFee();
    }
    return {descendant_count, descendant_size, descendant_fees};
}

void CTxMemPool::GetTransactionAncestry(const Txid& txid, size_t& ancestors, size_t& cluster_count, size_t* const ancestorsize, CAmount* const ancestorfees) const {
    LOCK(cs);
    auto it = mapTx.find(txid);
    ancestors = cluster_count = 0;
    if (it != mapTx.end()) {
        auto [ancestor_count, ancestor_size, ancestor_fees] = CalculateAncestorData(*it);
        ancestors = ancestor_count;
        if (ancestorsize) *ancestorsize = ancestor_size;
        if (ancestorfees) *ancestorfees = ancestor_fees;
        cluster_count = m_txgraph->GetCluster(*it, TxGraph::Level::MAIN).size();
    }
}

bool CTxMemPool::GetLoadTried() const
{
    LOCK(cs);
    return m_load_tried;
}

void CTxMemPool::SetLoadTried(bool load_tried)
{
    LOCK(cs);
    m_load_tried = load_tried;
}

std::vector<CTxMemPool::txiter> CTxMemPool::GatherClusters(const std::vector<Txid>& txids) const
{
    AssertLockHeld(cs);

    std::vector<CTxMemPool::txiter> ret;
    std::set<const CTxMemPoolEntry*> unique_cluster_representatives;
    for (auto txid : txids) {
        auto it = mapTx.find(txid);
        if (it != mapTx.end()) {
            auto cluster = m_txgraph->GetCluster(*it, TxGraph::Level::MAIN);
            if (unique_cluster_representatives.insert(static_cast<const CTxMemPoolEntry*>(&(**cluster.begin()))).second) {
                for (auto tx : cluster) {
                    ret.emplace_back(mapTx.iterator_to(static_cast<const CTxMemPoolEntry&>(*tx)));
                }
            }
        }
    }
    if (ret.size() > 500) {
        return {};
    }
    return ret;
}

util::Result<std::pair<std::vector<FeeFrac>, std::vector<FeeFrac>>> CTxMemPool::ChangeSet::CalculateChunksForRBF()
{
    LOCK(m_pool->cs);

    if (!CheckMemPoolPolicyLimits()) {
        return util::Error{Untranslated("cluster size limit exceeded")};
    }

    return m_pool->m_txgraph->GetMainStagingDiagrams();
}

CTxMemPool::ChangeSet::TxHandle CTxMemPool::ChangeSet::StageAddition(const CTransactionRef& tx, const CAmount fee, int64_t time, unsigned int entry_height, uint64_t entry_sequence, bool spends_coinbase, int64_t sigops_cost, LockPoints lp)
{
    LOCK(m_pool->cs);
    Assume(m_to_add.find(tx->GetHash()) == m_to_add.end());
    Assume(!m_dependencies_processed);

    // We need to process dependencies after adding a new transaction.
    m_dependencies_processed = false;

    CAmount delta{0};
    m_pool->ApplyDelta(tx->GetHash(), delta);

    TxGraph::Ref ref(m_pool->m_txgraph->AddTransaction(FeePerWeight(fee, GetSigOpsAdjustedWeight(GetTransactionWeight(*tx), sigops_cost, ::nBytesPerSigOp))));
    auto newit = m_to_add.emplace(std::move(ref), tx, fee, time, entry_height, entry_sequence, spends_coinbase, sigops_cost, lp).first;
    if (delta) {
        m_to_add.modify(newit, [&delta](CTxMemPoolEntry& e) { e.UpdateModifiedFee(delta); });
        m_pool->m_txgraph->SetTransactionFee(*newit, newit->GetModifiedFee());
    }

    m_entry_vec.push_back(newit);

    return newit;
}

void CTxMemPool::ChangeSet::StageRemoval(CTxMemPool::txiter it)
{
    LOCK(m_pool->cs);
    m_pool->m_txgraph->RemoveTransaction(*it);
    m_to_remove.insert(it);
}

void CTxMemPool::ChangeSet::Apply()
{
    LOCK(m_pool->cs);
    if (!m_dependencies_processed) {
        ProcessDependencies();
    }
    m_pool->Apply(this);
    m_to_add.clear();
    m_to_remove.clear();
    m_entry_vec.clear();
    m_ancestors.clear();
}

void CTxMemPool::ChangeSet::ProcessDependencies()
{
    LOCK(m_pool->cs);
    Assume(!m_dependencies_processed); // should only call this once.
    for (const auto& entryptr : m_entry_vec) {
        for (const auto &txin : entryptr->GetSharedTx()->vin) {
            std::optional<txiter> piter = m_pool->GetIter(txin.prevout.hash);
            if (!piter) {
                auto it = m_to_add.find(txin.prevout.hash);
                if (it != m_to_add.end()) {
                    piter = std::make_optional(it);
                }
            }
            if (piter) {
                m_pool->m_txgraph->AddDependency(/*parent=*/**piter, /*child=*/*entryptr);
            }
        }
    }
    m_dependencies_processed = true;
    return;
 }

bool CTxMemPool::ChangeSet::CheckMemPoolPolicyLimits()
{
    LOCK(m_pool->cs);
    if (!m_dependencies_processed) {
        ProcessDependencies();
    }

    return !m_pool->m_txgraph->IsOversized(TxGraph::Level::TOP);
}

std::vector<FeePerWeight> CTxMemPool::GetFeerateDiagram() const
{
    FeePerWeight zero{};
    std::vector<FeePerWeight> ret;

    ret.emplace_back(zero);

    StartBlockBuilding();

    std::vector<CTxMemPoolEntry::CTxMemPoolEntryRef> dummy;

    FeePerWeight last_selection = GetBlockBuilderChunk(dummy);
    while (last_selection != FeePerWeight{}) {
        last_selection += ret.back();
        ret.emplace_back(last_selection);
        IncludeBuilderChunk();
        last_selection = GetBlockBuilderChunk(dummy);
    }
    StopBlockBuilding();
    return ret;
}

static void LimitMempoolSize(CTxMemPool& pool, CCoinsViewCache& coins_cache)
    EXCLUSIVE_LOCKS_REQUIRED(::cs_main, pool.cs)
{
    AssertLockHeld(::cs_main);
    AssertLockHeld(pool.cs);
    int expired = pool.Expire(GetTime<std::chrono::seconds>() - pool.m_opts.expiry);
    if (expired != 0) {
        LogDebug(BCLog::MEMPOOL, "Expired %i transactions from the memory pool\n", expired);
    }

    std::vector<COutPoint> vNoSpendsRemaining;
    pool.TrimToSize(pool.m_opts.max_size_bytes, &vNoSpendsRemaining);
    for (const COutPoint& removed : vNoSpendsRemaining)
        coins_cache.Uncache(removed);
}

static bool IsCurrentForFeeEstimation(Chainstate& active_chainstate) EXCLUSIVE_LOCKS_REQUIRED(cs_main)
{
    AssertLockHeld(cs_main);
    if (active_chainstate.m_chainman.IsInitialBlockDownload()) {
        return false;
    }
    if (active_chainstate.m_chain.Tip()->GetBlockTime() < count_seconds(GetTime<std::chrono::seconds>() - MAX_FEE_ESTIMATION_TIP_AGE))
        return false;
    if (active_chainstate.m_chain.Height() < active_chainstate.m_chainman.m_best_header->nHeight - 1) {
        return false;
    }
    return true;
}

void CTxMemPool::MaybeUpdateMempoolForReorg(
    Chainstate& active_chainstate,
    DisconnectedBlockTransactions& disconnectpool,
    bool fAddToMempool)
{
    AssertLockHeld(cs_main);
    AssertLockHeld(cs);
    std::vector<Txid> vHashUpdate;
    {
        // disconnectpool is ordered so that the front is the most recently-confirmed
        // transaction (the last tx of the block at the tip) in the disconnected chain.
        // Iterate disconnectpool in reverse, so that we add transactions
        // back to the mempool starting with the earliest transaction that had
        // been previously seen in a block.
        const auto queuedTx = disconnectpool.take();
        auto it = queuedTx.rbegin();
        while (it != queuedTx.rend()) {
            // ignore validation errors in resurrected transactions
            if (!fAddToMempool || (*it)->IsCoinBase() ||
                AcceptToMemoryPool(active_chainstate, *it, *this, GetTime(),
                    /*bypass_limits=*/true, /*test_accept=*/false).m_result_type !=
                        MempoolAcceptResult::ResultType::VALID) {
                // If the transaction doesn't make it in to the mempool, remove any
                // transactions that depend on it (which would now be orphans).
                removeRecursive(**it, MemPoolRemovalReason::REORG);
            } else if (exists((*it)->GetHash())) {
                vHashUpdate.push_back((*it)->GetHash());
            }
            ++it;
        }
    }

    // AcceptToMemoryPool/addNewTransaction all assume that new mempool entries have
    // no in-mempool children, which is generally not true when adding
    // previously-confirmed transactions back to the mempool.
    // UpdateTransactionsFromBlock finds descendants of any transactions in
    // the disconnectpool that were added back and cleans up the mempool state.
    UpdateTransactionsFromBlock(vHashUpdate);

    // Predicate to use for filtering transactions in removeForReorg.
    // Checks whether the transaction is still final and, if it spends a coinbase output, mature.
    // Also updates valid entries' cached LockPoints if needed.
    // If false, the tx is still valid and its lockpoints are updated.
    // If true, the tx would be invalid in the next block; remove this entry and all of its descendants.
    // Note that TRUC rules are not applied here, so reorgs may cause violations of TRUC inheritance or
    // topology restrictions.
    const auto filter_final_and_mature = [&](CTxMemPool::txiter it)
        EXCLUSIVE_LOCKS_REQUIRED(cs, ::cs_main) {
        AssertLockHeld(cs);
        AssertLockHeld(::cs_main);
        const CTransaction& tx = it->GetTx();

        // The transaction must be final.
        if (!CheckFinalTxAtTip(*Assert(active_chainstate.m_chain.Tip()), tx)) return true;

        const LockPoints& lp = it->GetLockPoints();
        // CheckSequenceLocksAtTip checks if the transaction will be final in the next block to be
        // created on top of the new chain.
        if (TestLockPointValidity(active_chainstate.m_chain, lp)) {
            if (!CheckSequenceLocksAtTip(active_chainstate.m_chain.Tip(), lp)) {
                return true;
            }
        } else {
            const CCoinsViewMemPool view_mempool{&active_chainstate.CoinsTip(), *this};
            const std::optional<LockPoints> new_lock_points{CalculateLockPointsAtTip(active_chainstate.m_chain.Tip(), view_mempool, tx)};
            if (new_lock_points.has_value() && CheckSequenceLocksAtTip(active_chainstate.m_chain.Tip(), *new_lock_points)) {
                // Now update the mempool entry lockpoints as well.
                it->UpdateLockPoints(*new_lock_points);
            } else {
                return true;
            }
        }

        // If the transaction spends any coinbase outputs, it must be mature.
        if (it->GetSpendsCoinbase()) {
            for (const CTxIn& txin : tx.vin) {
                if (exists(txin.prevout.hash)) continue;
                const Coin& coin{active_chainstate.CoinsTip().AccessCoin(txin.prevout)};
                assert(!coin.IsSpent());
                const auto mempool_spend_height{active_chainstate.m_chain.Tip()->nHeight + 1};
                if (coin.IsCoinBase() && mempool_spend_height - coin.nHeight < COINBASE_MATURITY) {
                    return true;
                }
            }
        }
        // Transaction is still valid and cached LockPoints are updated.
        return false;
    };

    // We also need to remove any now-immature transactions
    removeForReorg(active_chainstate.m_chain, filter_final_and_mature);
    // Re-limit mempool size, in case we added any transactions
    LimitMempoolSize(*this, active_chainstate.CoinsTip());
}

/**
* Checks to avoid mempool polluting consensus critical paths since cached
* signature and script validity results will be reused if we validate this
* transaction again during block validation.
* */
static bool CheckInputsFromMempoolAndCache(const CTransaction& tx, TxValidationState& state,
                const CCoinsViewCache& view, const CTxMemPool& pool,
                script_verify_flags flags, PrecomputedTransactionData& txdata, CCoinsViewCache& coins_tip,
                ValidationCache& validation_cache)
                EXCLUSIVE_LOCKS_REQUIRED(cs_main, pool.cs)
{
    AssertLockHeld(cs_main);
    AssertLockHeld(pool.cs);

    assert(!tx.IsCoinBase());
    for (const CTxIn& txin : tx.vin) {
        const Coin& coin = view.AccessCoin(txin.prevout);

        // This coin was checked in PreChecks and MemPoolAccept
        // has been holding cs_main since then.
        Assume(!coin.IsSpent());
        if (coin.IsSpent()) return false;

        // If the Coin is available, there are 2 possibilities:
        // it is available in our current ChainstateActive UTXO set,
        // or it's a UTXO provided by a transaction in our mempool.
        // Ensure the scriptPubKeys in Coins from CoinsView are correct.
        const CTransactionRef& txFrom = pool.get(txin.prevout.hash);
        if (txFrom) {
            assert(txFrom->GetHash() == txin.prevout.hash);
            assert(txFrom->vout.size() > txin.prevout.n);
            assert(txFrom->vout[txin.prevout.n] == coin.out);
        } else {
            const Coin& coinFromUTXOSet = coins_tip.AccessCoin(txin.prevout);
            assert(!coinFromUTXOSet.IsSpent());
            assert(coinFromUTXOSet.out == coin.out);
        }
    }

    // Call CheckInputScripts() to cache signature and script validity against current tip consensus rules.
    return CheckInputScripts(tx, state, view, flags, /* cacheSigStore= */ true, /* cacheFullScriptStore= */ true, txdata, validation_cache);
}

namespace {

class MemPoolAccept
{
public:
    explicit MemPoolAccept(CTxMemPool& mempool, Chainstate& active_chainstate) :
        m_pool(mempool),
        m_view(&m_dummy),
        m_viewmempool(&active_chainstate.CoinsTip(), m_pool),
        m_active_chainstate(active_chainstate)
    {
    }

    // We put the arguments we're handed into a struct, so we can pass them
    // around easier.
    struct ATMPArgs {
        const CChainParams& m_chainparams;
        const int64_t m_accept_time;
        const bool m_bypass_limits;
        /*
         * Return any outpoints which were not previously present in the coins
         * cache, but were added as a result of validating the tx for mempool
         * acceptance. This allows the caller to optionally remove the cache
         * additions if the associated transaction ends up being rejected by
         * the mempool.
         */
        std::vector<COutPoint>& m_coins_to_uncache;
        /** When true, the transaction or package will not be submitted to the mempool. */
        const bool m_test_accept;
        /** Whether we allow transactions to replace mempool transactions. If false,
         * any transaction spending the same inputs as a transaction in the mempool is considered
         * a conflict. */
        const bool m_allow_replacement;
        /** When true, allow sibling eviction. This only occurs in single transaction package settings. */
        const bool m_allow_sibling_eviction;
        /** Used to skip the LimitMempoolSize() call within AcceptSingleTransaction(). This should be used when multiple
         * AcceptSubPackage calls are expected and the mempool will be trimmed at the end of AcceptPackage(). */
        const bool m_package_submission;
        /** When true, use package feerates instead of individual transaction feerates for fee-based
         * policies such as mempool min fee and min relay fee.
         */
        const bool m_package_feerates;
        /** Used for local submission of transactions to catch "absurd" fees
         * due to fee miscalculation by wallets. std:nullopt implies unset, allowing any feerates.
         * Any individual transaction failing this check causes immediate failure.
         */
        const std::optional<CFeeRate> m_client_maxfeerate;

        /** Parameters for single transaction mempool validation. */
        static ATMPArgs SingleAccept(const CChainParams& chainparams, int64_t accept_time,
                                     bool bypass_limits, std::vector<COutPoint>& coins_to_uncache,
                                     bool test_accept) {
            return ATMPArgs{/* m_chainparams */ chainparams,
                            /* m_accept_time */ accept_time,
                            /* m_bypass_limits */ bypass_limits,
                            /* m_coins_to_uncache */ coins_to_uncache,
                            /* m_test_accept */ test_accept,
                            /* m_allow_replacement */ true,
                            /* m_allow_sibling_eviction */ true,
                            /* m_package_submission */ false,
                            /* m_package_feerates */ false,
                            /* m_client_maxfeerate */ {}, // checked by caller
            };
        }

        /** Parameters for test package mempool validation through testmempoolaccept. */
        static ATMPArgs PackageTestAccept(const CChainParams& chainparams, int64_t accept_time,
                                          std::vector<COutPoint>& coins_to_uncache) {
            return ATMPArgs{/* m_chainparams */ chainparams,
                            /* m_accept_time */ accept_time,
                            /* m_bypass_limits */ false,
                            /* m_coins_to_uncache */ coins_to_uncache,
                            /* m_test_accept */ true,
                            /* m_allow_replacement */ false,
                            /* m_allow_sibling_eviction */ false,
                            /* m_package_submission */ false, // not submitting to mempool
                            /* m_package_feerates */ false,
                            /* m_client_maxfeerate */ {}, // checked by caller
            };
        }

        /** Parameters for child-with-parents package validation. */
        static ATMPArgs PackageChildWithParents(const CChainParams& chainparams, int64_t accept_time,
                                                std::vector<COutPoint>& coins_to_uncache, const std::optional<CFeeRate>& client_maxfeerate) {
            return ATMPArgs{/* m_chainparams */ chainparams,
                            /* m_accept_time */ accept_time,
                            /* m_bypass_limits */ false,
                            /* m_coins_to_uncache */ coins_to_uncache,
                            /* m_test_accept */ false,
                            /* m_allow_replacement */ true,
                            /* m_allow_sibling_eviction */ false,
                            /* m_package_submission */ true,
                            /* m_package_feerates */ true,
                            /* m_client_maxfeerate */ client_maxfeerate,
            };
        }

        /** Parameters for a single transaction within a package. */
        static ATMPArgs SingleInPackageAccept(const ATMPArgs& package_args) {
            return ATMPArgs{/* m_chainparams */ package_args.m_chainparams,
                            /* m_accept_time */ package_args.m_accept_time,
                            /* m_bypass_limits */ false,
                            /* m_coins_to_uncache */ package_args.m_coins_to_uncache,
                            /* m_test_accept */ package_args.m_test_accept,
                            /* m_allow_replacement */ true,
                            /* m_allow_sibling_eviction */ true,
                            /* m_package_submission */ true, // trim at the end of AcceptPackage()
                            /* m_package_feerates */ false, // only 1 transaction
                            /* m_client_maxfeerate */ package_args.m_client_maxfeerate,
            };
        }

    private:
        // Private ctor to avoid exposing details to clients and allowing the possibility of
        // mixing up the order of the arguments. Use static functions above instead.
        ATMPArgs(const CChainParams& chainparams,
                 int64_t accept_time,
                 bool bypass_limits,
                 std::vector<COutPoint>& coins_to_uncache,
                 bool test_accept,
                 bool allow_replacement,
                 bool allow_sibling_eviction,
                 bool package_submission,
                 bool package_feerates,
                 std::optional<CFeeRate> client_maxfeerate)
            : m_chainparams{chainparams},
              m_accept_time{accept_time},
              m_bypass_limits{bypass_limits},
              m_coins_to_uncache{coins_to_uncache},
              m_test_accept{test_accept},
              m_allow_replacement{allow_replacement},
              m_allow_sibling_eviction{allow_sibling_eviction},
              m_package_submission{package_submission},
              m_package_feerates{package_feerates},
              m_client_maxfeerate{client_maxfeerate}
        {
            // If we are using package feerates, we must be doing package submission.
            // It also means sibling eviction is not permitted.
            if (m_package_feerates) {
                Assume(m_package_submission);
                Assume(!m_allow_sibling_eviction);
            }
            if (m_allow_sibling_eviction) Assume(m_allow_replacement);
        }
    };

    /** Clean up all non-chainstate coins from m_view and m_viewmempool. */
    void CleanupTemporaryCoins() EXCLUSIVE_LOCKS_REQUIRED(cs_main, m_pool.cs);

    // Single transaction acceptance
    MempoolAcceptResult AcceptSingleTransactionAndCleanup(const CTransactionRef& ptx, ATMPArgs& args) EXCLUSIVE_LOCKS_REQUIRED(cs_main) {
        LOCK(m_pool.cs);
        MempoolAcceptResult result = AcceptSingleTransactionInternal(ptx, args);
        ClearSubPackageState();
        return result;
    }
    MempoolAcceptResult AcceptSingleTransactionInternal(const CTransactionRef& ptx, ATMPArgs& args) EXCLUSIVE_LOCKS_REQUIRED(cs_main, m_pool.cs);

    /**
    * Multiple transaction acceptance. Transactions may or may not be interdependent, but must not
    * conflict with each other, and the transactions cannot already be in the mempool. Parents must
    * come before children if any dependencies exist.
    */
    PackageMempoolAcceptResult AcceptMultipleTransactionsAndCleanup(const std::vector<CTransactionRef>& txns, ATMPArgs& args) EXCLUSIVE_LOCKS_REQUIRED(cs_main) {
        LOCK(m_pool.cs);
        PackageMempoolAcceptResult result = AcceptMultipleTransactionsInternal(txns, args);
        ClearSubPackageState();
        return result;
    }
    PackageMempoolAcceptResult AcceptMultipleTransactionsInternal(const std::vector<CTransactionRef>& txns, ATMPArgs& args) EXCLUSIVE_LOCKS_REQUIRED(cs_main, m_pool.cs);

    /**
     * Submission of a subpackage.
     * If subpackage size == 1, calls AcceptSingleTransaction() with adjusted ATMPArgs to
     * enable sibling eviction and creates a PackageMempoolAcceptResult
     * wrapping the result.
     *
     * If subpackage size > 1, calls AcceptMultipleTransactions() with the provided ATMPArgs.
     *
     * Also cleans up all non-chainstate coins from m_view at the end.
    */
    PackageMempoolAcceptResult AcceptSubPackage(const std::vector<CTransactionRef>& subpackage, ATMPArgs& args)
        EXCLUSIVE_LOCKS_REQUIRED(cs_main, m_pool.cs);

    /**
     * Package (more specific than just multiple transactions) acceptance. Package must be a child
     * with all of its unconfirmed parents, and topologically sorted.
     */
    PackageMempoolAcceptResult AcceptPackage(const Package& package, ATMPArgs& args) EXCLUSIVE_LOCKS_REQUIRED(cs_main);

private:
    // All the intermediate state that gets passed between the various levels
    // of checking a given transaction.
    struct Workspace {
        explicit Workspace(const CTransactionRef& ptx) : m_ptx(ptx), m_hash(ptx->GetHash()) {}
        /** Txids of mempool transactions that this transaction directly conflicts with or may
         * replace via sibling eviction. */
        std::set<Txid> m_conflicts;
        /** Iterators to mempool entries that this transaction directly conflicts with or may
         * replace via sibling eviction. */
        CTxMemPool::setEntries m_iters_conflicting;
        /** All mempool parents of this transaction. */
        std::vector<CTxMemPoolEntry::CTxMemPoolEntryRef> m_parents;
        /* Handle to the tx in the changeset */
        CTxMemPool::ChangeSet::TxHandle m_tx_handle;
        /** Whether RBF-related data structures (m_conflicts, m_iters_conflicting,
         * m_replaced_transactions) include a sibling in addition to txns with conflicting inputs. */
        bool m_sibling_eviction{false};

        /** Virtual size of the transaction as used by the mempool, calculated using serialized size
         * of the transaction and sigops. */
        int64_t m_vsize;
        /** Fees paid by this transaction: total input amounts subtracted by total output amounts. */
        CAmount m_base_fees;
        /** Base fees + any fee delta set by the user with prioritisetransaction. */
        CAmount m_modified_fees;

        /** If we're doing package validation (i.e. m_package_feerates=true), the "effective"
         * package feerate of this transaction is the total fees divided by the total size of
         * transactions (which may include its ancestors and/or descendants). */
        CFeeRate m_package_feerate{0};

        const CTransactionRef& m_ptx;
        /** Txid. */
        const Txid& m_hash;
        TxValidationState m_state;
        /** A temporary cache containing serialized transaction data for signature verification.
         * Reused across PolicyScriptChecks and ConsensusScriptChecks. */
        PrecomputedTransactionData m_precomputed_txdata;
    };

    // Run the policy checks on a given transaction, excluding any script checks.
    // Looks up inputs, calculates feerate, considers replacement, evaluates
    // package limits, etc. As this function can be invoked for "free" by a peer,
    // only tests that are fast should be done here (to avoid CPU DoS).
    bool PreChecks(ATMPArgs& args, Workspace& ws) EXCLUSIVE_LOCKS_REQUIRED(cs_main, m_pool.cs);

    // Run checks for mempool replace-by-fee, only used in AcceptSingleTransaction.
    bool ReplacementChecks(Workspace& ws) EXCLUSIVE_LOCKS_REQUIRED(cs_main, m_pool.cs);

    // Enforce package mempool ancestor/descendant limits (distinct from individual
    // ancestor/descendant limits done in PreChecks) and run Package RBF checks.
    bool PackageMempoolChecks(const std::vector<CTransactionRef>& txns,
                              std::vector<Workspace>& workspaces,
                              int64_t total_vsize,
                              PackageValidationState& package_state) EXCLUSIVE_LOCKS_REQUIRED(cs_main, m_pool.cs);

    // Run the script checks using our policy flags. As this can be slow, we should
    // only invoke this on transactions that have otherwise passed policy checks.
    bool PolicyScriptChecks(const ATMPArgs& args, Workspace& ws) EXCLUSIVE_LOCKS_REQUIRED(cs_main, m_pool.cs);

    // Re-run the script checks, using consensus flags, and try to cache the
    // result in the scriptcache. This should be done after
    // PolicyScriptChecks(). This requires that all inputs either be in our
    // utxo set or in the mempool.
    bool ConsensusScriptChecks(const ATMPArgs& args, Workspace& ws) EXCLUSIVE_LOCKS_REQUIRED(cs_main, m_pool.cs);

    // Try to add the transaction to the mempool, removing any conflicts first.
    void FinalizeSubpackage(const ATMPArgs& args) EXCLUSIVE_LOCKS_REQUIRED(cs_main, m_pool.cs);

    // Submit all transactions to the mempool and call ConsensusScriptChecks to add to the script
    // cache - should only be called after successful validation of all transactions in the package.
    // Does not call LimitMempoolSize(), so mempool max_size_bytes may be temporarily exceeded.
    bool SubmitPackage(const ATMPArgs& args, std::vector<Workspace>& workspaces, PackageValidationState& package_state,
                       std::map<Wtxid, MempoolAcceptResult>& results)
         EXCLUSIVE_LOCKS_REQUIRED(cs_main, m_pool.cs);

    // Compare a package's feerate against minimum allowed.
    bool CheckFeeRate(size_t package_size, CAmount package_fee, TxValidationState& state) EXCLUSIVE_LOCKS_REQUIRED(::cs_main, m_pool.cs)
    {
        AssertLockHeld(::cs_main);
        AssertLockHeld(m_pool.cs);
        CAmount mempoolRejectFee = m_pool.GetMinFee().GetFee(package_size);
        if (mempoolRejectFee > 0 && package_fee < mempoolRejectFee) {
            return state.Invalid(TxValidationResult::TX_RECONSIDERABLE, "mempool min fee not met", strprintf("%d < %d", package_fee, mempoolRejectFee));
        }

        if (package_fee < m_pool.m_opts.min_relay_feerate.GetFee(package_size)) {
            return state.Invalid(TxValidationResult::TX_RECONSIDERABLE, "min relay fee not met",
                                 strprintf("%d < %d", package_fee, m_pool.m_opts.min_relay_feerate.GetFee(package_size)));
        }
        return true;
    }

    ValidationCache& GetValidationCache()
    {
        return m_active_chainstate.m_chainman.m_validation_cache;
    }

private:
    CTxMemPool& m_pool;

    /** Holds a cached view of available coins from the UTXO set, mempool, and artificial temporary coins (to enable package validation).
     * The view doesn't track whether a coin previously existed but has now been spent. We detect conflicts in other ways:
     * - conflicts within a transaction are checked in CheckTransaction (bad-txns-inputs-duplicate)
     * - conflicts within a package are checked in IsWellFormedPackage (conflict-in-package)
     * - conflicts with an existing mempool transaction are found in CTxMemPool::GetConflictTx and replacements are allowed
     * The temporary coins should persist between individual transaction checks so that package validation is possible,
     * but must be cleaned up when we finish validating a subpackage, whether accepted or rejected. The cache must also
     * be cleared when mempool contents change (when a changeset is applied or when the mempool trims itself) because it
     * can return cached coins that no longer exist in the backend. Use CleanupTemporaryCoins() anytime you are finished
     * with a SubPackageState or call LimitMempoolSize().
     */
    CCoinsViewCache m_view;

    // These are the two possible backends for m_view.
    /** When m_view is connected to m_viewmempool as its backend, it can pull coins from the mempool and from the UTXO
     * set. This is also where temporary coins are stored. */
    CCoinsViewMemPool m_viewmempool;
    /** When m_view is connected to m_dummy, it can no longer look up coins from the mempool or UTXO set (meaning no disk
     * operations happen), but can still return coins it accessed previously. Useful for keeping track of which coins
     * were pulled from disk. */
    CCoinsView m_dummy;

    Chainstate& m_active_chainstate;

    // Fields below are per *sub*package state and must be reset prior to subsequent
    // AcceptSingleTransaction and AcceptMultipleTransactions invocations
    struct SubPackageState {
        /** Aggregated modified fees of all transactions, used to calculate package feerate. */
        CAmount m_total_modified_fees{0};
        /** Aggregated virtual size of all transactions, used to calculate package feerate. */
        int64_t m_total_vsize{0};

        // RBF-related members
        /** Whether the transaction(s) would replace any mempool transactions and/or evict any siblings.
         * If so, RBF rules apply. */
        bool m_rbf{false};
        /** Mempool transactions that were replaced. */
        std::list<CTransactionRef> m_replaced_transactions;
        /* Changeset representing adding transactions and removing their conflicts. */
        std::unique_ptr<CTxMemPool::ChangeSet> m_changeset;

        /** Total modified fees of mempool transactions being replaced. */
        CAmount m_conflicting_fees{0};
        /** Total size (in virtual bytes) of mempool transactions being replaced. */
        size_t m_conflicting_size{0};
    };

    struct SubPackageState m_subpackage;

    /** Re-set sub-package state to not leak between evaluations */
    void ClearSubPackageState() EXCLUSIVE_LOCKS_REQUIRED(cs_main, m_pool.cs)
    {
        m_subpackage = SubPackageState{};

        // And clean coins while at it
        CleanupTemporaryCoins();
    }
};

bool MemPoolAccept::PreChecks(ATMPArgs& args, Workspace& ws)
{
    AssertLockHeld(cs_main);
    AssertLockHeld(m_pool.cs);
    const CTransactionRef& ptx = ws.m_ptx;
    const CTransaction& tx = *ws.m_ptx;
    const Txid& hash = ws.m_hash;

    // Copy/alias what we need out of args
    const int64_t nAcceptTime = args.m_accept_time;
    const bool bypass_limits = args.m_bypass_limits;
    std::vector<COutPoint>& coins_to_uncache = args.m_coins_to_uncache;

    // Alias what we need out of ws
    TxValidationState& state = ws.m_state;

    if (!CheckTransaction(tx, state)) {
        return false; // state filled in by CheckTransaction
    }

    // Coinbase is only valid in a block, not as a loose transaction
    if (tx.IsCoinBase())
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "coinbase");

    // Rather not work on nonstandard transactions (unless -testnet/-regtest)
    std::string reason;
    if (m_pool.m_opts.require_standard && !IsStandardTx(tx, m_pool.m_opts.max_datacarrier_bytes, m_pool.m_opts.permit_bare_multisig, m_pool.m_opts.dust_relay_feerate, reason)) {
        return state.Invalid(TxValidationResult::TX_NOT_STANDARD, reason);
    }

    // Transactions smaller than 65 non-witness bytes are not relayed to mitigate CVE-2017-12842.
    if (::GetSerializeSize(TX_NO_WITNESS(tx)) < MIN_STANDARD_TX_NONWITNESS_SIZE)
        return state.Invalid(TxValidationResult::TX_NOT_STANDARD, "tx-size-small");

    // Only accept nLockTime-using transactions that can be mined in the next
    // block; we don't want our mempool filled up with transactions that can't
    // be mined yet.
    if (!CheckFinalTxAtTip(*Assert(m_active_chainstate.m_chain.Tip()), tx)) {
        return state.Invalid(TxValidationResult::TX_PREMATURE_SPEND, "non-final");
    }

    if (m_pool.exists(tx.GetWitnessHash())) {
        // Exact transaction already exists in the mempool.
        return state.Invalid(TxValidationResult::TX_CONFLICT, "txn-already-in-mempool");
    } else if (m_pool.exists(tx.GetHash())) {
        // Transaction with the same non-witness data but different witness (same txid, different
        // wtxid) already exists in the mempool.
        return state.Invalid(TxValidationResult::TX_CONFLICT, "txn-same-nonwitness-data-in-mempool");
    }

    // Check for conflicts with in-memory transactions
    for (const CTxIn &txin : tx.vin)
    {
        const CTransaction* ptxConflicting = m_pool.GetConflictTx(txin.prevout);
        if (ptxConflicting) {
            if (!args.m_allow_replacement) {
                // Transaction conflicts with a mempool tx, but we're not allowing replacements in this context.
                return state.Invalid(TxValidationResult::TX_MEMPOOL_POLICY, "bip125-replacement-disallowed");
            }
            ws.m_conflicts.insert(ptxConflicting->GetHash());
        }
    }

    m_view.SetBackend(m_viewmempool);

    const CCoinsViewCache& coins_cache = m_active_chainstate.CoinsTip();
    // do all inputs exist?
    for (const CTxIn& txin : tx.vin) {
        if (!coins_cache.HaveCoinInCache(txin.prevout)) {
            coins_to_uncache.push_back(txin.prevout);
        }

        // Note: this call may add txin.prevout to the coins cache
        // (coins_cache.cacheCoins) by way of FetchCoin(). It should be removed
        // later (via coins_to_uncache) if this tx turns out to be invalid.
        if (!m_view.HaveCoin(txin.prevout)) {
            // Are inputs missing because we already have the tx?
            for (size_t out = 0; out < tx.vout.size(); out++) {
                // Optimistically just do efficient check of cache for outputs
                if (coins_cache.HaveCoinInCache(COutPoint(hash, out))) {
                    return state.Invalid(TxValidationResult::TX_CONFLICT, "txn-already-known");
                }
            }
            // Otherwise assume this might be an orphan tx for which we just haven't seen parents yet
            return state.Invalid(TxValidationResult::TX_MISSING_INPUTS, "bad-txns-inputs-missingorspent");
        }
    }

    // This is const, but calls into the back end CoinsViews. The CCoinsViewDB at the bottom of the
    // hierarchy brings the best block into scope. See CCoinsViewDB::GetBestBlock().
    m_view.GetBestBlock();

    // we have all inputs cached now, so switch back to dummy (to protect
    // against bugs where we pull more inputs from disk that miss being added
    // to coins_to_uncache)
    m_view.SetBackend(m_dummy);

    assert(m_active_chainstate.m_blockman.LookupBlockIndex(m_view.GetBestBlock()) == m_active_chainstate.m_chain.Tip());

    // Only accept BIP68 sequence locked transactions that can be mined in the next
    // block; we don't want our mempool filled up with transactions that can't
    // be mined yet.
    // Pass in m_view which has all of the relevant inputs cached. Note that, since m_view's
    // backend was removed, it no longer pulls coins from the mempool.
    const std::optional<LockPoints> lock_points{CalculateLockPointsAtTip(m_active_chainstate.m_chain.Tip(), m_view, tx)};
    if (!lock_points.has_value() || !CheckSequenceLocksAtTip(m_active_chainstate.m_chain.Tip(), *lock_points)) {
        return state.Invalid(TxValidationResult::TX_PREMATURE_SPEND, "non-BIP68-final");
    }

    // The mempool holds txs for the next block, so pass height+1 to CheckTxInputs
    if (!Consensus::CheckTxInputs(tx, state, m_view, m_active_chainstate.m_chain.Height() + 1, ws.m_base_fees)) {
        return false; // state filled in by CheckTxInputs
    }

    if (m_pool.m_opts.require_standard && !AreInputsStandard(tx, m_view)) {
        return state.Invalid(TxValidationResult::TX_INPUTS_NOT_STANDARD, "bad-txns-nonstandard-inputs");
    }

    // Check for non-standard witnesses.
    if (tx.HasWitness() && m_pool.m_opts.require_standard && !IsWitnessStandard(tx, m_view)) {
        return state.Invalid(TxValidationResult::TX_WITNESS_MUTATED, "bad-witness-nonstandard");
    }

    int64_t nSigOpsCost = GetTransactionSigOpCost(tx, m_view, STANDARD_SCRIPT_VERIFY_FLAGS);

    // Keep track of transactions that spend a coinbase, which we re-scan
    // during reorgs to ensure COINBASE_MATURITY is still met.
    bool fSpendsCoinbase = false;
    for (const CTxIn &txin : tx.vin) {
        const Coin &coin = m_view.AccessCoin(txin.prevout);
        if (coin.IsCoinBase()) {
            fSpendsCoinbase = true;
            break;
        }
    }

    // Set entry_sequence to 0 when bypass_limits is used; this allows txs from a block
    // reorg to be marked earlier than any child txs that were already in the mempool.
    const uint64_t entry_sequence = bypass_limits ? 0 : m_pool.GetSequence();
    if (!m_subpackage.m_changeset) {
        m_subpackage.m_changeset = m_pool.GetChangeSet();
    }
    ws.m_tx_handle = m_subpackage.m_changeset->StageAddition(ptx, ws.m_base_fees, nAcceptTime, m_active_chainstate.m_chain.Height(), entry_sequence, fSpendsCoinbase, nSigOpsCost, lock_points.value());

    // ws.m_modified_fees includes any fee deltas from PrioritiseTransaction
    ws.m_modified_fees = ws.m_tx_handle->GetModifiedFee();

    ws.m_vsize = ws.m_tx_handle->GetTxSize();

    // Enforces 0-fee for dust transactions, no incentive to be mined alone
    if (m_pool.m_opts.require_standard) {
        if (!PreCheckEphemeralTx(*ptx, m_pool.m_opts.dust_relay_feerate, ws.m_base_fees, ws.m_modified_fees, state)) {
            return false; // state filled in by PreCheckEphemeralTx
        }
    }

    if (nSigOpsCost > MAX_STANDARD_TX_SIGOPS_COST)
        return state.Invalid(TxValidationResult::TX_NOT_STANDARD, "bad-txns-too-many-sigops",
                strprintf("%d", nSigOpsCost));

    // No individual transactions are allowed below the min relay feerate except from disconnected blocks.
    // This requirement, unlike CheckFeeRate, cannot be bypassed using m_package_feerates because,
    // while a tx could be package CPFP'd when entering the mempool, we do not have a DoS-resistant
    // method of ensuring the tx remains bumped. For example, the fee-bumping child could disappear
    // due to a replacement.
    // The only exception is TRUC transactions.
    if (!bypass_limits && ws.m_ptx->version != TRUC_VERSION && ws.m_modified_fees < m_pool.m_opts.min_relay_feerate.GetFee(ws.m_vsize)) {
        // Even though this is a fee-related failure, this result is TX_MEMPOOL_POLICY, not
        // TX_RECONSIDERABLE, because it cannot be bypassed using package validation.
        return state.Invalid(TxValidationResult::TX_MEMPOOL_POLICY, "min relay fee not met",
                             strprintf("%d < %d", ws.m_modified_fees, m_pool.m_opts.min_relay_feerate.GetFee(ws.m_vsize)));
    }
    // No individual transactions are allowed below the mempool min feerate except from disconnected
    // blocks and transactions in a package. Package transactions will be checked using package
    // feerate later.
    if (!bypass_limits && !args.m_package_feerates && !CheckFeeRate(ws.m_vsize, ws.m_modified_fees, state)) return false;

    ws.m_iters_conflicting = m_pool.GetIterSet(ws.m_conflicts);

    ws.m_parents = m_pool.GetParents(*ws.m_tx_handle);

    if (!args.m_bypass_limits) {
        // Perform the TRUC checks, using the in-mempool parents.
        if (const auto err{SingleTRUCChecks(m_pool, ws.m_ptx, ws.m_parents, ws.m_conflicts, ws.m_vsize)}) {
            // Single transaction contexts only.
            if (args.m_allow_sibling_eviction && err->second != nullptr) {
                // We should only be considering where replacement is considered valid as well.
                Assume(args.m_allow_replacement);
                // Potential sibling eviction. Add the sibling to our list of mempool conflicts to be
                // included in RBF checks.
                ws.m_conflicts.insert(err->second->GetHash());
                // Adding the sibling to m_iters_conflicting here means that it doesn't count towards
                // RBF Carve Out above. This is correct, since removing to-be-replaced transactions from
                // the descendant count is done separately in SingleTRUCChecks for TRUC transactions.
                ws.m_iters_conflicting.insert(m_pool.GetIter(err->second->GetHash()).value());
                ws.m_sibling_eviction = true;
                // The sibling will be treated as part of the to-be-replaced set in ReplacementChecks.
                // Note that we are not checking whether it opts in to replaceability via BIP125 or TRUC
                // (which is normally done in PreChecks). However, the only way a TRUC transaction can
                // have a non-TRUC and non-BIP125 descendant is due to a reorg.
            } else {
                return state.Invalid(TxValidationResult::TX_MEMPOOL_POLICY, "TRUC-violation", err->first);
            }
        }
    }

    // We want to detect conflicts in any tx in a package to trigger package RBF logic
    m_subpackage.m_rbf |= !ws.m_conflicts.empty();
    return true;
}

bool MemPoolAccept::ReplacementChecks(Workspace& ws)
{
    AssertLockHeld(cs_main);
    AssertLockHeld(m_pool.cs);

    const CTransaction& tx = *ws.m_ptx;
    const Txid& hash = ws.m_hash;
    TxValidationState& state = ws.m_state;

    CFeeRate newFeeRate(ws.m_modified_fees, ws.m_vsize);

    CTxMemPool::setEntries all_conflicts;

    // Calculate all conflicting entries and enforce Rule #5.
    if (const auto err_string{GetEntriesForConflicts(tx, m_pool, ws.m_iters_conflicting, all_conflicts)}) {
        return state.Invalid(TxValidationResult::TX_MEMPOOL_POLICY,
                             strprintf("too many potential replacements%s", ws.m_sibling_eviction ? " (including sibling eviction)" : ""), *err_string);
    }

    // Check if it's economically rational to mine this transaction rather than the ones it
    // replaces and pays for its own relay fees. Enforce Rules #3 and #4.
    for (CTxMemPool::txiter it : all_conflicts) {
        m_subpackage.m_conflicting_fees += it->GetModifiedFee();
        m_subpackage.m_conflicting_size += it->GetTxSize();
    }

    if (const auto err_string{PaysForRBF(m_subpackage.m_conflicting_fees, ws.m_modified_fees, ws.m_vsize,
                                         m_pool.m_opts.incremental_relay_feerate, hash)}) {
        // Result may change in a package context
        return state.Invalid(TxValidationResult::TX_RECONSIDERABLE,
                             strprintf("insufficient fee%s", ws.m_sibling_eviction ? " (including sibling eviction)" : ""), *err_string);
    }

    // Add all the to-be-removed transactions to the changeset.
    for (auto it : all_conflicts) {
        m_subpackage.m_changeset->StageRemoval(it);
    }

    // Run cluster size limit checks and fail if we exceed them.
    if (!m_subpackage.m_changeset->CheckMemPoolPolicyLimits()) {
        return state.Invalid(TxValidationResult::TX_MEMPOOL_POLICY, "too-large-cluster", "");
    }

    if (const auto err_string{ImprovesFeerateDiagram(*m_subpackage.m_changeset)}) {
        // We checked above for the cluster size limits being respected, so a
        // failure here can only be due to an insufficient fee.
        Assume(err_string->first == DiagramCheckError::FAILURE);
        return state.Invalid(TxValidationResult::TX_RECONSIDERABLE, "replacement-failed", err_string->second);
    }

    return true;
}

bool MemPoolAccept::PackageMempoolChecks(const std::vector<CTransactionRef>& txns,
                                         std::vector<Workspace>& workspaces,
                                         const int64_t total_vsize,
                                         PackageValidationState& package_state)
{
    AssertLockHeld(cs_main);
    AssertLockHeld(m_pool.cs);

    assert(std::all_of(txns.cbegin(), txns.cend(), [this](const auto& tx)
                       { return !m_pool.exists(tx->GetHash());}));

    assert(txns.size() == workspaces.size());

    // No conflicts means we're finished. Further checks are all RBF-only.
    if (!m_subpackage.m_rbf) return true;

    // We're in package RBF context; replacement proposal must be size 2
    if (workspaces.size() != 2 || !Assume(IsChildWithParents(txns))) {
        return package_state.Invalid(PackageValidationResult::PCKG_POLICY, "package RBF failed: package must be 1-parent-1-child");
    }

    // If the package has in-mempool parents, we won't consider a package RBF
    // since it would result in a cluster larger than 2.
    // N.B. To relax this constraint we will need to revisit how CCoinsViewMemPool::PackageAddTransaction
    // is being used inside AcceptMultipleTransactions to track available inputs while processing a package.
    // Specifically we would need to check that the ancestors of the new
    // transactions don't intersect with the set of transactions to be removed
    // due to RBF, which is not checked at all in the package acceptance
    // context.
    for (const auto& ws : workspaces) {
        if (!ws.m_parents.empty()) {
            return package_state.Invalid(PackageValidationResult::PCKG_POLICY, "package RBF failed: new transaction cannot have mempool ancestors");
        }
    }

    // Aggregate all conflicts into one set.
    CTxMemPool::setEntries direct_conflict_iters;
    for (Workspace& ws : workspaces) {
        // Aggregate all conflicts into one set.
        direct_conflict_iters.merge(ws.m_iters_conflicting);
    }

    const auto& parent_ws = workspaces[0];
    const auto& child_ws = workspaces[1];

    // Don't consider replacements that would cause us to remove a large number of mempool entries.
    // This limit is not increased in a package RBF. Use the aggregate number of transactions.
    CTxMemPool::setEntries all_conflicts;
    if (const auto err_string{GetEntriesForConflicts(*child_ws.m_ptx, m_pool, direct_conflict_iters,
                                                     all_conflicts)}) {
        return package_state.Invalid(PackageValidationResult::PCKG_POLICY,
                                     "package RBF failed: too many potential replacements", *err_string);
    }

    for (CTxMemPool::txiter it : all_conflicts) {
        m_subpackage.m_changeset->StageRemoval(it);
        m_subpackage.m_conflicting_fees += it->GetModifiedFee();
        m_subpackage.m_conflicting_size += it->GetTxSize();
    }

    // Use the child as the transaction for attributing errors to.
    const Txid& child_hash = child_ws.m_ptx->GetHash();
    if (const auto err_string{PaysForRBF(/*original_fees=*/m_subpackage.m_conflicting_fees,
                                         /*replacement_fees=*/m_subpackage.m_total_modified_fees,
                                         /*replacement_vsize=*/m_subpackage.m_total_vsize,
                                         m_pool.m_opts.incremental_relay_feerate, child_hash)}) {
        return package_state.Invalid(PackageValidationResult::PCKG_POLICY,
                                     "package RBF failed: insufficient anti-DoS fees", *err_string);
    }

    // Ensure this two transaction package is a "chunk" on its own; we don't want the child
    // to be only paying anti-DoS fees
    const CFeeRate parent_feerate(parent_ws.m_modified_fees, parent_ws.m_vsize);
    const CFeeRate package_feerate(m_subpackage.m_total_modified_fees, m_subpackage.m_total_vsize);
    if (package_feerate <= parent_feerate) {
        return package_state.Invalid(PackageValidationResult::PCKG_POLICY,
                                     "package RBF failed: package feerate is less than or equal to parent feerate",
                                     strprintf("package feerate %s <= parent feerate is %s", package_feerate.ToString(), parent_feerate.ToString()));
    }

    // Run cluster size limit checks and fail if we exceed them.
    if (!m_subpackage.m_changeset->CheckMemPoolPolicyLimits()) {
        return package_state.Invalid(PackageValidationResult::PCKG_POLICY, "too-large-cluster", "");
    }

    // Check if it's economically rational to mine this package rather than the ones it replaces.
    if (const auto err_tup{ImprovesFeerateDiagram(*m_subpackage.m_changeset)}) {
        Assume(err_tup->first == DiagramCheckError::FAILURE);
        return package_state.Invalid(PackageValidationResult::PCKG_POLICY,
                                     "package RBF failed: " + err_tup.value().second, "");
    }

    LogDebug(BCLog::TXPACKAGES, "package RBF checks passed: parent %s (wtxid=%s), child %s (wtxid=%s), package hash (%s)\n",
        txns.front()->GetHash().ToString(), txns.front()->GetWitnessHash().ToString(),
        txns.back()->GetHash().ToString(), txns.back()->GetWitnessHash().ToString(),
        GetPackageHash(txns).ToString());


    return true;
}

bool MemPoolAccept::PolicyScriptChecks(const ATMPArgs& args, Workspace& ws)
{
    AssertLockHeld(cs_main);
    AssertLockHeld(m_pool.cs);
    const CTransaction& tx = *ws.m_ptx;
    TxValidationState& state = ws.m_state;

    constexpr script_verify_flags scriptVerifyFlags = STANDARD_SCRIPT_VERIFY_FLAGS;

    // Check input scripts and signatures.
    // This is done last to help prevent CPU exhaustion denial-of-service attacks.
    if (!CheckInputScripts(tx, state, m_view, scriptVerifyFlags, true, false, ws.m_precomputed_txdata, GetValidationCache())) {
        // Detect a failure due to a missing witness so that p2p code can handle rejection caching appropriately.
        if (!tx.HasWitness() && SpendsNonAnchorWitnessProg(tx, m_view)) {
            state.Invalid(TxValidationResult::TX_WITNESS_STRIPPED,
                    state.GetRejectReason(), state.GetDebugMessage());
        }
        return false; // state filled in by CheckInputScripts
    }

    return true;
}

bool MemPoolAccept::ConsensusScriptChecks(const ATMPArgs& args, Workspace& ws)
{
    AssertLockHeld(cs_main);
    AssertLockHeld(m_pool.cs);
    const CTransaction& tx = *ws.m_ptx;
    const Txid& hash = ws.m_hash;
    TxValidationState& state = ws.m_state;

    // Check again against the current block tip's script verification
    // flags to cache our script execution flags. This is, of course,
    // useless if the next block has different script flags from the
    // previous one, but because the cache tracks script flags for us it
    // will auto-invalidate and we'll just have a few blocks of extra
    // misses on soft-fork activation.
    //
    // This is also useful in case of bugs in the standard flags that cause
    // transactions to pass as valid when they're actually invalid. For
    // instance the STRICTENC flag was incorrectly allowing certain
    // CHECKSIG NOT scripts to pass, even though they were invalid.
    //
    // There is a similar check in CreateNewBlock() to prevent creating
    // invalid blocks (using TestBlockValidity), however allowing such
    // transactions into the mempool can be exploited as a DoS attack.
    script_verify_flags currentBlockScriptVerifyFlags{GetBlockScriptFlags(*m_active_chainstate.m_chain.Tip(), m_active_chainstate.m_chainman)};
    if (!CheckInputsFromMempoolAndCache(tx, state, m_view, m_pool, currentBlockScriptVerifyFlags,
                                        ws.m_precomputed_txdata, m_active_chainstate.CoinsTip(), GetValidationCache())) {
        LogPrintf("BUG! PLEASE REPORT THIS! CheckInputScripts failed against latest-block but not STANDARD flags %s, %s\n", hash.ToString(), state.ToString());
        return Assume(false);
    }

    return true;
}

void MemPoolAccept::FinalizeSubpackage(const ATMPArgs& args)
{
    AssertLockHeld(cs_main);
    AssertLockHeld(m_pool.cs);

    if (!m_subpackage.m_changeset->GetRemovals().empty()) Assume(args.m_allow_replacement);
    // Remove conflicting transactions from the mempool
    for (CTxMemPool::txiter it : m_subpackage.m_changeset->GetRemovals())
    {
        std::string log_string = strprintf("replacing mempool tx %s (wtxid=%s, fees=%s, vsize=%s). ",
                                      it->GetTx().GetHash().ToString(),
                                      it->GetTx().GetWitnessHash().ToString(),
                                      it->GetFee(),
                                      it->GetTxSize());
        FeeFrac feerate{m_subpackage.m_total_modified_fees, int32_t(m_subpackage.m_total_vsize)};
        uint256 tx_or_package_hash{};
        const bool replaced_with_tx{m_subpackage.m_changeset->GetTxCount() == 1};
        if (replaced_with_tx) {
            const CTransaction& tx = m_subpackage.m_changeset->GetAddedTxn(0);
            tx_or_package_hash = tx.GetHash().ToUint256();
            log_string += strprintf("New tx %s (wtxid=%s, fees=%s, vsize=%s)",
                                    tx.GetHash().ToString(),
                                    tx.GetWitnessHash().ToString(),
                                    feerate.fee,
                                    feerate.size);
        } else {
            tx_or_package_hash = GetPackageHash(m_subpackage.m_changeset->GetAddedTxns());
            log_string += strprintf("New package %s with %lu txs, fees=%s, vsize=%s",
                                    tx_or_package_hash.ToString(),
                                    m_subpackage.m_changeset->GetTxCount(),
                                    feerate.fee,
                                    feerate.size);

        }
        LogDebug(BCLog::MEMPOOL, "%s\n", log_string);
        TRACEPOINT(mempool, replaced,
                it->GetTx().GetHash().data(),
                it->GetTxSize(),
                it->GetFee(),
                std::chrono::duration_cast<std::chrono::duration<std::uint64_t>>(it->GetTime()).count(),
                tx_or_package_hash.data(),
                feerate.size,
                feerate.fee,
                replaced_with_tx
        );
        m_subpackage.m_replaced_transactions.push_back(it->GetSharedTx());
    }
    m_subpackage.m_changeset->Apply();
    m_subpackage.m_changeset.reset();
}

bool MemPoolAccept::SubmitPackage(const ATMPArgs& args, std::vector<Workspace>& workspaces,
                                  PackageValidationState& package_state,
                                  std::map<Wtxid, MempoolAcceptResult>& results)
{
    AssertLockHeld(cs_main);
    AssertLockHeld(m_pool.cs);
    // Sanity check: none of the transactions should be in the mempool, and none of the transactions
    // should have a same-txid-different-witness equivalent in the mempool.
    assert(std::all_of(workspaces.cbegin(), workspaces.cend(), [this](const auto& ws) { return !m_pool.exists(ws.m_ptx->GetHash()); }));

    bool all_submitted = true;
    FinalizeSubpackage(args);
    // ConsensusScriptChecks adds to the script cache and is therefore consensus-critical;
    // CheckInputsFromMempoolAndCache asserts that transactions only spend coins available from the
    // mempool or UTXO set. Submit each transaction to the mempool immediately after calling
    // ConsensusScriptChecks to make the outputs available for subsequent transactions.
    for (Workspace& ws : workspaces) {
        if (!ConsensusScriptChecks(args, ws)) {
            results.emplace(ws.m_ptx->GetWitnessHash(), MempoolAcceptResult::Failure(ws.m_state));
            // Since PolicyScriptChecks() passed, this should never fail.
            Assume(false);
            all_submitted = false;
            package_state.Invalid(PackageValidationResult::PCKG_MEMPOOL_ERROR,
                                  strprintf("BUG! PolicyScriptChecks succeeded but ConsensusScriptChecks failed: %s",
                                            ws.m_ptx->GetHash().ToString()));
            // Remove the transaction from the mempool.
            if (!m_subpackage.m_changeset) m_subpackage.m_changeset = m_pool.GetChangeSet();
            m_subpackage.m_changeset->StageRemoval(m_pool.GetIter(ws.m_ptx->GetHash()).value());
        }
    }
    if (!all_submitted) {
        Assume(m_subpackage.m_changeset);
        // This code should be unreachable; it's here as belt-and-suspenders
        // to try to ensure we have no consensus-invalid transactions in the
        // mempool.
        m_subpackage.m_changeset->Apply();
        m_subpackage.m_changeset.reset();
        return false;
    }

    std::vector<Wtxid> all_package_wtxids;
    all_package_wtxids.reserve(workspaces.size());
    std::transform(workspaces.cbegin(), workspaces.cend(), std::back_inserter(all_package_wtxids),
                   [](const auto& ws) { return ws.m_ptx->GetWitnessHash(); });

    if (!m_subpackage.m_replaced_transactions.empty()) {
        LogDebug(BCLog::MEMPOOL, "replaced %u mempool transactions with %u new one(s) for %s additional fees, %d delta bytes\n",
                 m_subpackage.m_replaced_transactions.size(), workspaces.size(),
                 m_subpackage.m_total_modified_fees - m_subpackage.m_conflicting_fees,
                 m_subpackage.m_total_vsize - static_cast<int>(m_subpackage.m_conflicting_size));
    }

    // Add successful results. The returned results may change later if LimitMempoolSize() evicts them.
    for (Workspace& ws : workspaces) {
        auto iter = m_pool.GetIter(ws.m_ptx->GetHash());
        Assume(iter.has_value());
        const auto effective_feerate = args.m_package_feerates ? ws.m_package_feerate :
            CFeeRate{ws.m_modified_fees, static_cast<int32_t>(ws.m_vsize)};
        const auto effective_feerate_wtxids = args.m_package_feerates ? all_package_wtxids :
            std::vector<Wtxid>{ws.m_ptx->GetWitnessHash()};
        results.emplace(ws.m_ptx->GetWitnessHash(),
                        MempoolAcceptResult::Success(std::move(m_subpackage.m_replaced_transactions), ws.m_vsize,
                                         ws.m_base_fees, effective_feerate, effective_feerate_wtxids));
        if (!m_pool.m_opts.signals) continue;
        const CTransaction& tx = *ws.m_ptx;
        const auto tx_info = NewMempoolTransactionInfo(ws.m_ptx, ws.m_base_fees,
                                                       ws.m_vsize, (*iter)->GetHeight(),
                                                       args.m_bypass_limits, args.m_package_submission,
                                                       IsCurrentForFeeEstimation(m_active_chainstate),
                                                       m_pool.HasNoInputsOf(tx));
        m_pool.m_opts.signals->TransactionAddedToMempool(tx_info, m_pool.GetAndIncrementSequence());
    }
    return all_submitted;
}

MempoolAcceptResult MemPoolAccept::AcceptSingleTransactionInternal(const CTransactionRef& ptx, ATMPArgs& args)
{
    AssertLockHeld(cs_main);
    AssertLockHeld(m_pool.cs);

    Workspace ws(ptx);
    const std::vector<Wtxid> single_wtxid{ws.m_ptx->GetWitnessHash()};

    if (!PreChecks(args, ws)) {
        if (ws.m_state.GetResult() == TxValidationResult::TX_RECONSIDERABLE) {
            // Failed for fee reasons. Provide the effective feerate and which tx was included.
            return MempoolAcceptResult::FeeFailure(ws.m_state, CFeeRate(ws.m_modified_fees, ws.m_vsize), single_wtxid);
        }
        return MempoolAcceptResult::Failure(ws.m_state);
    }

    if (m_subpackage.m_rbf && !ReplacementChecks(ws)) {
        if (ws.m_state.GetResult() == TxValidationResult::TX_RECONSIDERABLE) {
            // Failed for incentives-based fee reasons. Provide the effective feerate and which tx was included.
            return MempoolAcceptResult::FeeFailure(ws.m_state, CFeeRate(ws.m_modified_fees, ws.m_vsize), single_wtxid);
        }
        return MempoolAcceptResult::Failure(ws.m_state);
    }

    // Check if the transaction would exceed the cluster size limit.
    if (!m_subpackage.m_changeset->CheckMemPoolPolicyLimits()) {
        ws.m_state.Invalid(TxValidationResult::TX_MEMPOOL_POLICY, "too-large-cluster", "");
        return MempoolAcceptResult::Failure(ws.m_state);
    }

    // Now that we've verified the cluster limit is respected, we can perform
    // calculations involving the full ancestors of the tx.
    if (ws.m_conflicts.size()) {
        auto ancestors = m_subpackage.m_changeset->CalculateMemPoolAncestors(ws.m_tx_handle);

        // A transaction that spends outputs that would be replaced by it is invalid. Now
        // that we have the set of all ancestors we can detect this
        // pathological case by making sure ws.m_conflicts and this tx's ancestors don't
        // intersect.
        if (const auto err_string{EntriesAndTxidsDisjoint(ancestors, ws.m_conflicts, ptx->GetHash())}) {
            // We classify this as a consensus error because a transaction depending on something it
            // conflicts with would be inconsistent.
            ws.m_state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-spends-conflicting-tx", *err_string);
            return MempoolAcceptResult::Failure(ws.m_state);
        }
    }

    m_subpackage.m_total_vsize = ws.m_vsize;
    m_subpackage.m_total_modified_fees = ws.m_modified_fees;

    // Individual modified feerate exceeded caller-defined max; abort
    if (args.m_client_maxfeerate && CFeeRate(ws.m_modified_fees, ws.m_vsize) > args.m_client_maxfeerate.value()) {
        ws.m_state.Invalid(TxValidationResult::TX_MEMPOOL_POLICY, "max feerate exceeded", "");
        return MempoolAcceptResult::Failure(ws.m_state);
    }

    if (m_pool.m_opts.require_standard) {
        Wtxid dummy_wtxid;
        if (!CheckEphemeralSpends(/*package=*/{ptx}, m_pool.m_opts.dust_relay_feerate, m_pool, ws.m_state, dummy_wtxid)) {
            return MempoolAcceptResult::Failure(ws.m_state);
        }
    }

    // Perform the inexpensive checks first and avoid hashing and signature verification unless
    // those checks pass, to mitigate CPU exhaustion denial-of-service attacks.
    if (!PolicyScriptChecks(args, ws)) return MempoolAcceptResult::Failure(ws.m_state);

    if (!ConsensusScriptChecks(args, ws)) return MempoolAcceptResult::Failure(ws.m_state);

    const CFeeRate effective_feerate{ws.m_modified_fees, static_cast<int32_t>(ws.m_vsize)};
    // Tx was accepted, but not added
    if (args.m_test_accept) {
        return MempoolAcceptResult::Success(std::move(m_subpackage.m_replaced_transactions), ws.m_vsize,
                                            ws.m_base_fees, effective_feerate, single_wtxid);
    }

    FinalizeSubpackage(args);

    // Limit the mempool, if appropriate.
    if (!args.m_package_submission && !args.m_bypass_limits) {
        LimitMempoolSize(m_pool, m_active_chainstate.CoinsTip());
        // If mempool contents change, then the m_view cache is dirty. Given this isn't a package
        // submission, we won't be using the cache anymore, but clear it anyway for clarity.
        CleanupTemporaryCoins();

        if (!m_pool.exists(ws.m_hash)) {
            // The tx no longer meets our (new) mempool minimum feerate but could be reconsidered in a package.
            ws.m_state.Invalid(TxValidationResult::TX_RECONSIDERABLE, "mempool full");
            return MempoolAcceptResult::FeeFailure(ws.m_state, CFeeRate(ws.m_modified_fees, ws.m_vsize), {ws.m_ptx->GetWitnessHash()});
        }
    }

    if (m_pool.m_opts.signals) {
        const CTransaction& tx = *ws.m_ptx;
        auto iter = m_pool.GetIter(tx.GetHash());
        Assume(iter.has_value());
        const auto tx_info = NewMempoolTransactionInfo(ws.m_ptx, ws.m_base_fees,
                                                       ws.m_vsize, (*iter)->GetHeight(),
                                                       args.m_bypass_limits, args.m_package_submission,
                                                       IsCurrentForFeeEstimation(m_active_chainstate),
                                                       m_pool.HasNoInputsOf(tx));
        m_pool.m_opts.signals->TransactionAddedToMempool(tx_info, m_pool.GetAndIncrementSequence());
    }

    if (!m_subpackage.m_replaced_transactions.empty()) {
        LogDebug(BCLog::MEMPOOL, "replaced %u mempool transactions with 1 new transaction for %s additional fees, %d delta bytes\n",
                 m_subpackage.m_replaced_transactions.size(),
                 ws.m_modified_fees - m_subpackage.m_conflicting_fees,
                 ws.m_vsize - static_cast<int>(m_subpackage.m_conflicting_size));
    }

    return MempoolAcceptResult::Success(std::move(m_subpackage.m_replaced_transactions), ws.m_vsize, ws.m_base_fees,
                                        effective_feerate, single_wtxid);
}

PackageMempoolAcceptResult MemPoolAccept::AcceptMultipleTransactionsInternal(const std::vector<CTransactionRef>& txns, ATMPArgs& args)
{
    AssertLockHeld(cs_main);
    AssertLockHeld(m_pool.cs);

    // These context-free package limits can be done before taking the mempool lock.
    PackageValidationState package_state;
    if (!IsWellFormedPackage(txns, package_state, /*require_sorted=*/true)) return PackageMempoolAcceptResult(package_state, {});

    std::vector<Workspace> workspaces{};
    workspaces.reserve(txns.size());
    std::transform(txns.cbegin(), txns.cend(), std::back_inserter(workspaces),
                   [](const auto& tx) { return Workspace(tx); });
    std::map<Wtxid, MempoolAcceptResult> results;

    // Do all PreChecks first and fail fast to avoid running expensive script checks when unnecessary.
    for (Workspace& ws : workspaces) {
        if (!PreChecks(args, ws)) {
            package_state.Invalid(PackageValidationResult::PCKG_TX, "transaction failed");
            // Exit early to avoid doing pointless work. Update the failed tx result; the rest are unfinished.
            results.emplace(ws.m_ptx->GetWitnessHash(), MempoolAcceptResult::Failure(ws.m_state));
            return PackageMempoolAcceptResult(package_state, std::move(results));
        }

        // Individual modified feerate exceeded caller-defined max; abort
        // N.B. this doesn't take into account CPFPs. Chunk-aware validation may be more robust.
        if (args.m_client_maxfeerate && CFeeRate(ws.m_modified_fees, ws.m_vsize) > args.m_client_maxfeerate.value()) {
            // Need to set failure here both individually and at package level
            ws.m_state.Invalid(TxValidationResult::TX_MEMPOOL_POLICY, "max feerate exceeded", "");
            package_state.Invalid(PackageValidationResult::PCKG_TX, "transaction failed");
            // Exit early to avoid doing pointless work. Update the failed tx result; the rest are unfinished.
            results.emplace(ws.m_ptx->GetWitnessHash(), MempoolAcceptResult::Failure(ws.m_state));
            return PackageMempoolAcceptResult(package_state, std::move(results));
        }

        // Make the coins created by this transaction available for subsequent transactions in the
        // package to spend. If there are no conflicts within the package, no transaction can spend a coin
        // needed by another transaction in the package. We also need to make sure that no package
        // tx replaces (or replaces the ancestor of) the parent of another package tx. As long as we
        // check these two things, we don't need to track the coins spent.
        // If a package tx conflicts with a mempool tx, PackageMempoolChecks() ensures later that any package RBF attempt
        // has *no* in-mempool ancestors, so we don't have to worry about subsequent transactions in
        // same package spending the same in-mempool outpoints. This needs to be revisited for general
        // package RBF.
        m_viewmempool.PackageAddTransaction(ws.m_ptx);
    }

    // At this point we have all in-mempool parents, and we know every transaction's vsize.
    // Run the TRUC checks on the package.
    for (Workspace& ws : workspaces) {
        if (auto err{PackageTRUCChecks(m_pool, ws.m_ptx, ws.m_vsize, txns, ws.m_parents)}) {
            package_state.Invalid(PackageValidationResult::PCKG_POLICY, "TRUC-violation", err.value());
            return PackageMempoolAcceptResult(package_state, {});
        }
    }

    // Transactions must meet two minimum feerates: the mempool minimum fee and min relay fee.
    // For transactions consisting of exactly one child and its parents, it suffices to use the
    // package feerate (total modified fees / total virtual size) to check this requirement.
    // Note that this is an aggregate feerate; this function has not checked that there are transactions
    // too low feerate to pay for themselves, or that the child transactions are higher feerate than
    // their parents. Using aggregate feerate may allow "parents pay for child" behavior and permit
    // a child that is below mempool minimum feerate. To avoid these behaviors, callers of
    // AcceptMultipleTransactions need to restrict txns topology (e.g. to ancestor sets) and check
    // the feerates of individuals and subsets.
    m_subpackage.m_total_vsize = std::accumulate(workspaces.cbegin(), workspaces.cend(), int64_t{0},
        [](int64_t sum, auto& ws) { return sum + ws.m_vsize; });
    m_subpackage.m_total_modified_fees = std::accumulate(workspaces.cbegin(), workspaces.cend(), CAmount{0},
        [](CAmount sum, auto& ws) { return sum + ws.m_modified_fees; });
    const CFeeRate package_feerate(m_subpackage.m_total_modified_fees, m_subpackage.m_total_vsize);
    std::vector<Wtxid> all_package_wtxids;
    all_package_wtxids.reserve(workspaces.size());
    std::transform(workspaces.cbegin(), workspaces.cend(), std::back_inserter(all_package_wtxids),
                   [](const auto& ws) { return ws.m_ptx->GetWitnessHash(); });
    TxValidationState placeholder_state;
    if (args.m_package_feerates &&
        !CheckFeeRate(m_subpackage.m_total_vsize, m_subpackage.m_total_modified_fees, placeholder_state)) {
        package_state.Invalid(PackageValidationResult::PCKG_TX, "transaction failed");
        return PackageMempoolAcceptResult(package_state, {{workspaces.back().m_ptx->GetWitnessHash(),
            MempoolAcceptResult::FeeFailure(placeholder_state, CFeeRate(m_subpackage.m_total_modified_fees, m_subpackage.m_total_vsize), all_package_wtxids)}});
    }

    // Apply package mempool RBF checks.
    if (!PackageMempoolChecks(txns, workspaces, m_subpackage.m_total_vsize, package_state)) {
        return PackageMempoolAcceptResult(package_state, std::move(results));
    }

    // Check if the transactions would exceed the cluster size limit.
    if (!m_subpackage.m_changeset->CheckMemPoolPolicyLimits()) {
        package_state.Invalid(PackageValidationResult::PCKG_POLICY, "too-large-cluster", "");
        return PackageMempoolAcceptResult(package_state, std::move(results));
    }

    // Now that we've bounded the resulting possible ancestry count, check package for dust spends
    if (m_pool.m_opts.require_standard) {
        TxValidationState child_state;
        Wtxid child_wtxid;
        if (!CheckEphemeralSpends(txns, m_pool.m_opts.dust_relay_feerate, m_pool, child_state, child_wtxid)) {
            package_state.Invalid(PackageValidationResult::PCKG_TX, "unspent-dust");
            results.emplace(child_wtxid, MempoolAcceptResult::Failure(child_state));
            return PackageMempoolAcceptResult(package_state, std::move(results));
        }
    }

    for (Workspace& ws : workspaces) {
        ws.m_package_feerate = package_feerate;
        if (!PolicyScriptChecks(args, ws)) {
            // Exit early to avoid doing pointless work. Update the failed tx result; the rest are unfinished.
            package_state.Invalid(PackageValidationResult::PCKG_TX, "transaction failed");
            results.emplace(ws.m_ptx->GetWitnessHash(), MempoolAcceptResult::Failure(ws.m_state));
            return PackageMempoolAcceptResult(package_state, std::move(results));
        }
        if (args.m_test_accept) {
            const auto effective_feerate = args.m_package_feerates ? ws.m_package_feerate :
                CFeeRate{ws.m_modified_fees, static_cast<int32_t>(ws.m_vsize)};
            const auto effective_feerate_wtxids = args.m_package_feerates ? all_package_wtxids :
                std::vector<Wtxid>{ws.m_ptx->GetWitnessHash()};
            results.emplace(ws.m_ptx->GetWitnessHash(),
                            MempoolAcceptResult::Success(std::move(m_subpackage.m_replaced_transactions),
                                                         ws.m_vsize, ws.m_base_fees, effective_feerate,
                                                         effective_feerate_wtxids));
        }
    }

    if (args.m_test_accept) return PackageMempoolAcceptResult(package_state, std::move(results));

    if (!SubmitPackage(args, workspaces, package_state, results)) {
        // PackageValidationState filled in by SubmitPackage().
        return PackageMempoolAcceptResult(package_state, std::move(results));
    }

    return PackageMempoolAcceptResult(package_state, std::move(results));
}

void MemPoolAccept::CleanupTemporaryCoins()
{
    // There are 3 kinds of coins in m_view:
    // (1) Temporary coins from the transactions in subpackage, constructed by m_viewmempool.
    // (2) Mempool coins from transactions in the mempool, constructed by m_viewmempool.
    // (3) Confirmed coins fetched from our current UTXO set.
    //
    // (1) Temporary coins need to be removed, regardless of whether the transaction was submitted.
    // If the transaction was submitted to the mempool, m_viewmempool will be able to fetch them from
    // there. If it wasn't submitted to mempool, it is incorrect to keep them - future calls may try
    // to spend those coins that don't actually exist.
    // (2) Mempool coins also need to be removed. If the mempool contents have changed as a result
    // of submitting or replacing transactions, coins previously fetched from mempool may now be
    // spent or nonexistent. Those coins need to be deleted from m_view.
    // (3) Confirmed coins don't need to be removed. The chainstate has not changed (we are
    // holding cs_main and no blocks have been processed) so the confirmed tx cannot disappear like
    // a mempool tx can. The coin may now be spent after we submitted a tx to mempool, but
    // we have already checked that the package does not have 2 transactions spending the same coin
    // and we check whether a mempool transaction spends conflicting coins (CTxMemPool::GetConflictTx).
    // Keeping them in m_view is an optimization to not re-fetch confirmed coins if we later look up
    // inputs for this transaction again.
    for (const auto& outpoint : m_viewmempool.GetNonBaseCoins()) {
        // In addition to resetting m_viewmempool, we also need to manually delete these coins from
        // m_view because it caches copies of the coins it fetched from m_viewmempool previously.
        m_view.Uncache(outpoint);
    }
    // This deletes the temporary and mempool coins.
    m_viewmempool.Reset();
}

PackageMempoolAcceptResult MemPoolAccept::AcceptSubPackage(const std::vector<CTransactionRef>& subpackage, ATMPArgs& args)
{
    AssertLockHeld(::cs_main);
    AssertLockHeld(m_pool.cs);
    auto result = [&]() EXCLUSIVE_LOCKS_REQUIRED(::cs_main, m_pool.cs) {
        if (subpackage.size() > 1) {
            return AcceptMultipleTransactionsInternal(subpackage, args);
        }
        const auto& tx = subpackage.front();
        ATMPArgs single_args = ATMPArgs::SingleInPackageAccept(args);
        const auto single_res = AcceptSingleTransactionInternal(tx, single_args);
        PackageValidationState package_state_wrapped;
        if (single_res.m_result_type != MempoolAcceptResult::ResultType::VALID) {
            package_state_wrapped.Invalid(PackageValidationResult::PCKG_TX, "transaction failed");
        }
        return PackageMempoolAcceptResult(package_state_wrapped, {{tx->GetWitnessHash(), single_res}});
    }();

    // Clean up m_view and m_viewmempool so that other subpackage evaluations don't have access to
    // coins they shouldn't. Keep some coins in order to minimize re-fetching coins from the UTXO set.
    // Clean up package feerate and rbf calculations
    ClearSubPackageState();

    return result;
}

PackageMempoolAcceptResult MemPoolAccept::AcceptPackage(const Package& package, ATMPArgs& args)
{
    Assert(!package.empty());
    AssertLockHeld(cs_main);
    // Used if returning a PackageMempoolAcceptResult directly from this function.
    PackageValidationState package_state_quit_early;

    // There are two topologies we are able to handle through this function:
    // (1) A single transaction
    // (2) A child-with-parents package.
    // Check that the package is well-formed. If it isn't, we won't try to validate any of the
    // transactions and thus won't return any MempoolAcceptResults, just a package-wide error.

    // Context-free package checks.
    if (!IsWellFormedPackage(package, package_state_quit_early, /*require_sorted=*/true)) {
        return PackageMempoolAcceptResult(package_state_quit_early, {});
    }

    if (package.size() > 1 && !IsChildWithParents(package)) {
        // All transactions in the package must be a parent of the last transaction. This is just an
        // opportunity for us to fail fast on a context-free check without taking the mempool lock.
        package_state_quit_early.Invalid(PackageValidationResult::PCKG_POLICY, "package-not-child-with-parents");
        return PackageMempoolAcceptResult(package_state_quit_early, {});
    }

    LOCK(m_pool.cs);
    // Stores results from which we will create the returned PackageMempoolAcceptResult.
    // A result may be changed if a mempool transaction is evicted later due to LimitMempoolSize().
    std::map<Wtxid, MempoolAcceptResult> results_final;
    // Results from individual validation which will be returned if no other result is available for
    // this transaction. "Nonfinal" because if a transaction fails by itself but succeeds later
    // (i.e. when evaluated with a fee-bumping child), the result in this map may be discarded.
    std::map<Wtxid, MempoolAcceptResult> individual_results_nonfinal;
    // Tracks whether we think package submission could result in successful entry to the mempool
    bool quit_early{false};
    std::vector<CTransactionRef> txns_package_eval;
    for (const auto& tx : package) {
        const auto& wtxid = tx->GetWitnessHash();
        const auto& txid = tx->GetHash();
        // There are 3 possibilities: already in mempool, same-txid-diff-wtxid already in mempool,
        // or not in mempool. An already confirmed tx is treated as one not in mempool, because all
        // we know is that the inputs aren't available.
        if (m_pool.exists(wtxid)) {
            // Exact transaction already exists in the mempool.
            // Node operators are free to set their mempool policies however they please, nodes may receive
            // transactions in different orders, and malicious counterparties may try to take advantage of
            // policy differences to pin or delay propagation of transactions. As such, it's possible for
            // some package transaction(s) to already be in the mempool, and we don't want to reject the
            // entire package in that case (as that could be a censorship vector). De-duplicate the
            // transactions that are already in the mempool, and only call AcceptMultipleTransactions() with
            // the new transactions. This ensures we don't double-count transaction counts and sizes when
            // checking ancestor/descendant limits, or double-count transaction fees for fee-related policy.
            const auto& entry{*Assert(m_pool.GetEntry(txid))};
            results_final.emplace(wtxid, MempoolAcceptResult::MempoolTx(entry.GetTxSize(), entry.GetFee()));
        } else if (m_pool.exists(txid)) {
            // Transaction with the same non-witness data but different witness (same txid,
            // different wtxid) already exists in the mempool.
            //
            // We don't allow replacement transactions right now, so just swap the package
            // transaction for the mempool one. Note that we are ignoring the validity of the
            // package transaction passed in.
            // TODO: allow witness replacement in packages.
            const auto& entry{*Assert(m_pool.GetEntry(txid))};
            // Provide the wtxid of the mempool tx so that the caller can look it up in the mempool.
            results_final.emplace(wtxid, MempoolAcceptResult::MempoolTxDifferentWitness(entry.GetTx().GetWitnessHash()));
        } else {
            // Transaction does not already exist in the mempool.
            // Try submitting the transaction on its own.
            const auto single_package_res = AcceptSubPackage({tx}, args);
            const auto& single_res = single_package_res.m_tx_results.at(wtxid);
            if (single_res.m_result_type == MempoolAcceptResult::ResultType::VALID) {
                // The transaction succeeded on its own and is now in the mempool. Don't include it
                // in package validation, because its fees should only be "used" once.
                assert(m_pool.exists(wtxid));
                results_final.emplace(wtxid, single_res);
            } else if (package.size() == 1 || // If there is only one transaction, no need to retry it "as a package"
                       (single_res.m_state.GetResult() != TxValidationResult::TX_RECONSIDERABLE &&
                       single_res.m_state.GetResult() != TxValidationResult::TX_MISSING_INPUTS)) {
                // Package validation policy only differs from individual policy in its evaluation
                // of feerate. For example, if a transaction fails here due to violation of a
                // consensus rule, the result will not change when it is submitted as part of a
                // package. To minimize the amount of repeated work, unless the transaction fails
                // due to feerate or missing inputs (its parent is a previous transaction in the
                // package that failed due to feerate), don't run package validation. Note that this
                // decision might not make sense if different types of packages are allowed in the
                // future.  Continue individually validating the rest of the transactions, because
                // some of them may still be valid.
                quit_early = true;
                package_state_quit_early.Invalid(PackageValidationResult::PCKG_TX, "transaction failed");
                individual_results_nonfinal.emplace(wtxid, single_res);
            } else {
                individual_results_nonfinal.emplace(wtxid, single_res);
                txns_package_eval.push_back(tx);
            }
        }
    }

    auto multi_submission_result = quit_early || txns_package_eval.empty() ? PackageMempoolAcceptResult(package_state_quit_early, {}) :
        AcceptSubPackage(txns_package_eval, args);
    PackageValidationState& package_state_final = multi_submission_result.m_state;

    // This is invoked by AcceptSubPackage() already, so this is just here for
    // clarity (since it's not permitted to invoke LimitMempoolSize() while a
    // changeset is outstanding).
    ClearSubPackageState();

    // Make sure we haven't exceeded max mempool size.
    // Package transactions that were submitted to mempool or already in mempool may be evicted.
    // If mempool contents change, then the m_view cache is dirty. It has already been cleared above.
    LimitMempoolSize(m_pool, m_active_chainstate.CoinsTip());

    for (const auto& tx : package) {
        const auto& wtxid = tx->GetWitnessHash();
        if (multi_submission_result.m_tx_results.count(wtxid) > 0) {
            // We shouldn't have re-submitted if the tx result was already in results_final.
            Assume(results_final.count(wtxid) == 0);
            // If it was submitted, check to see if the tx is still in the mempool. It could have
            // been evicted due to LimitMempoolSize() above.
            const auto& txresult = multi_submission_result.m_tx_results.at(wtxid);
            if (txresult.m_result_type == MempoolAcceptResult::ResultType::VALID && !m_pool.exists(wtxid)) {
                package_state_final.Invalid(PackageValidationResult::PCKG_TX, "transaction failed");
                TxValidationState mempool_full_state;
                mempool_full_state.Invalid(TxValidationResult::TX_MEMPOOL_POLICY, "mempool full");
                results_final.emplace(wtxid, MempoolAcceptResult::Failure(mempool_full_state));
            } else {
                results_final.emplace(wtxid, txresult);
            }
        } else if (const auto it{results_final.find(wtxid)}; it != results_final.end()) {
            // Already-in-mempool transaction. Check to see if it's still there, as it could have
            // been evicted when LimitMempoolSize() was called.
            Assume(it->second.m_result_type != MempoolAcceptResult::ResultType::INVALID);
            Assume(individual_results_nonfinal.count(wtxid) == 0);
            // Query by txid to include the same-txid-different-witness ones.
            if (!m_pool.exists(tx->GetHash())) {
                package_state_final.Invalid(PackageValidationResult::PCKG_TX, "transaction failed");
                TxValidationState mempool_full_state;
                mempool_full_state.Invalid(TxValidationResult::TX_MEMPOOL_POLICY, "mempool full");
                // Replace the previous result.
                results_final.erase(wtxid);
                results_final.emplace(wtxid, MempoolAcceptResult::Failure(mempool_full_state));
            }
        } else if (const auto it{individual_results_nonfinal.find(wtxid)}; it != individual_results_nonfinal.end()) {
            Assume(it->second.m_result_type == MempoolAcceptResult::ResultType::INVALID);
            // Interesting result from previous processing.
            results_final.emplace(wtxid, it->second);
        }
    }
    Assume(results_final.size() == package.size());
    return PackageMempoolAcceptResult(package_state_final, std::move(results_final));
}

} // anon namespace

MempoolAcceptResult AcceptToMemoryPool(Chainstate& active_chainstate, const CTransactionRef& tx, CTxMemPool& pool,
                                       int64_t accept_time, bool bypass_limits, bool test_accept)
{
    AssertLockHeld(::cs_main);
    const CChainParams& chainparams{active_chainstate.m_chainman.GetParams()};

    std::vector<COutPoint> coins_to_uncache;

    auto args = MemPoolAccept::ATMPArgs::SingleAccept(chainparams, accept_time, bypass_limits, coins_to_uncache, test_accept);
    MempoolAcceptResult result = MemPoolAccept(pool, active_chainstate).AcceptSingleTransactionAndCleanup(tx, args);

    if (result.m_result_type != MempoolAcceptResult::ResultType::VALID) {
        // Remove coins that were not present in the coins cache before calling
        // AcceptSingleTransaction(); this is to prevent memory DoS in case we receive a large
        // number of invalid transactions that attempt to overrun the in-memory coins cache
        // (`CCoinsViewCache::cacheCoins`).

        for (const COutPoint& hashTx : coins_to_uncache)
            active_chainstate.CoinsTip().Uncache(hashTx);
        TRACEPOINT(mempool, rejected,
                tx->GetHash().data(),
                result.m_state.GetRejectReason().c_str()
        );
    }
    // After we've (potentially) uncached entries, ensure our coins cache is still within its size limits
    BlockValidationState state_dummy;
    active_chainstate.FlushStateToDisk(state_dummy, FlushStateMode::PERIODIC);
    return result;
}

PackageMempoolAcceptResult ProcessNewPackage(Chainstate& active_chainstate, CTxMemPool& pool,
                                                   const Package& package, bool test_accept, const std::optional<CFeeRate>& client_maxfeerate)
{
    AssertLockHeld(cs_main);
    assert(!package.empty());
    assert(std::all_of(package.cbegin(), package.cend(), [](const auto& tx){return tx != nullptr;}));

    std::vector<COutPoint> coins_to_uncache;
    const CChainParams& chainparams = active_chainstate.m_chainman.GetParams();
    auto result = [&]() EXCLUSIVE_LOCKS_REQUIRED(cs_main) {
        AssertLockHeld(cs_main);
        if (test_accept) {
            auto args = MemPoolAccept::ATMPArgs::PackageTestAccept(chainparams, GetTime(), coins_to_uncache);
            return MemPoolAccept(pool, active_chainstate).AcceptMultipleTransactionsAndCleanup(package, args);
        } else {
            auto args = MemPoolAccept::ATMPArgs::PackageChildWithParents(chainparams, GetTime(), coins_to_uncache, client_maxfeerate);
            return MemPoolAccept(pool, active_chainstate).AcceptPackage(package, args);
        }
    }();

    // Uncache coins pertaining to transactions that were not submitted to the mempool.
    if (test_accept || result.m_state.IsInvalid()) {
        for (const COutPoint& hashTx : coins_to_uncache) {
            active_chainstate.CoinsTip().Uncache(hashTx);
        }
    }
    // Ensure the coins cache is still within limits.
    BlockValidationState state_dummy;
    active_chainstate.FlushStateToDisk(state_dummy, FlushStateMode::PERIODIC);
    return result;
}


