#!/usr/bin/env python3
# Copyright (c) The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test migrating a v28.2 block tree to the flat file block tree store

"""

import shutil

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class BlockTreeMigrationTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True

    def skip_test_if_missing_module(self):
        self.skip_if_no_previous_releases()

    def setup_network(self):
        self.add_nodes(
            self.num_nodes,
            versions=[
                None,
                280200,
            ],
        )

    def run_test(self):
        block_tree_store_node = self.nodes[0]
        legacy_node = self.nodes[1]

        self.start_node(1)
        nblocks = 100
        self.generate(legacy_node, nblocks, sync_fun=self.no_op)
        assert_equal(legacy_node.getblockchaininfo()["blocks"], nblocks)
        self.stop_node(1)

        migrate_log = "Successfully migrated the leveldb block tree db to new block tree store."
        reindex_log = "Detected legacy leveldb block tree db - removing it"

        self.log.info("Start the node with a legacy data directory to trigger migration")
        shutil.copytree(legacy_node.chain_path, block_tree_store_node.chain_path)
        with block_tree_store_node.assert_debug_log(expected_msgs=[migrate_log]):
            self.start_node(0)
        index_dir = block_tree_store_node.chain_path / "blocks" / "index"
        assert (index_dir / "headers.dat").exists()
        assert not (index_dir / "CURRENT").exists()
        assert_equal(block_tree_store_node.getblockchaininfo()["blocks"], nblocks)
        self.stop_node(0)

        self.log.info("Re-starting the node to exercise non-migration path")
        with block_tree_store_node.assert_debug_log(expected_msgs=[], unexpected_msgs=[migrate_log]):
            self.start_node(0)
        assert_equal(block_tree_store_node.getblockchaininfo()["blocks"], nblocks)
        self.stop_node(0)

        self.log.info("A corrupt legacy block index fails the migration and kills the node")
        shutil.move(block_tree_store_node.chain_path, block_tree_store_node.chain_path.with_name("regtest_migrated"))
        shutil.copytree(legacy_node.chain_path, block_tree_store_node.chain_path)
        manifests = list(block_tree_store_node.chain_path.glob("blocks/index/MANIFEST*"))
        assert_equal(len(manifests), 1)
        manifests[0].unlink()
        with block_tree_store_node.assert_debug_log(expected_msgs=["Error opening block database"]):
            block_tree_store_node.assert_start_raises_init_error()

        self.log.info("Restarting with -reindex will create a block tree store and remove the corrupt leveldb data")
        with block_tree_store_node.assert_debug_log(expected_msgs=[reindex_log]):
            self.start_node(0, extra_args=["-reindex"])
        self.wait_until(lambda: block_tree_store_node.getblockchaininfo()["blocks"] == nblocks)
        assert (index_dir / "headers.dat").exists()
        assert not (index_dir / "CURRENT").exists()
        self.stop_node(0)

        self.log.info("A corrupt legacy block index prompts the user to reindex")
        shutil.move(block_tree_store_node.chain_path, block_tree_store_node.chain_path.with_name("regtest_migrated_2"))
        shutil.copytree(legacy_node.chain_path, block_tree_store_node.chain_path)
        manifests = list(block_tree_store_node.chain_path.glob("blocks/index/MANIFEST*"))
        assert_equal(len(manifests), 1)
        manifests[0].unlink()
        with block_tree_store_node.assert_debug_log(expected_msgs=[reindex_log]):
            self.start_node(0, extra_args=["-test=reindex_after_failure_noninteractive_yes"])
        self.wait_until(lambda: block_tree_store_node.getblockchaininfo()["blocks"] == nblocks)
        assert (index_dir / "headers.dat").exists()
        assert not (index_dir / "CURRENT").exists()
        self.stop_node(0)


if __name__ == '__main__':
    BlockTreeMigrationTest(__file__).main()
