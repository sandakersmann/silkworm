/*
   Copyright 2020-2022 The Silkworm Authors

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

#pragma once

#include <functional>
#include <optional>
#include <variant>
#include <vector>

#include <silkworm/common/base.hpp>
#include <silkworm/trie/node.hpp>

namespace silkworm::trie {

// Erigon HashCollector2
using NodeCollector = std::function<void(ByteView nibbled_key, const Node&)>;

// Calculates root hash of a Modified Merkle Patricia Trie.
// See Appendix D "Modified Merkle Patricia Trie" of the Yellow Paper
// and https://eth.wiki/fundamentals/patricia-tree
class HashBuilder {
  public:
    HashBuilder() = default;

    // Not copyable nor movable
    HashBuilder(const HashBuilder&) = delete;
    HashBuilder& operator=(const HashBuilder&) = delete;

    //! \details Entries (leaves, nodes) must be added in the strictly increasing lexicographic order (by key).
    //! Consequently, duplicate keys are not allowed.
    //! The key should be unpacked, i.e. have one nibble per byte.
    //! In addition, a leaf key may not be a prefix of another leaf key
    //! (e.g. leaves with keys 0a0b & 0a0b0005 may not coexist).
    void add_leaf(Bytes nibbled_key, ByteView value);

    //! \details Entries (leaves, nodes) must be added in the strictly increasing lexicographic order (by key).
    //! Consequently, duplicate keys are not allowed.
    //! The key should be unpacked, i.e. have one nibble per byte.
    //! Nodes whose RLP is shorter than 32 bytes may not be added.
    void add_branch_node(Bytes nibbled_key, const evmc::bytes32& hash, bool is_in_db_trie = false);

    //! \brief Returns the root hash computed on behalf of added entries
    //! \remarks If no entries in the stack_ the kEmptyRoot is returned
    evmc::bytes32 root_hash();

    //! \brief Pointer to function for collecting nodes in etl.
    NodeCollector node_collector{nullptr};

    //! \brief Resets the builder as newly created
    void reset();

  private:
    evmc::bytes32 root_hash(bool auto_finalize);

    void finalize();

    // See Erigon GenStructStep
    void gen_struct_step(ByteView current, ByteView succeeding);

    std::vector<Bytes> branch_ref(uint16_t state_mask, uint16_t hash_mask);

    ByteView leaf_node_rlp(ByteView path, ByteView value);

    ByteView extension_node_rlp(ByteView path, ByteView child_ref);

    Bytes key_;                                 // unpacked – one nibble per byte
    std::variant<Bytes, evmc::bytes32> value_;  // leaf value or node hash
    bool is_in_db_trie_{false};

    std::vector<uint16_t> groups_;
    std::vector<uint16_t> tree_masks_;
    std::vector<uint16_t> hash_masks_;
    std::vector<Bytes> stack_;  // node references: hashes or embedded RLPs

    Bytes rlp_buffer_;
};

}  // namespace silkworm::trie
