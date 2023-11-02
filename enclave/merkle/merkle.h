// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

#ifndef __SVR2_MERKLE_MERKLE_H__
#define __SVR2_MERKLE_MERKLE_H__

#include <array>
#include <stdint.h>
#include "proto/error.pb.h"
#include "util/macros.h"

namespace svr2::merkle {

// Bytes of a hash to use for internal integrity checking.
#define MERKLE_HASH_SIZE 8

// Number of children in each node.  We set this to 13 since
// the node also has:
//   - parent (8 bytes)
//   - hash (8 bytes)
//   - flags (1 byte)
// so with 13 nodes, it should fit in 16*8 bytes, and powers of 2 are cool.
#define MERKLE_NODE_SIZE 13

typedef std::array<uint8_t, MERKLE_HASH_SIZE> Hash;
extern const Hash zero_hash;

// This header defines an in-memory merkle-ish tree for verifying the integrity
// of our in-memory databases (or at least, trying to really hard).  One of the
// attack vectors we're concerned about is the ability of an attacker to roll
// back specific pages within memory while keeping the rest as they are.  This
// code attempts to make that attack unlikely to succeed without lots of extra
// work.
// 
// As with any merkle tree, this tree consists of a set of internal nodes and
// a set of leaves.  Each leaf has a hash, and each internal node contains up
// to MERKLE_NODE_SIZE children, which are either all leaves or all other
// internal nodes.  Each internal node also has a hash:
// 
//   Hash(node) = Hash(concat(child1.hash, child2.hash, ...))
// 
// If an internal node lacks a child at index X, it will use all zeros for the
// hash of that child.  Each internal hash is MERKLE_NODE_SIZE bytes long,
// and is the prefix of a SHA256.
// 
// A typical merkle tree will have leaves that are key/value pairs, such that an
// individual key can be updated.  Rather than do this and require that the DB's
// keys are duplicated elsewhere, in our implementation the merkle::Leaf objects
// are embedded within the row data for the DB.  Effectively, their position in
// the DB is itself their key.
// 
// The tree starts off with a single internal node.  New nodes are added as
// necessary.  We'll consider the tree to grow from left to right, with the root
// at the top of the tree, for the purpose of discussion.
// 
// This tree has a very simple mechanism for growing/shrinking.  The main tree
// keeps track of two internal nodes, `root` and `curr`.  `root` is the top-most
// node in the tree.  `curr` is the internal node containing the rightmost (IE:
// most recent) leaf in the tree.  When a new leaf is added to the tree, it
// walks from `curr` up towards `root` looking for the first internal node it
// can find with empty space.  It then builds down a branch from that node to
// the level of `curr` containing all empty nodes.  Finally, it adds itself to
// the lowest node on that branch, and sets `curr` to that branch.
// 
// In the simple case, `curr` has space, and the leaf is added without other
// changes.  In the most complex case, the entire tree is full, including
// `root`.  When this happens, a new node is created above `root` with an empty
// branch down to the level of `curr`, the new topmost node becomes `root`, and
// the new rightmost node becomes `curr`.  To illustrate this, consider this
// tree with 2-slot nodes, where * denotes a full slot.
// 
//                                                          [**]   <- root
//           [**]       <- root        old_root ->  [**]      [* ]
//       [**]    [**]              =>           [**]    [**]  [* ]
//     [**][**][**][**] <- curr               [**][**][**][**][  ] <- curr
// 
// Note that the new root contains the old root as its left child and the
// top of a new branch as its right child.  The branch contains only left
// children down to the bottom (the new `curr`), which starts empty.  The
// leaf will then add itself to `curr`.
// 
// Deletes are very simple, with a few minor corner cases.  A leaf will,
// when it is itself destructed, remove itself from its parent node.  If
// that node is empty and is not `root` or `curr`, it will remove that
// node from its parent, then delete it.  We walk up the tree as far as
// possible, removing empty nodes, until we find a node that is either `root` or
// `curr`, or is not empty when the prior node has been removed from it.  Note
// that this means the depth of the tree will never decrease.  However, in our
// case, we expect there to be relatively few deletes, and definitely not enough
// that space savings would be found by shrinking the depth of the tree.
// 
// With our current use of this tree, the merkle root for a single replica will
// not match the merkle root of other replicas.  This is because the position of
// leaves in the tree depends on the order they were added to the tree.  When a
// new replica starts up, it adds nodes in lexigraphical order, while an
// already-running replica adds nodes as clients request it.  Hence, different
// orders will create different trees.  This is fine, since merkle roots are
// never shared across replicas.
// 
// This tree is specifically designed to handle an attack vector where an
// attacker can roll back specific pages in memory to prior known-good states.
// This tree construction makes that difficult, since Merkle leaves are stored
// within the DB itself, while the non-node leaves are stored externally and are
// allocated as needed, thus most probably being spread across multiple pages.
// 
// We currently use a relatively small hash size (8 bytes) to keep memory
// consumption of the tree small while making accidentally-valid trees very
// improbable (~1 in 2^(8*8) or ~1 in 14e16).
// 
// Verifications, updates, additions, and deletes to the tree should take
// O(depth) time to compute, which for this tree construction depth=logn.
// 
// Usage:
//   merkle::Tree tree;
//   {
//     merkle::Leaf lf1(&tree);
//     lf1.Update(hash_value);
//     lf1.Verify(hash_value);
//   }  // lf1 falls out of scope and is removed from the tree.
//   // tree falls out of scope and is destroyed.
// 
// Note that all leaves must fall out of scope prior to the tree doing so.
// Within our databases, we do this by essentially doing:
// 
//   class DB {
//     merkle::Tree tree_;  // cleaned up after rows_, thus after their leaves
//     class Row {
//       .. other stuff ..
//       merkle::Leaf leaf_;
//     };
//     std::map<RowKey, Row> rows_;  // later in the class, so cleaned up first.
//   };

class Tree;
class Node;

// Given a larger hash, return a prefix of size MERKLE_HASH_SIZE.
template <size_t N>
Hash HashFrom(const std::array<uint8_t, N>& in) {
  Hash out;
  CHECK(in.size() >= out.size());
  std::copy_n(in.begin(), out.size(), out.begin());
  return out;
}

// Base class for Leaf and Node.
class Part {
 public:
  virtual ~Part();
  Part(const Part& copy_from) = delete;
  Part(Node* parent);
  Part(Node* parent, const Hash& hash);
  const Hash& hash() const { return hash_; }
  Node* parent() const { return parent_; }  // nullptr for root.
 protected:
  Node* parent_;
  Hash hash_;
};

// Leaf class, should be embedded within the DB datastructure.
class Leaf : public Part {
 public:
  virtual ~Leaf();

  // Constructs a new leaf.  The hash on creation is `zero_hash`, so an
  // `Update` should probably be called directly after creation with the
  // actual hash associated with this leaf.
  Leaf(Tree* t);

  // No copy allowed, since this would break parent/child relationships.
  Leaf(const Leaf& no_copy_allowed) = delete;
  // Move constructor used by std collections for moving things around in memory.
  // This calls parent->Replace.
  Leaf(Leaf&& move_allowed);

  // Set this leaf's hash to the newly computed value `new_hash`, updating
  // the entire tree as necessary.
  void Update(const Hash& new_hash);
  // Given the computed `hash` that this Leaf _should_ have, verify that
  // the tree all the way up to the root is valid.
  virtual error::Error Verify(const Hash& hash) const;
 private:
  void Insert();
};

// Internal nodes keep track of whether they're `curr` or `root` so they know
// how best to clean themselves up.
enum class NodeFlag {
  NONE = 0,
  ROOT = 1 << 0,
  CURR = 1 << 1,
};

// Internal node within the tree.
class Node : public Part {
 public:
  Node(Node* parent);
  virtual ~Node();
  bool Full() const { return Parts() == MERKLE_NODE_SIZE; }
  bool Empty() const { return Parts() == 0; }
  // Add the given part to this node.  Will CHECK-fail if this node
  // is currently Full(), or if part->parent() is not already set
  // to this node.
  void Insert(Part* part);
  // Replace the given part with the new one.  Will CHECK-fail if
  // b->parent() is not already this node, if `a` is not a child of
  // this node, or if a->hash() != b->hash().  Used for Part move constructor.
  void Replace(Part* a, Part* b);
  // Remove the given part from this node.  Will CHECK-fail if `part`
  // is not a current child of this node.
  void Remove(Part* part);
  NodeFlag Flags() const { return static_cast<NodeFlag>(flags_); }
  // Update this node (and its parents, recursively) with the hashes
  // of its children.
  void Update();
  // Compute the current hash of this node without changing this node,
  // by computing the hash-of-hashes of its children and setting `hash`
  // to the value.  In a correctly-updated node, it should be the case
  // that:
  //    n->ComputeCurrent(&h);
  //    h == n->hash();
  void ComputeCurrent(Hash* hash) const;
 private:
  // Allow the tree to set and clear flags.
  friend class Tree;
  void SetFlag(NodeFlag f) { flags_ |= static_cast<uint8_t>(f); }
  void ClearFlag(NodeFlag f) { flags_ &= ~static_cast<uint8_t>(f); }

  size_t Parts() const;
  void UpdateCurrent();

  // When a node is created, it will have zero or more children in `children_`.
  // An empty child will be nullptr, and a nullptr child will be treated as
  // having the hash `zero_hash` (defined at global scope, all zeros).
  std::array<Part*, MERKLE_NODE_SIZE> children_;
  uint8_t flags_;
};

// Tree object.  Most of its actual logic is within the functions of Leaf,
// which computes things via loops rather than recursion to decrease
// overhead.
class Tree {
 public:
  Tree();
  ~Tree();
  DELETE_COPY_AND_ASSIGN(Tree);
  // Return the current node, making sure in advance that it has
  // space to store a new leaf.  CurrentWithSpace()->Full() will
  // always return false.
  Node* CurrentWithSpace();

 private:
  Node* root_;
  Node* curr_;
};

}  // namespace svr2::merkle

#endif  // __SVR2_MERKLE_MERKLE_H__
