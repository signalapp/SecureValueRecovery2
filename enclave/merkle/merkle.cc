// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

#include "merkle/merkle.h"
#include <sodium/crypto_auth_hmacsha256.h>
#include <algorithm>
#include "util/macros.h"
#include "util/log.h"
#include "util/constant.h"
#include "metrics/metrics.h"

namespace svr2::merkle {

const Hash zero_hash = {};
static bool IsZeroHash(const Hash& h) {
  return util::ConstantTimeEquals(h, zero_hash);
}

Part::Part(Node* parent) : parent_(parent), hash_(zero_hash) {}
Part::Part(Node* parent, const Hash& hash) : parent_(parent), hash_(hash) {}

void Node::ComputeCurrent(Hash* hash) const {
  std::array<uint8_t, 32> full_hash;
  crypto_hash_sha256_state s;
  crypto_hash_sha256_init(&s);
  for (size_t i = 0; i < MERKLE_NODE_SIZE; i++) {
    Part* p = children_[i];
    const Hash& h = p == nullptr ? zero_hash : p->hash();
    crypto_hash_sha256_update(&s, h.data(), h.size());
  }
  crypto_hash_sha256_final(&s, full_hash.data());
  std::copy_n(full_hash.begin(), std::min(full_hash.size(), hash->size()), hash->begin());
}

Node::Node(Node* parent)
    : Part(parent), children_{0}, flags_(0) {
  COUNTER(merkle, nodes)->Increment();
  ComputeCurrent(&hash_);
}
void Node::Update() {
  ComputeCurrent(&hash_);
  if (parent_ != nullptr) parent_->Update();
}

void Node::Remove(Part* part) {
  bool skip_update = IsZeroHash(part->hash());
  for (size_t i = 0; i < MERKLE_NODE_SIZE; i++) {
    if (part == children_[i]) {
      children_[i] = nullptr;
      if (!skip_update) {
        Update();
      }
      return;
    }
  }
  CHECK(nullptr == "Remove of non-child");
}

void Node::Replace(Part* a, Part* b) {
  CHECK(util::ConstantTimeEquals(a->hash(), b->hash()));
  CHECK(b->parent() == this);
  for (size_t i = 0; i < MERKLE_NODE_SIZE; i++) {
    if (a == children_[i]) {
      children_[i] = b;
      return;
    }
  }
  CHECK(nullptr == "Replace of non-child");
}

size_t Node::Parts() const {
  size_t s = 0;
  for (size_t i = 0; i < MERKLE_NODE_SIZE; i++) {
    if (children_[i] != nullptr) {
      s++;
    }
  }
  return s;
}

void Node::Insert(Part* part) {
  CHECK(part->parent() == this);
  for (size_t i = 0; i < MERKLE_NODE_SIZE; i++) {
    if (children_[i] == nullptr) {
      children_[i] = part;
      if (!IsZeroHash(part->hash())) {
        Update();
      }
      return;
    }
  }
  CHECK(nullptr == "Insert on full node");
}

// This constructor contains the complete logic for growing the tree
// as necessary.  In the base-case, if !n->Full(), it'll just n->Insert(this),
// which should be pretty darn quick.  Note that the leaf is also created
// with hash=zero_hash, the same hash as nullptr, so in that base case
// the nodes of the tree won't even need to Update.  They will
// update, however:
//   - if internal nodes are created during this call
//   - on the first call to leaf->Update
Leaf::Leaf(Tree* t) : Part(t->CurrentWithSpace()) {
  parent_->Insert(this);
  COUNTER(merkle, leaves)->Increment();
}

Node* Tree::CurrentWithSpace() {
  size_t i = 0;
  Node* n = curr_;
  for (; n != root_ && n->Full(); i++, n = n->parent()) {}
  if (n->Full()) {
    // We've reached the root and we're full all the way up.
    CHECK(n == root_);
    Node* new_root = new Node(nullptr);
    root_->parent_ = new_root;
    new_root->Insert(root_);
    root_->ClearFlag(NodeFlag::ROOT);
    root_ = new_root;
    root_->SetFlag(NodeFlag::ROOT);
    i++;
    n = new_root;
    LOG(INFO) << "New merkle depth " << i+1;
  }
  for (; i > 0; i--) {
    Node* new_node = new Node(n);
    n->Insert(new_node);
    n = new_node;
  }
  curr_->ClearFlag(NodeFlag::CURR);
  curr_ = n;
  curr_->SetFlag(NodeFlag::CURR);
  return n;
}

error::Error Leaf::Verify(const Hash& hash) const {
  if (!util::ConstantTimeEquals(hash, hash_)) {
    return COUNTED_ERROR(Merkle_VerifyLeaf);
  }
  // We could recurse here, but this keeps our stack depth and size constant.
  Hash h;
  for (Node* n = parent_; n != nullptr; n = n->parent()) {
    if (n->ComputeCurrent(&h); !util::ConstantTimeEquals(h, n->hash())) {
      return COUNTED_ERROR(Merkle_VerifyNode);
    }
  }
  return error::OK;
}

Part::~Part() {
  if (parent_ != nullptr) {
    parent_->Remove(this);
    // Verify we're not about to delete a special node (CURR or ROOT)
    if (parent_->Empty() && parent_->Flags() == NodeFlag::NONE) {
      delete parent_;
    }
  }
}

void Leaf::Update(const Hash& new_hash) {
  if (util::ConstantTimeEquals(new_hash, hash_)) return;
  std::copy(new_hash.begin(), new_hash.end(), hash_.begin());
  parent_->Update();
}

Leaf::Leaf(Leaf&& from) : Part(from.parent_, from.hash_) {
  COUNTER(merkle, leaves)->Increment();
  parent_->Replace(&from, this);
  from.parent_ = nullptr;
}

Tree::Tree() {
  // This assumes exactly one merkle tree.
  LOG(INFO) << "Intial merkle depth 1";
  root_ = new Node(nullptr);
  curr_ = root_;
  root_->SetFlag(NodeFlag::ROOT);
  root_->SetFlag(NodeFlag::CURR);
}

Tree::~Tree() {
  root_->ClearFlag(NodeFlag::ROOT);
  curr_->ClearFlag(NodeFlag::CURR);
  delete curr_;
}

Node::~Node() {
  COUNTER(merkle, nodes)->Decrement();
}

Leaf::~Leaf() {
  COUNTER(merkle, leaves)->Decrement();
}

}  // namespace svr2::merkle
