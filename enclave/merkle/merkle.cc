// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

#include "merkle/merkle.h"
#include <algorithm>
#include <mutex>
#include "util/macros.h"
#include "util/log.h"
#include "util/constant.h"
#include "metrics/metrics.h"
#include "env/env.h"
#include "sip/hasher.h"

namespace svr2::merkle {

const Hash zero_hash = {0};
static std::array<uint8_t, 16> initial_sip_key = {0};
static sip::Full sip_full(initial_sip_key);

static std::once_flag sip_key_once;
static void SetSIPKey() {
  LOG(INFO) << "Setting SIP key to random bytes";
  std::array<uint8_t, 16> new_sip_key;
  env::environment->RandomBytes(new_sip_key.data(), new_sip_key.size());
  sip_full.ResetKey(new_sip_key);
}

Part::Part(Node* parent) : parent_(parent) {
  hptr_ = parent_->Insert(this);
}
Part::Part(Hash* hptr) : parent_(nullptr), hptr_(hptr) {}
Part::Part() : parent_(nullptr), hptr_(nullptr) {}

void Node::ComputeCurrent(Hash* hash) const {
  *hash = sip_full.Hash8(hashes_[0].data(), MERKLE_HASH_SIZE * MERKLE_NODE_SIZE);
}

void Node::Init() {
  memset(hashes_[0].data(), 0, MERKLE_HASH_SIZE * MERKLE_NODE_SIZE);
  memset(&children_[0], 0, sizeof(children_));
  flags_ = 0;
  COUNTER(merkle, nodes)->Increment();
}

Node::Node(Node* parent) : Part(parent) {
  Init();
}

Node::Node(Hash* hptr) : Part(hptr) {
  Init();
}

void Node::Update() {
  ComputeCurrent(hptr_);
  if (parent_ != nullptr) parent_->Update();
}

void Node::Remove(Part* part) {
  for (size_t i = 0; i < MERKLE_NODE_SIZE; i++) {
    if (part == children_[i]) {
      children_[i] = nullptr;
      hashes_[i] = zero_hash;
      Update();
      return;
    }
  }
  CHECK(nullptr == "Remove of non-child");
}

Hash* Node::Replace(Part* a, Part* b) {
  CHECK(a->parent() == this);
  CHECK(b->parent() == this);
  for (size_t i = 0; i < MERKLE_NODE_SIZE; i++) {
    if (a == children_[i]) {
      children_[i] = b;
      return &hashes_[i];
    }
  }
  CHECK(nullptr == "Replace of non-child");
  return nullptr;
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

Hash* Node::Insert(Part* part) {
  CHECK(part->parent() == this);
  for (size_t i = 0; i < MERKLE_NODE_SIZE; i++) {
    if (children_[i] == nullptr) {
      children_[i] = part;
      return &hashes_[i];
    }
  }
  CHECK(nullptr == "Insert on full node");
}

// This constructor contains the complete logic for growing the tree
// as necessary.  In the base-case, if !n->Full(), it'll just n->Insert(this),
// which should be pretty darn quick.  As mentioned in the header,
// leaf.Update() _must_ be called after construction, or the tree may
// be invalid.
Leaf::Leaf(Tree* t) : Part(t->CurrentWithSpace()) {
  COUNTER(merkle, leaves)->Increment();
}

Node* Tree::CurrentWithSpace() {
  size_t i = 0;
  Node* n = curr_;
  for (; n != root_ && n->Full(); i++, n = n->parent()) {}
  if (n->Full()) {
    // We've reached the root and we're full all the way up.
    // We need to create a new root, which is a node with:
    //   parent_ == nullptr
    //   hptr_ = &roothash_
    // This requires some moving around of the current root,
    // whose hptr_ is currently &roothash_, so that it starts
    // to act like a "normal" internal node pointing to hashes_[0] 
    // inside the new root.
    CHECK(n == root_);
    // Create a new root node
    Node* new_root = new Node(&roothash_);
    // Rewire the old root to store its hash in the new root.
    root_->parent_ = new_root;
    root_->hptr_ = new_root->Insert(root_);
    *root_->hptr_ = roothash_;
    // Make the new node the actual root
    root_->ClearFlag(NodeFlag::ROOT);
    root_ = new_root;
    root_->SetFlag(NodeFlag::ROOT);
    // All done!
    i++;
    n = root_;
    LOG(INFO) << "New merkle depth " << i+1;
  }
  for (; i > 0; i--) {
    n = new Node(n);
  }
  if (curr_ != n) {
    curr_->ClearFlag(NodeFlag::CURR);
    curr_ = n;
    curr_->SetFlag(NodeFlag::CURR);
  }
  return n;
}

error::Error Leaf::Verify(const Hash& computed) const {
  if (!util::ConstantTimeEquals(computed, hash())) {
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
  std::copy(new_hash.begin(), new_hash.end(), hptr_->begin());
  parent_->Update();
}

Leaf::Leaf(Leaf&& from) : Part() {
  COUNTER(merkle, leaves)->Increment();
  parent_ = from.parent_;
  hptr_ = parent_->Replace(&from, this);
  from.parent_ = nullptr;
  from.hptr_ = nullptr;
}

Tree::Tree() {
  std::call_once(sip_key_once, SetSIPKey);
  // This assumes exactly one merkle tree.
  LOG(INFO) << "Intial merkle depth 1";
  root_ = new Node(&roothash_);
  curr_ = root_;
  root_->SetFlag(NodeFlag::ROOT);
  root_->SetFlag(NodeFlag::CURR);
  root_->Update();
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
