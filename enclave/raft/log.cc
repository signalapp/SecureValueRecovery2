// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

#include "raft/log.h"
#include "peerid/peerid.h"
#include <algorithm>
#include "util/log.h"
#include "metrics/metrics.h"

namespace svr2::raft {

// Guess the size of the logentry in bytes in memory, including the
// container (map node and key) holding it.
size_t Log::logentry_bytes_in_log(const LogEntry& e) {
  // Estimate size of membership change proto.
  size_t mem_change = 0;
  if (e.has_membership_change()) {
    mem_change +=
        sizeof(ReplicaGroup) +
        // for each replica:
        e.membership_change().replicas_size() * (
            // each replica should point to a string of this size
            sizeof(peerid::PeerID) +
            // plus the size of the replica object itself
            sizeof(Replica));
  }
  if (e.hash_chain().size()) {
    mem_change += e.hash_chain().size() +
        sizeof(std::string);
  }
  return mem_change +
      // Size of the value
      sizeof(LogEntry) +
      // Size of the data on the heap, which should be at least a length and the actual bytes
      sizeof(std::string) + e.data().size();
}

Log::Log(size_t max_bytes) : oldest_stored_idx_(1), curr_bytes_(0), max_bytes_(max_bytes) {
  GAUGE(raft, log_total_size)->Set(max_bytes_);
  UpdateMetrics();
}

error::Error Log::CancelFrom(LogIdx from_log_idx) {
  if (from_log_idx < oldest_stored_idx_) {
    return COUNTED_ERROR(Raft_CancelingBeforeFirst);
  }
  size_t index = from_log_idx - oldest_stored_idx_;
  entries_.resize(index);
  return error::OK;
}

Log::Iterator Log::At(LogIdx idx) const {
  size_t di = idx < oldest_stored_idx_ ? entries_.size() : idx - oldest_stored_idx_;
  return Iterator(this, di);
}

LogIdx Log::Iterator::Index() const {
  if (!Valid()) return 0;
  return log_->oldest_stored_idx_ + deque_index_;
}

bool Log::Iterator::Valid() const {
  return deque_index_ < log_->entries_.size();
}

const LogEntry* Log::Iterator::Entry() const {
  if (!Valid()) return nullptr;
  return &log_->entries_[deque_index_];
}

TermId Log::Iterator::Term() const {
  if (!Valid()) return 0;
  return Entry()->term();
}

size_t Log::Iterator::SerializedSize() const {
  if (!Valid()) return 0;
  // We called ByteSizeLong when we appended this log entry, and its
  // size can't have changed since, so GetCachedSize will give us the
  // correct value.  Guaranteed to be >= 1 since we check that term()
  // is nonzero.  Must return a value <= INT_MAX, since GetCachedSize
  // returns an int.
  return (size_t) Entry()->GetCachedSize();
}

size_t Log::Iterator::MemSize() const {
  if (!Valid()) return 0;
  return logentry_bytes_in_log(*Entry());
}

void Log::Iterator::Next() {
  if (Valid()) { ++deque_index_; }
}

void Log::Iterator::Prev() {
  if (Valid()) { --deque_index_; }
}

LogIdx Log::oldest_stored_idx() const {
  if (entries_.size() == 0) { return 0; }
  return oldest_stored_idx_;
}

LogIdx Log::last_idx() const {
  if (entries_.size() == 0) { return 0; }
  return oldest_stored_idx_ + entries_.size() - 1;
}

LogIdx Log::last_term() const {
  if (entries_.size() == 0) { return 0; }
  return At(last_idx()).Term();
}

error::Error Log::Append(const LogEntry& log, LogIdx maybe_truncate_to) {
  if (log.term() == 0) {
    return COUNTED_ERROR(Raft_AppendWithoutTerm);
  }
  if (log.hash_chain().size() != 32) {
    return COUNTED_ERROR(Raft_NoHashChainInAppend);
  }
  size_t mem = logentry_bytes_in_log(log);
  while (curr_bytes_ + mem > max_bytes_) {
    if (!RemoveOldestLogOlderThan(maybe_truncate_to)) {
      return COUNTED_ERROR(Raft_LogOutOfSpace);
    }
  }
  // Don't allow larger than 2G, since that'll mess up our call to GetCachedSize
  // which returns an int.
  if (log.ByteSizeLong() > INT_MAX) {
    return COUNTED_ERROR(Raft_LogEntryTooLarge);
  }
  // This creates a copy of the log, which is important since the
  // original log we got the reference from may fall out of scope before
  // we do.
  entries_.emplace_back(log);
  // Re-compute byte size, in the new location.
  entries_.rbegin()->ByteSizeLong();
  curr_bytes_ += mem;
  UpdateMetrics();
  return error::OK;
}

bool Log::RemoveOldestLogOlderThan(LogIdx truncate_to) {
  if (oldest_stored_idx_ >= truncate_to) return false;
  size_t mem = logentry_bytes_in_log(entries_.front());
  entries_.pop_front();
  oldest_stored_idx_++;
  curr_bytes_ -= mem;
  return true;
}

void Log::UpdateMetrics() {
  GAUGE(raft, log_oldest_stored_log_index)->Set(oldest_stored_idx());
  GAUGE(raft, log_last_log_index)->Set(last_idx());
  GAUGE(raft, log_last_log_term)->Set(last_term());
  GAUGE(raft, log_size)->Set(curr_bytes_);
  GAUGE(raft, log_entries)->Set(entries_.size());
}

bool Log::MostRecentHash(std::array<uint8_t, 32>* out) {
  for (auto iter = At(last_idx()); iter.Valid(); iter.Prev()) {
    if (iter.Entry()->hash_chain().size() == out->size()) {
      std::copy(iter.Entry()->hash_chain().cbegin(), iter.Entry()->hash_chain().cend(), out->begin());
      return true;
    }
  }
  return false;
}

error::Error Log::SetNextIdx(LogIdx idx) {
  if (entries_.size()) {
    return COUNTED_ERROR(Raft_SetNextOnNonemptyLog);
  }
  oldest_stored_idx_ = idx;
  return error::OK;
}

}  // namespace svr2::raft
