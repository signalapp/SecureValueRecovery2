// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

#ifndef __SVR2_RAFT_LOG_H__
#define __SVR2_RAFT_LOG_H__

#include <memory>
#include <deque>
#include "raft/types.h"
#include "proto/error.pb.h"
#include "proto/raft.pb.h"
#include "util/macros.h"

namespace svr2::raft {

// Raft log storage.
class Log {
 public:
  Log(size_t max_bytes);

  class Iterator {
   public:
    // Returns true if this iterator points to a valid entry.  If !Valid,
    // other functions will all return default zero-values.
    bool Valid() const;
    // Which index we point to.
    LogIdx Index() const;
    // Return the log entry at this index, nullptr if !Valid.
    const LogEntry* Entry() const;
    // Return the term ID at this index.
    TermId Term() const;
    // Estimated serialized size of the LogEntry proto.
    size_t SerializedSize() const;
    // Estimated in-memory size of this log entry.
    size_t MemSize() const;
    // Move the iterator forward, may invalidate if we're at the end of the log.
    // Typical usage:
    //
    //   for (auto iter = log->At(123); iter.Valid(); iter.Next()) { ... }
    void Next();
    // Move the iterator backwards, may invalidate if we're at the beginning of the log.
    // Typical usage:
    //
    //   for (auto iter = log->At(123); iter.Valid(); iter.Prev()) { ... }
    void Prev();
   private:
    friend class Log;
    Iterator(const Log* log, size_t di) : log_(log), deque_index_(di) {}
    const Log* log_;
    size_t deque_index_;
  };
  // Returns a new iterator.  Any change to the log (Append, RemoveOldestLogOlderThan,
  // CancelFrom) may invalidate this iterator.
  Iterator At(LogIdx idx) const;

  // oldest_stored_idx returns the index of the least recent entry this log stores.
  // It's incremented by a successful call to RemoveOldestLogOlderThan.
  LogIdx oldest_stored_idx() const;
  // last_idx returns the index of the most recent entry this log stores.
  // It's incremented by a successful call to Append.
  LogIdx last_idx() const;
  // next_idx returns the index that a successfully Append'd entry will have.
  LogIdx next_idx() const { return last_idx() + 1; }
  TermId last_term() const;
  size_t log_data_length_bytes() const { return curr_bytes_; }

  // Append a log to the Log.  May return one of the following:
  //  - Raft_LogOutOfSpace:  The log is currently full
  //  - Raft_LogEntryTooLarge:  Rejecting the log entry because it's HUGE
  //  - various other errors?
  // While appending this log, we're allowed to truncate old logs up to (but
  // not including) `maybe_truncate_to` if we run out of space.  We'll only
  // return Raft_LogOutOfSpace if this fails to make enough space for the new
  // log entry.
  error::Error Append(const LogEntry& log, LogIdx maybe_truncate_to);

  // CancelFrom cancels (removes) all logs from the given log index on,
  // leaving only entries of [start,from_log_idx) remaining in the log.
  // This is necessary in cases where an old leader's uncommitted logs are
  // overridden by a new leader.
  error::Error CancelFrom(LogIdx from_log_idx);

  // Get the most recent hash chain value from the log.
  bool MostRecentHash(std::array<uint8_t, 32>* out);

  // If this log is empty, set what the next index will be.  This is useful
  // in cases where we're replicating an already-truncated log.
  error::Error SetNextIdx(LogIdx idx);

  // Return true if there are no log entries in this log.
  bool empty() const { return entries_.size() == 0; }

 public_for_test:
  static size_t logentry_bytes_in_log(const LogEntry& e);
  std::unique_ptr<Log> Copy() const {
    auto r = std::make_unique<Log>(max_bytes_);
    r->entries_ = entries_;
    r->oldest_stored_idx_ = oldest_stored_idx_;
    r->curr_bytes_ = curr_bytes_;

    return r;
  }

 private:
  // RemoveOldestLogOlderThan removes the oldest log from the Log and returns
  // true.  It will return false if there is no log older than [truncate_to].
  bool RemoveOldestLogOlderThan(LogIdx truncate_to);

  friend class Iterator;
  void UpdateMetrics();

  std::deque<LogEntry> entries_;
  LogIdx oldest_stored_idx_;
  size_t curr_bytes_;
  size_t max_bytes_;
};

}  // namespace svr2::raft

#endif  // __SVR2_RAFT_LOG_H__
