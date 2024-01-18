// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

#ifndef __SVR2_CONTEXT_CONTEXT_H__
#define __SVR2_CONTEXT_CONTEXT_H__

#include <google/protobuf/arena.h>
#include <mutex>

#include "util/macros.h"
#include "metrics/metrics.h"
#include "util/mutex.h"

namespace svr2::context {

class Context;

// Class CPUMeasurement allows for counting of CPU ticks used in parts of code.
// On creation, it records the number of CPU ticks, and on destruction it adds
// those ticks to a counter.  It's not stand-alone - use Context.MeasureCPU or
// better-yet use the MEASURE_CPU macro.
//
// Usage:
//
//   void Foo(ctx) {
//     MEASURE_CPU(ctx, cpu_foo);
//     ... stuff #1 ...
//     Bar(ctx)
//     ... stuff #2 ...
//   }
//   void Bar(ctx) {
//     MEASURE_CPU(ctx, cpu_bar);  // turns off cpu_foo ticking, then back on when destroyed
//     ... stuff #3 ...
//   }
//
// This will count CPU ticks of stuff#1 and stuff#2 (but NOT stuff#3) in
// COUNTER(context, cpu_foo), and measure stuff#3 in COUNTER(context, cpu_bar).
class CPUMeasurement {
 public:
  ~CPUMeasurement();
 private:
  friend class Context;
  CPUMeasurement(Context* ctx, metrics::Counter* counter);
  void SetContext(Context* ctx);

  Context* ctx_;
  metrics::Counter* counter_;
  CPUMeasurement* parent_;  // Provides a singly-linked list back to parent CPUMeasurements.
  uint64_t ticks_;
};

class Context {
 public:
  DELETE_COPY_AND_ASSIGN(Context);
  Context();

  // Protobuf<T> creates a protobuf of type <T> that has a lifetime tied
  // to the lifetime of this Context (IE: when this context falls out of scope,
  // it will be cleaned up) using a protobuf Arena.  This optimization allows
  // for much faster creation and deletion of intermediate protobufs.  However,
  // care should be taken to not store the output of this function long-term
  // in a class that will live beyond the scope of this Context, as the pointer
  // will be invalidated at that time.
  template <class T>
  T* Protobuf() {
    return google::protobuf::Arena::CreateMessage<T>(&arena_);
  }

  CPUMeasurement MeasureCPU(metrics::Counter* counter);

  // All protobufs returned by Protobuf() are no longer valid after this call.
  void GarbageCollectProtobufs() { arena_.Reset(); }

 private:
  friend class CPUMeasurement;
  google::protobuf::Arena arena_;
  CPUMeasurement* cpu_current_;
  CPUMeasurement cpu_top_;
};

}  // namespace svr2::context

#define MEASURE_CPU(ctx, name) MEASURE_CPU_CTR1(ctx, name, __COUNTER__)
#define MEASURE_CPU_CTR1(ctx, name, ctr) MEASURE_CPU_CTR2(ctx, name, ctr)
#define MEASURE_CPU_CTR2(ctx, name, ctr) \
    ::svr2::context::CPUMeasurement __cpumeasure_ ## ctr = (ctx)->MeasureCPU(COUNTER(context, name))
#define IGNORE_CPU(ctx) IGNORE_CPU_CTR1(ctx, __COUNTER__)
#define IGNORE_CPU_CTR1(ctx, ctr) IGNORE_CPU_CTR2(ctx, ctr)
#define IGNORE_CPU_CTR2(ctx, ctr) \
    ::svr2::context::CPUMeasurement __cpuignore_ ## ctr = (ctx)->MeasureCPU(nullptr)

// Creates an RAII util::unique_lock named `lockname`.  Use this
// if you need to do things with the lock after you create it (e.g., explicitly
// calling `unlock()`).
#define ACQUIRE_NAMED_LOCK(lockname, mu, ctx, name) \
    util::unique_lock lockname(mu, std::defer_lock); \
    { \
      MEASURE_CPU(ctx, name); \
      lockname.lock(); \
    }
// Creates an RAII util::unique_lock on the given mu with an arbitrary
// name, for when you need `mu` locked but you're not doing anything
// tricky with it like manually unlocking it after.  This is more like
// std::lock_guard.
#define ACQUIRE_LOCK(mu, ctx, name) ACQUIRE_NAMED_LOCK(__lock_ ## __COUNTER__, mu, ctx, name)

#endif  // __SVR2_CONTEXT_CONTEXT_H__
