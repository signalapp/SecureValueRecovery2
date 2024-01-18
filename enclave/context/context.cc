// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

#include "context/context.h"
#include "metrics/metrics.h"
#include "util/cpu.h"

namespace svr2::context {

Context::Context() : cpu_current_(nullptr), cpu_top_(nullptr, COUNTER(context, cpu_uncategorized)) {
  cpu_top_.SetContext(this);
}

CPUMeasurement::CPUMeasurement(Context* ctx, metrics::Counter* counter)
    : ctx_(nullptr), counter_(counter), ticks_(util::asm_rdtsc()) {
  if (ctx != nullptr) {
    SetContext(ctx);
  }
}

CPUMeasurement::~CPUMeasurement() {
  uint64_t ticks = util::asm_rdtsc();
  if (counter_ != nullptr) {
    counter_->IncrementBy(ticks - ticks_);
  }
  if (parent_ != nullptr) {
    parent_->ticks_ = ticks;
  }
  ctx_->cpu_current_ = parent_;
}

void CPUMeasurement::SetContext(Context* ctx) {
  CHECK(ctx_ == nullptr);
  ctx_ = ctx;
  parent_ = ctx_->cpu_current_;
  ctx_->cpu_current_ = this;
  if (parent_ != nullptr && parent_->counter_ != nullptr) {
    // If there's a parent CPUMeasurement, increment its ticks-so-far.
    // When we're destroyed, we'll push parent_->ticks_ forward so ticks
    // during our lifetime are not double-counted.
    parent_->counter_->IncrementBy(ticks_ - parent_->ticks_);
  }
}

CPUMeasurement Context::MeasureCPU(metrics::Counter* counter) {
  return CPUMeasurement(this, counter);
}

}  // namespace svr2::context
