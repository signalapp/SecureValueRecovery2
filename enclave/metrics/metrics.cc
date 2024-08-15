// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

#include "metrics/metrics.h"
#include "context/context.h"

namespace svr2::metrics {

namespace {
static std::atomic<uint64_t> recorded_errors[error::Error_ARRAYSIZE] = {0};
}  // namespace

MetricsPB* AllAsPB(context::Context* ctx) {
  auto out = ctx->Protobuf<MetricsPB>();
  for (int i = 0; i < error::Error_ARRAYSIZE; i++) {
    if (error::Error_IsValid(i)) {
      uint64_t v = recorded_errors[i].load();
      if (v > 0) {
        U64PB* counter = out->add_counters();
        counter->set_name("errors");
        (*counter->mutable_tags())["error"] = error::Error_Name(i);
        counter->set_v(v);
      }
    }
  }
  for (int i = 0; i < COUNTERS_ARRAY_SIZE; i++) {
    internal::counters[i].AddToMetrics(out);
  }
  for (int i = 0; i < GAUGES_ARRAY_SIZE; i++) {
    internal::gauges[i].AddToMetrics(out);
  }
  return out;
}

void ClearAllForTest() {
  for (int i = 0; i < error::Error_ARRAYSIZE; i++) {
    recorded_errors[i].store(0);
  }
  for (int i = 0; i < COUNTERS_ARRAY_SIZE; i++) {
    internal::counters[i].Clear();
  }
}

Counter::Counter(const std::string& name, std::map<std::string, std::string>&& tags)
    : name_(name), tags_(tags) {}

void Counter::IncrementBy(uint64_t v) {
  v_.fetch_add(v);
}

void Counter::AddToMetrics(MetricsPB* pb) {
  auto c = pb->add_counters();
  c->set_name(name_);
  c->set_v(v_.load());
  for (auto iter = tags_.cbegin(); iter != tags_.cend(); ++iter) {
    (*c->mutable_tags())[iter->first] = iter->second;
  }
}

void Counter::Clear() {
  v_.store(0);
}

Gauge::Gauge(const std::string& name)
    : v_(UINT64_MAX), name_(name) {}

void Gauge::Set(uint64_t v) {
  v_.store(v);
}

void Gauge::AddToMetrics(MetricsPB* pb) {
  uint64_t v = v_.load();
  if (v == UINT64_MAX) { return; }
  auto c = pb->add_gauges();
  c->set_name(name_);
  c->set_v(v);
}

void Gauge::Clear() {
  v_.store(UINT64_MAX);
}

namespace internal {
error::Error RecordError(error::Error e, const char* file, int line) {
  LOG(VERBOSE) << e << " @ " << file << ":" << line;
  recorded_errors[e].fetch_add(1);
  return e;
}

Counter counters[COUNTERS_ARRAY_SIZE] = {
#define CREATE_COUNTER(ns, varname, name, tags) Counter(#ns "." #name, std::map<std::string, std::string>tags),
#include "counters.h"
#undef CREATE_COUNTER
};
Gauge gauges[GAUGES_ARRAY_SIZE] = {
#define CREATE_GAUGE(ns, name) Gauge(#ns "." #name),
#include "gauges.h"
#undef CREATE_GAUGE
};
}  // namespace internal

}  // namespace svr2::metrics
