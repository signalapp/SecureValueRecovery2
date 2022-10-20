// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

#ifndef __SVR2_METRICS_METRICS_H__
#define __SVR2_METRICS_METRICS_H__

#include <string>
#include <atomic>

#include "proto/metrics.pb.h"
#include "proto/error.pb.h"

namespace svr2::metrics {

// Export all global metrics as a single protobuf.
MetricsPB AllAsPB();

// Return all global metrics to an initial state.  For testing only.
void ClearAllForTest();

// A counter provides a simple, atomic counter object that monotonically increases.
// We do not protect against overflows, but given that this is a 64-bit value, they
// would be pretty impressive.
class Counter {
 public:
  Counter(const std::string& name, std::map<std::string, std::string>&& tags);
  void IncrementBy(uint64_t v);
  inline void Increment() { IncrementBy(1); }
 private:
  friend MetricsPB AllAsPB();
  friend void ClearAllForTest();
  void AddToMetrics(MetricsPB* pb);
  void Clear();
  std::atomic<uint64_t> v_;
  const std::string name_;
  const std::map<std::string, std::string> tags_;
};

// A gauge provides a simple, atomic gauge object that can be set to arbitrary
// values.  We save UINT64_MAX as a special invalid value.
class Gauge {
 public:
  Gauge(const std::string& name);
  void Set(uint64_t v);
  void Clear();
 private:
  friend MetricsPB AllAsPB();
  friend void ClearAllForTest();
  void AddToMetrics(MetricsPB* pb);
  std::atomic<uint64_t> v_;
  const std::string name_;
};

// We use the somewhat tricky counters.h/gauges.h file to generate a set of metricss
// that are both accessible to the rest of the code and iterable by this code.
// In short, we use a CREATE_COUNTER/CREATE_GAUGE macros, which we define/include/undef,
// both here and in metrics.cc, to generate the header and source parts of the metrics.
enum Counters {
#define CREATE_COUNTER(ns, varname, name, tags) CTR__##ns##__##varname,
#include "counters.h"
#undef CREATE_COUNTER
  COUNTERS_ARRAY_SIZE,
};
enum Gauges {
#define CREATE_GAUGE(ns, name) GAG__##ns##__##name,
#include "gauges.h"
#undef CREATE_GAUGE
  GAUGES_ARRAY_SIZE,
};

namespace internal {
error::Error RecordError(error::Error);
extern Counter counters[COUNTERS_ARRAY_SIZE];
extern Gauge gauges[GAUGES_ARRAY_SIZE];
}  // namespace internal

}  // namespace svr2::metrics

// COUNTER(ns, name) returns a pointer to a metrics::Counter based on the
// counter namespace/name as created in counters.h.
#define COUNTER(ns, name) (&::svr2::metrics::internal::counters[::svr2::metrics::CTR__##ns##__##name])

// GAUGE(ns, name) returns a pointer to a metrics::Gauge based on the
// gauge namespace/name as created in gauges.h.
#define GAUGE(ns, name) (&::svr2::metrics::internal::gauges[::svr2::metrics::GAG__##ns##__##name])

// COUNTED_ERROR counts an error within metrics, returning that same error.
// It's generally used like:
//    return COUNTED_ERROR(Foo_Bar);
#define COUNTED_ERROR(x) ::svr2::metrics::internal::RecordError(error::x)

#endif  // __SVR2_METRICS_METRICS_H__
