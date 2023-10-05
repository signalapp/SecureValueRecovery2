// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

//TESTDEP gtest
//TESTDEP metrics
//TESTDEP context
//TESTDEP proto
//TESTDEP protobuf-lite

#include <gtest/gtest.h>
#include "proto/error.pb.h"
#include "metrics/metrics.h"
#include "context/context.h"

namespace svr2::metrics {

class MetricsTest : public ::testing::Test {
 protected:
  void SetUp() {
    ClearAllForTest();
  }

  const int FindCounter(const MetricsPB& pb, const std::string& name, const std::map<std::string, std::string>& tags) {
    for (int i = 0; i < pb.counters_size(); i++) {
      auto c = pb.counters(i);
      if (name != c.name() || tags.size() != c.tags().size()) {
        continue;
      }
      bool tags_equal = true;
      for (auto iter = tags.cbegin(); iter != tags.cend() && tags_equal; ++iter) {
        if (c.tags().count(iter->first) == 0 ||
            c.tags().at(iter->first) != iter->second) {
          tags_equal = false;
          break;
        }
      }
      if (!tags_equal) { continue; }
      return i;
    }
    return -1;
  }
  const int FindGauge(const MetricsPB& pb, const std::string& name) {
    for (int i = 0; i < pb.gauges_size(); i++) {
      auto c = pb.gauges(i);
      if (name == c.name()) { return i; }
    }
    return -1;
  }

  context::Context ctx;
};

error::Error ReturnsGeneralUnimplemented() {
  return COUNTED_ERROR(General_Unimplemented);
}

error::Error ReturnsCoreReInit() {
  return COUNTED_ERROR(Core_ReInit);
}

TEST_F(MetricsTest, CountsReturnedErrors) {
  for (int i = 0; i < 3; i++) {
    ReturnsGeneralUnimplemented();
  }
  MetricsPB* got = AllAsPB(&ctx);
  ASSERT_EQ(got->counters_size(), 1 + COUNTERS_ARRAY_SIZE);
  auto c = got->counters(0);
  ASSERT_EQ(c.v(), 3);
  ASSERT_EQ(c.tags().at("error"), "General_Unimplemented");
  for (int i = 0; i < 5; i++) {
    ReturnsCoreReInit();
  }
  got = AllAsPB(&ctx);
  ASSERT_EQ(got->counters_size(), 2 + COUNTERS_ARRAY_SIZE);
  c = got->counters(0);
  ASSERT_EQ(c.v(), 3);
  ASSERT_EQ(c.tags().at("error"), "General_Unimplemented");
  c = got->counters(1);
  ASSERT_EQ(c.v(), 5);
  ASSERT_EQ(c.tags().at("error"), "Core_ReInit");
}

TEST_F(MetricsTest, Counters) {
  COUNTER(core, peer_msgs_received)->Increment();
  COUNTER(core, peer_msgs_received)->Increment();
  COUNTER(core, peer_msgs_received)->Increment();
  MetricsPB* got = AllAsPB(&ctx);
  int i = FindCounter(*got, "core.msgs_received", {{"type", "peer_message"}});
  ASSERT_GE(i, 0);
  auto c = got->counters(i);
  ASSERT_EQ(c.name(), "core.msgs_received");
  ASSERT_EQ(c.tags().size(), 1);
  ASSERT_EQ(c.tags().at("type"), "peer_message");
  ASSERT_EQ(c.v(), 3);
}

TEST_F(MetricsTest, Gauges) {
  MetricsPB* got = AllAsPB(&ctx);
  ASSERT_EQ(got->gauges_size(), 0);
  GAUGE(test, test1)->Set(123);
  got = AllAsPB(&ctx);
  ASSERT_EQ(got->gauges_size(), 1);
  EXPECT_EQ(got->gauges(0).name(), "test.test1");
  EXPECT_EQ(got->gauges(0).v(), 123);
  GAUGE(test, test2)->Set(234);
  GAUGE(test, test1)->Set(345);
  got = AllAsPB(&ctx);
  ASSERT_EQ(got->gauges_size(), 2);
  int t1 = FindGauge(*got, "test.test1");
  int t2 = FindGauge(*got, "test.test2");
  ASSERT_GE(t1, 0);
  ASSERT_GE(t2, 0);
  auto g1 = got->gauges(t1);
  auto g2 = got->gauges(t2);
  EXPECT_EQ(g1.name(), "test.test1");
  EXPECT_EQ(g1.v(), 345);
  EXPECT_EQ(g2.name(), "test.test2");
  EXPECT_EQ(g2.v(), 234);
  GAUGE(test, test1)->Clear();
  got = AllAsPB(&ctx);
  ASSERT_EQ(got->gauges_size(), 1);
  EXPECT_EQ(got->gauges(0).name(), "test.test2");
  EXPECT_EQ(got->gauges(0).v(), 234);
}

}  // namespace svr2::metrics
