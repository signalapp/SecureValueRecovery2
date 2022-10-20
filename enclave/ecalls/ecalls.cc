// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

#include <stdint.h>
#include <memory>
#include <atomic>
#include <mutex>
#include <cstdlib>
#include "svr2/svr2_t.h"
#include "core/core.h"
#include "proto/error.pb.h"
#include "proto/enclaveconfig.pb.h"
#include "env/env.h"
#include "context/context.h"
#include "util/endian.h"
#include "util/log.h"
#include "metrics/metrics.h"

namespace svr2::ecalls {
namespace {

void SeedWeakRandom() {
  LOG(INFO) << "Seeding weak randomness with strong";
  // Best-effort seeding of weak randomness from strong.
  uint8_t bytes[8];
  env::environment->RandomBytes(bytes, sizeof(bytes));
  srand(util::BigEndian64FromBytes(bytes));
}
std::unique_ptr<svr2::core::Core> global_core;
// Sadly, we don't appear to have access to std::shared_mutex, so we use
// the next best thing.
enum class GlobalCoreState {
  UNINITIATED = 0,
  INITIATING = 1,
  INITIATED = 2,
};
std::atomic<GlobalCoreState> global_core_state(GlobalCoreState::UNINITIATED);

}  // namespace

extern "C" {

int svr2_init(
    size_t config_size,
    unsigned char* config,
    unsigned char* peer_id) {
  context::Context ctx;
  COUNTER(ecalls, init_calls)->Increment();
  GlobalCoreState state_expected = GlobalCoreState::UNINITIATED;
  GlobalCoreState state_requested = GlobalCoreState::INITIATING;
  if (!global_core_state.compare_exchange_strong(state_expected, state_requested)) {
    return COUNTED_ERROR(Core_ReInit);
  }

  enclaveconfig::InitConfig config_pb;
  if (!config_pb.ParseFromArray(config, config_size)) {
    global_core_state.store(GlobalCoreState::UNINITIATED);
    return COUNTED_ERROR(Core_ConfigProtobufParse);
  }
  if (config_pb.initial_log_level() != enclaveconfig::LOG_LEVEL_NONE) {
    util::SetLogLevel(config_pb.initial_log_level());
  }

  env::Init(config_pb.group_config().simulated());  // Can be called more than once, but never concurrently.
  SeedWeakRandom();

  LOG(INFO) << "Creating core";
  auto [core, err] = core::Core::Create(&ctx, config_pb);
  if (err != error::OK) {
    global_core_state.store(GlobalCoreState::UNINITIATED);
    return err;
  }
  global_core = std::move(core);
  const auto peer_id_array = global_core->ID().Get();
  std::copy(peer_id_array.begin(), peer_id_array.end(), peer_id);
  global_core_state.store(GlobalCoreState::INITIATED);
  return error::OK;
}

int svr2_input_message(
    size_t msg_size,
    unsigned char* msg) {
  context::Context ctx;
  COUNTER(ecalls, host_messages_received)->Increment();
  COUNTER(ecalls, host_bytes_received)->IncrementBy(msg_size);
  if (global_core_state.load() != GlobalCoreState::INITIATED) {
    return COUNTED_ERROR(Core_NoInit);
  }
  UntrustedMessage* msg_pb = ctx.Protobuf<UntrustedMessage>();
  if (!msg_pb->ParseFromArray(msg, msg_size)) {
    return COUNTED_ERROR(Core_ReceiveProtobufParse);
  }
  return global_core->Receive(&ctx, *msg_pb);
}

}  // extern "C"
}  // namespace svr2::ecalls
