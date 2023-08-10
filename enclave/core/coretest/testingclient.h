// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

#ifndef __SVR2_CORE_CORETEST_CLIENT_H__
#define __SVR2_CORE_CORETEST_CLIENT_H__

#include <array>
#include <string>

#include "db/db.h"  // for BACKUP_ID_SIZE
#include "noise/noise.h"
#include "proto/client.pb.h"

namespace svr2::core::test {
class TestingCore;

class TestingClient {
 public:
  using PIN = std::array<uint8_t, 32>;
  using SecretData = std::array<uint8_t, 48>;

  client::BackupResponse* get_backup_response() {
    return state_ == State::BACKUP_READY ? &backup_response_ : nullptr;
  }

  client::RestoreResponse* get_restore_response() {
    return state_ == State::RESTORE_READY ? &restore_response_ : nullptr;
  }

  client::ExposeResponse* get_expose_response() {
    return state_ == State::AVAILABLE_READY ? &expose_response_ : nullptr;
  }

  client::TriesResponse* get_tries_response() {
    return state_ == State::TRIES_READY ? &tries_response_ : nullptr;
  }

  // These functions return void so that we can use gtest assertions inside
  // them. (gtest asertions that generate a fatal failure can only be used with
  // void-returning functions:
  // https://chromium.googlesource.com/external/github.com/google/googletest/+/HEAD/docs/advanced.md#assertion-placement)
  void RequestHandshake();
  void RequestBackup(SecretData data, PIN pin, uint32_t tries);
  void RequestExpose(SecretData data);
  void RequestRestore(PIN pin);
  void RequestTries();

  void HandleNewClientReply(NewClientReply ncr);
  void HandleExistingClientReply(ExistingClientReply ecr);

  TestingClient(TestingCore& core, const std::string& authenticated_id);

 private:
  enum class State {
    NO_HANDSHAKE,
    HANDSHAKING,
    READY,
    AWAITING_BACKUP,
    AWAITING_RESTORE,
    AWAITING_AVAILABLE,
    AWAITING_TRIES,
    BACKUP_READY,
    RESTORE_READY,
    AVAILABLE_READY,
    TRIES_READY
  };
  void FinishHandshake(ExistingClientReply ecr);
  void HandleBackupResponse(ExistingClientReply ecr);
  void HandleExposeResponse(ExistingClientReply ecr);
  void HandleRestoreResponse(ExistingClientReply ecr);
  void HandleTriesResponse(ExistingClientReply ecr);
  void DecryptClientReply(ExistingClientReply ecr, client::Response* rsp);

  TestingCore& core_;
  std::string client_authenticated_id_;
  uint64_t client_id_{0};
  State state_{State::NO_HANDSHAKE};
  noise::HandshakeState hs_;
  noise::CipherState tx_;
  noise::CipherState rx_;

  client::BackupResponse backup_response_;
  client::RestoreResponse restore_response_;
  client::ExposeResponse expose_response_;
  client::TriesResponse tries_response_;
};

};  // namespace svr2::core::test

#endif  // __SVR2_CORE_CORETEST_CLIENT_H__
