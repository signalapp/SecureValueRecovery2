// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

#include "testingclient.h"

#include <gtest/gtest.h>
#include <noise/protocol/errors.h>

#include "testingcore.h"
#include "util/bytes.h"

#define NOISE_OK(x)                                               \
  do {                                                            \
    int out = (x);                                                \
    if (out != NOISE_ERROR_NONE) {                                \
      char buf[64];                                               \
      noise_strerror(out, buf, sizeof(buf));                      \
      ASSERT_EQ(out, NOISE_ERROR_NONE) << "Noise error: " << buf; \
    }                                                             \
  } while (0)

namespace svr2::core::test {

using svr2::util::ByteArrayToString;

TestingClient::TestingClient(TestingCore& core, const std::string& authenticated_id)
    : core_(core),
      client_authenticated_id_(authenticated_id),
      hs_(noise::WrapHandshakeState(nullptr)),
      tx_(noise::WrapCipherState(nullptr)),
      rx_(noise::WrapCipherState(nullptr)) {}

void TestingClient::RequestHandshake() {
  state_ = State::HANDSHAKING;
  ASSERT_EQ(error::OK, core_.NewClientRequest(this, client_authenticated_id_));
  NoiseHandshakeState* hsp;
  NOISE_OK(noise_handshakestate_new_by_id(&hsp, &client::client_protocol,
                                          NOISE_ROLE_INITIATOR));
  hs_ = noise::WrapHandshakeState(hsp);
}

void TestingClient::RequestBackup(SecretData data, PIN pin, uint32_t tries) {
  LOG(INFO) << "sending backup request";

  client::Request req;
  auto b = req.mutable_backup();
  b->set_data(ByteArrayToString(data));
  b->set_pin(ByteArrayToString(pin));
  b->set_max_tries(tries);

  // serialize and encrypt
  std::string req_str;
  ASSERT_TRUE(req.SerializeToString(&req_str));
  auto [ciphertext, encrypt_err] = noise::Encrypt(tx_.get(), req_str);
  ASSERT_EQ(error::OK, encrypt_err);
  ASSERT_EQ(error::OK,
            core_.ExistingClientRequest(this, client_id_, ciphertext));
  state_ = State::AWAITING_BACKUP;
}

void TestingClient::RequestExpose(SecretData data) {
  LOG(INFO) << "sending expose request";

  client::Request req;
  auto b = req.mutable_expose();
  b->set_data(ByteArrayToString(data));

  // serialize and encrypt
  std::string req_str;
  ASSERT_TRUE(req.SerializeToString(&req_str));
  auto [ciphertext, encrypt_err] = noise::Encrypt(tx_.get(), req_str);
  ASSERT_EQ(error::OK, encrypt_err);
  ASSERT_EQ(error::OK,
            core_.ExistingClientRequest(this, client_id_, ciphertext));
  state_ = State::AWAITING_AVAILABLE;
}

void TestingClient::RequestRestore(PIN pin) {
  LOG(INFO) << "sending restore request";

  client::Request req;
  auto b = req.mutable_restore();
  b->set_pin(ByteArrayToString(pin));

  // serialize and encrypt
  std::string req_str;
  ASSERT_TRUE(req.SerializeToString(&req_str));
  auto [ciphertext, encrypt_err] = noise::Encrypt(tx_.get(), req_str);
  ASSERT_EQ(error::OK, encrypt_err);
  ASSERT_EQ(error::OK,
            core_.ExistingClientRequest(this, client_id_, ciphertext));
  state_ = State::AWAITING_RESTORE;
}

void TestingClient::RequestTries() {
  LOG(INFO) << "sending tries request";

  client::Request req;
  req.mutable_tries();

  // serialize and encrypt
  std::string req_str;
  ASSERT_TRUE(req.SerializeToString(&req_str));
  auto [ciphertext, encrypt_err] = noise::Encrypt(tx_.get(), req_str);
  ASSERT_EQ(error::OK, encrypt_err);
  ASSERT_EQ(error::OK,
            core_.ExistingClientRequest(this, client_id_, ciphertext));
  state_ = State::AWAITING_TRIES;
}

void TestingClient::HandleNewClientReply(NewClientReply ncr) {
  client_id_ = ncr.client_id();
  ASSERT_GT(client_id_, 0ul);
  LOG(VERBOSE) << "new client " << client_id_;

  auto hsp = hs_.get();
  auto hs_msg = ncr.handshake_start();
  NOISE_OK(noise_dhstate_set_public_key(
      noise_handshakestate_get_remote_public_key_dh(hsp),
      noise::StrU8Ptr(hs_msg.test_only_pubkey()),
      hs_msg.test_only_pubkey().size()));

  NOISE_OK(noise_handshakestate_start(hsp));
  ASSERT_EQ(NOISE_ACTION_WRITE_MESSAGE, noise_handshakestate_get_action(hsp));

  // Now pass a message to complete the handshake
  std::string data;
  data.resize(noise::HANDSHAKE_INIT_SIZE, '\0');
  NoiseBuffer write_buf = noise::BufferOutputFromString(&data);
  NOISE_OK(noise_handshakestate_write_message(hsp, &write_buf, nullptr));
  data.resize(write_buf.size, '\0');

  core_.ExistingClientRequest(this, client_id_, data);
  // now we wait for the existing client reply to finish the handshake
}

void TestingClient::FinishHandshake(ExistingClientReply ecr) {
  LOG(VERBOSE) << "finish handshake client: " << client_id_;
  auto hsp = hs_.get();
  NoiseCipherState* txp;
  NoiseCipherState* rxp;

  ASSERT_EQ(NOISE_ACTION_READ_MESSAGE, noise_handshakestate_get_action(hsp));
  NoiseBuffer read_buf = noise::BufferInputFromString(ecr.mutable_data());
  NOISE_OK(noise_handshakestate_read_message(hsp, &read_buf, nullptr));
  ASSERT_EQ(NOISE_ACTION_SPLIT, noise_handshakestate_get_action(hsp));
  NOISE_OK(noise_handshakestate_split(hsp, &txp, &rxp));

  tx_ = noise::WrapCipherState(txp);
  rx_ = noise::WrapCipherState(rxp);
  state_ = State::READY;
}

void TestingClient::DecryptClientReply(ExistingClientReply ecr,
                                       client::Response* rsp) {
  auto [plaintext, decrypt_err] = noise::Decrypt(rx_.get(), ecr.data());
  ASSERT_EQ(error::OK, decrypt_err);

  ASSERT_TRUE(rsp->ParseFromString(plaintext));
}

void TestingClient::HandleBackupResponse(ExistingClientReply ecr) {
  client::Response response;
  DecryptClientReply(ecr, &response);
  ASSERT_EQ(response.inner_case(), client::Response::kBackup);
  backup_response_ = response.backup();
  state_ = State::BACKUP_READY;
}
void TestingClient::HandleExposeResponse(ExistingClientReply ecr) {
  client::Response response;
  DecryptClientReply(ecr, &response);
  ASSERT_EQ(response.inner_case(), client::Response::kExpose);
  expose_response_ = response.expose();
  state_ = State::AVAILABLE_READY;
}
void TestingClient::HandleRestoreResponse(ExistingClientReply ecr) {
  client::Response response;
  DecryptClientReply(ecr, &response);
  ASSERT_EQ(response.inner_case(), client::Response::kRestore);
  restore_response_ = response.restore();
  state_ = State::RESTORE_READY;
}
void TestingClient::HandleTriesResponse(ExistingClientReply ecr) {
  client::Response response;
  DecryptClientReply(ecr, &response);
  ASSERT_EQ(response.inner_case(), client::Response::kTries);
  tries_response_ = response.tries();
  state_ = State::TRIES_READY;
}

void TestingClient::HandleExistingClientReply(ExistingClientReply ecr) {
  LOG(VERBOSE) << "state_: "
               << static_cast<std::underlying_type<State>::type>(state_);
  switch (state_) {
    case State::HANDSHAKING:
      return FinishHandshake(ecr);
    case State::AWAITING_BACKUP:
      return HandleBackupResponse(ecr);
    case State::AWAITING_RESTORE:
      return HandleRestoreResponse(ecr);
    case State::AWAITING_AVAILABLE:
      return HandleExposeResponse(ecr);
    case State::AWAITING_TRIES:
      return HandleTriesResponse(ecr);
    default:
      CHECK(false);
  }
}
};  // namespace svr2::core::test
