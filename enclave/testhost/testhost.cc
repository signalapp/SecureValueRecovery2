// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

#include <openenclave/attestation/custom_claims.h>
#include <openenclave/attestation/sgx/evidence.h>
#include <openenclave/attestation/verifier.h>
#include <openenclave/host.h>

#include <array>
#include <cstdio>
#include <cstdlib>
#include <deque>
#include <string>
#include <vector>

#include "../../host/enclave/c/svr2_u.h"
#include "proto/e2e.pb.h"
#include "proto/enclaveconfig.pb.h"
#include "proto/error.pb.h"
#include "proto/msgs.pb.h"
#include "util/constant.h"
#include "util/macros.h"
#include "attestation/attestation.h"

// OCALL implementation
static std::deque<::svr2::EnclaveMessage> out_msgs;

void svr2_output_message(size_t msg_size, unsigned char* msg) {
  fprintf(stderr, "received message\n");
  ::svr2::EnclaveMessage em;
  CHECK(em.ParseFromArray(msg, msg_size));
  out_msgs.emplace_back(std::move(em));
}

namespace {

oe_enclave_t* create_enclave(const char* enclave_path, uint32_t flags) {
  oe_enclave_t* enclave = NULL;

  printf("Host: Enclave library %s\n", enclave_path);
  oe_result_t result = oe_create_svr2_enclave(
      enclave_path, OE_ENCLAVE_TYPE_AUTO, flags, NULL, 0, &enclave);

  if (result != OE_OK) {
    printf("Host: oe_create_attestation_enclave failed. %s",
           oe_result_str(result));
  } else {
    printf("Host: Enclave successfully created.\n");
  }
  return enclave;
}

void terminate_enclave(oe_enclave_t* enclave) {
  oe_terminate_enclave(enclave);
  printf("Host: Enclave successfully terminated.\n");
}

static void print_peer_id(std::array<uint8_t, 32> peer_id) {
  fprintf(stderr, "{");
  for (size_t i = 0; i < 31; ++i) {
    fprintf(stderr, "%u, ", peer_id[i]);
  }
  fprintf(stderr, "%u }\n", peer_id[31]);
}

template <size_t N>
std::string BytesToString(std::array<uint8_t, N> arr) {
  std::string s(N, 0);
  std::copy(arr.begin(), arr.end(), s.begin());
  return s;
}

void VerifyAttestation(const std::string& evidence,
                        const std::string& endorsements,
                        const std::array<uint8_t, 32>& expected_id) {
  auto [claims, claims_length] = svr2::attestation::VerifyAndReadClaims(evidence, endorsements);
  auto free_claims_known_size = [claims_length=claims_length](oe_claim_t* ptr) {
    return oe_free_claims(ptr, claims_length);
  };
  std::unique_ptr<oe_claim_t, decltype(free_claims_known_size)> free_claims(
      claims, free_claims_known_size);

  // evidence is verified, now check id
  std::array<uint8_t, 32> out{0};

  ::svr2::error::Error err =
      ::svr2::attestation::ReadKeyFromVerifiedClaims(claims, claims_length, out);
  CHECK(::svr2::util::ConstantTimeEquals(out, expected_id));
}

class TestEnclave {
  oe_enclave_t* enclave_;
  std::array<uint8_t, 32> id_{0};
  uint32_t flags_;

 public:
  TestEnclave(const char* enclave_path, uint32_t flags) : flags_(flags) {
    this->enclave_ = create_enclave(enclave_path, flags);
  }
  ~TestEnclave() { terminate_enclave(this->enclave_); }

  bool is_simulated() const { return this->flags_ & OE_ENCLAVE_FLAG_SIMULATE; }

  ::svr2::error::Error Init(::svr2::enclaveconfig::EnclaveConfig config) {
    int ret = ::svr2::error::OK;
    std::string serialized_cfg;
    CHECK(config.SerializeToString(&serialized_cfg));
    oe_result_t result =
        svr2_init(this->enclave_, &ret, serialized_cfg.size(),
                  reinterpret_cast<unsigned char*>(serialized_cfg.data()),
                  this->id_.data());
    fprintf(stderr, "Created enclave with id: ");
    print_peer_id(this->id_);
    return ::svr2::error::OK;
  }

  void Connect(TestEnclave& other) {
    oe_result_t result = OE_OK;
    int ret = ::svr2::error::OK;

    // request that peer 0 connect to peer 1
    // construct and serialize the H2E message
    ::svr2::UntrustedMessage h2e_connect_cmd;
    auto her = h2e_connect_cmd.mutable_h2e_request();
    her->set_request_id(1001);
    
    auto req = her->mutable_create_new_raft_group();
    req->set_min_voting_replicas(1);
    req->set_max_voting_replicas(2);

    std::string serialized_req;
    CHECK(h2e_connect_cmd.SerializeToString(&serialized_req));

    // send command to enclave
    result = svr2_input_message(
        this->enclave_, &ret, serialized_req.size(),
        reinterpret_cast<unsigned char*>(serialized_req.data()));
    CHECK(result == OE_OK);
    CHECK(ret == ::svr2::error::OK);

    // Get the peer message
    svr2::EnclaveMessage emsg = std::move(out_msgs.front());
    out_msgs.pop_front();
    CHECK(emsg.inner_case() == svr2::EnclaveMessage::kPeerMessage);

    // if not simulating, extract the attestation and verify it
    if (!this->is_simulated()) {
      ::svr2::e2e::ConnectRequest conn_request;
      CHECK(conn_request.ParseFromString(emsg.peer_message().data()));

      auto remote_attestation = conn_request.attestation();
      VerifyAttestation(remote_attestation.evidence(),
                         remote_attestation.endorsements(), this->id_);
    }

    // get the HostToEnclaveResponse
    svr2::EnclaveMessage h2e_response = std::move(out_msgs.front());
    out_msgs.pop_front();
    CHECK(h2e_response.inner_case() ==
          svr2::EnclaveMessage::kH2EResponse);
    CHECK(h2e_response.h2e_response().status() ==
          ::svr2::error::OK);

    // Forward the peer message to peer 1
    svr2::UntrustedMessage e2e_connect_request;
    *e2e_connect_request.mutable_peer_message() =
        std::move(*emsg.mutable_peer_message());
    // The peer_id field on a PeerMessage is the ID of the sender
    e2e_connect_request.mutable_peer_message()->set_peer_id(
        BytesToString(this->id_));

    CHECK(e2e_connect_request.SerializeToString(&serialized_req));

    // send the peer message to other enclave
    result = svr2_input_message(
        other.enclave_, &ret, serialized_req.size(),
        reinterpret_cast<unsigned char*>(serialized_req.data()));
    CHECK(result == OE_OK);
    CHECK(ret == ::svr2::error::OK);

    // the other enclave produces exactly one messge - a PeerMessage to finish
    // the handshake
    CHECK(out_msgs.size() == 1);
    emsg = std::move(out_msgs.front());
    out_msgs.pop_front();
    CHECK(emsg.inner_case() == svr2::EnclaveMessage::kPeerMessage);

    // forward this message to our enclave
    svr2::UntrustedMessage e2e_connect_response;
    *e2e_connect_response.mutable_peer_message() =
        std::move(*emsg.mutable_peer_message());

    // this message is from `other`
    e2e_connect_response.mutable_peer_message()->set_peer_id(
        BytesToString(other.id_));

    CHECK(e2e_connect_response.SerializeToString(&serialized_req));
    result = svr2_input_message(
        this->enclave_, &ret, serialized_req.size(),
        reinterpret_cast<unsigned char*>(serialized_req.data()));
    CHECK(result == OE_OK);
    CHECK(ret == ::svr2::error::OK);

    // There should be no message from our enclave
    CHECK(out_msgs.size() == 0);
    fprintf(stderr, "handshake successful\n");
  }
};

};  // namespace
bool check_simulate_opt(int* argc, const char* argv[]) {
  for (int i = 0; i < *argc; i++) {
    if (strcmp(argv[i], "--simulate") == 0) {
      fprintf(stdout, "Running in simulation mode\n");
      memmove(&argv[i], &argv[i + 1], (*argc - i) * sizeof(char*));
      (*argc)--;
      return true;
    }
  }
  return false;
}

int main(int argc, const char* argv[]) {
  uint32_t flags = OE_ENCLAVE_FLAG_DEBUG;
  // oe_uuid_t* format_id = nullptr;

  bool simulate = false;
  if (check_simulate_opt(&argc, argv)) {
    flags |= OE_ENCLAVE_FLAG_SIMULATE;
    simulate = true;
  } else {
    CHECK(OE_OK == oe_verifier_initialize());
  }

  // check_simulate_opt decrements argc if it found `--simulate`
  if (argc != 2) {
    fprintf(stderr, "Usage: %s enclave_image_path [ --simulate  ]\n", argv[0]);
    return 1;
  }

  printf("Host: Creating enclave 0\n");
  TestEnclave e0(argv[1], flags);

  printf("Host: Creating enclave 1\n");
  TestEnclave e1(argv[1], flags);

  {
    // create a config pb
    ::svr2::enclaveconfig::EnclaveConfig config;

    auto raft_config = config.mutable_raft();
    raft_config->set_election_ticks(4);
    raft_config->set_heartbeat_ticks(2);
    raft_config->set_replication_chunk_bytes(1 << 20);

    ::svr2::error::Error err = e0.Init(config);
    CHECK(err == ::svr2::error::OK);
    err = e1.Init(config);
    CHECK(err == ::svr2::error::OK);
  }

  e0.Connect(e1);
  return 0;
}
