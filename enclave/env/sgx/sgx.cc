// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

#include <openenclave/attestation/attester.h>
#include <openenclave/attestation/custom_claims.h>
#include <openenclave/attestation/sgx/evidence.h>
#include <openenclave/attestation/verifier.h>
#include <openenclave/bits/evidence.h>
#include <openenclave/enclave.h>
#include <openenclave/advanced/mallinfo.h>

#include <memory>

#include "attestation/oe/attestation.h"
#include "env/env.h"
#include "metrics/metrics.h"
#include "svr2/svr2_t.h"
#include "util/constant.h"
#include "util/log.h"
#include "util/bytes.h"

namespace svr2::env {
namespace sgx {

static const char* unattested_evidence_prefix = "UNATTESTED EVIDENCE:";
static const char* custom_claim_pk = "pk";
static const char* custom_claim_config = "config";
static const char* custom_claim_minimum_limits = "minimum_limits";

class Environment : public ::svr2::env::Environment {
 public:
  DELETE_COPY_AND_ASSIGN(Environment);
  Environment(bool simulated) : ::svr2::env::Environment(), simulated_(simulated) {
    if (!simulated_) {
      if (auto r = oe_attester_initialize(); r != OE_OK) {
        LOG(ERROR) << "oe_attester_initialize: " << r;
        CHECK(false);
      }
      if (auto r = oe_verifier_initialize(); r != OE_OK) {
        LOG(ERROR) << "oe_verifier_initialize: " << r;
        CHECK(false);
      }
      CHECK(error::OK == GetMRENCLAVE());
    }
  }

  virtual ~Environment() {
    if (!simulated_) {
      oe_attester_shutdown();
      oe_verifier_shutdown();
    }
  }

  virtual std::pair<e2e::Attestation, error::Error> Evidence(
      context::Context* ctx,
      const attestation::AttestationData& attestation) const {
    MEASURE_CPU(ctx, cpu_env_evidence);
    e2e::Attestation out;
    if (simulated_) {
      out.set_evidence(unattested_evidence_prefix + attestation.SerializeAsString());
      return std::make_pair(out, error::OK);
    }
    std::string serialized_config;
    if (!attestation.group_config().SerializeToString(&serialized_config)) {
      return std::make_pair(e2e::Attestation(), COUNTED_ERROR(Env_SerializeConfigForEvidence));
    }
    std::string serialized_minimums;
    if (!attestation.minimum_limits().SerializeToString(&serialized_minimums)) {
      return std::make_pair(e2e::Attestation(), COUNTED_ERROR(Env_SerializeMinimumsForEvidence));
    }

    uint8_t* custom_claims_buffer = NULL;
    size_t custom_claims_buffer_size = 0;
    oe_claim_t custom_claims[] = {
        {
          .name = const_cast<char*>(custom_claim_pk),
          .value = reinterpret_cast<uint8_t*>(const_cast<char*>(attestation.public_key().data())),
          .value_size = attestation.public_key().size(),
        },
        {
          .name = const_cast<char*>(custom_claim_config),
          .value = reinterpret_cast<uint8_t*>(serialized_config.data()),
          .value_size = serialized_config.size(),
        },
        {
          .name = const_cast<char*>(custom_claim_minimum_limits),
          .value = reinterpret_cast<uint8_t*>(serialized_minimums.data()),
          .value_size = serialized_minimums.size(),
        },
    };
    if (auto r = oe_serialize_custom_claims(custom_claims, sizeof(custom_claims) / sizeof(custom_claims[0]),
                                            &custom_claims_buffer,
                                            &custom_claims_buffer_size);
        r != OE_OK) {
      LOG(ERROR) << "oe_serialize_custom_claims: " << r;
      return std::make_pair(e2e::Attestation(),
                            COUNTED_ERROR(Env_SerializeCustomClaims));
    }
    std::unique_ptr<uint8_t, oe_result_t (*)(uint8_t*)> free_cc(
        custom_claims_buffer, oe_free_serialized_custom_claims);

    uint8_t* evidence_buffer = NULL;
    size_t evidence_buffer_size = 0;
    uint8_t* endorsements_buffer = NULL;
    size_t endorsements_buffer_size = 0;
    if (auto r = oe_get_evidence(&attestation::sgx_remote_uuid, 0, custom_claims_buffer,
                                 custom_claims_buffer_size, NULL, 0,
                                 &evidence_buffer, &evidence_buffer_size,
                                 &endorsements_buffer,
                                 &endorsements_buffer_size);
        r != OE_OK) {
      LOG(ERROR) << "oe_get_evidence: " << r;
      return std::make_pair(e2e::Attestation(), error::Env_GetEvidence);
    }

    std::unique_ptr<uint8_t, oe_result_t (*)(uint8_t*)> free_evidence(
        evidence_buffer, oe_free_evidence);
    std::unique_ptr<uint8_t, oe_result_t (*)(uint8_t*)> free_endorsements(
        endorsements_buffer, oe_free_endorsements);

    std::string evidence((char*)evidence_buffer, evidence_buffer_size);
    std::string endorsements((char*)endorsements_buffer,
                             endorsements_buffer_size);

    out.set_evidence(evidence);
    out.set_endorsements(endorsements);
    return std::make_pair(out, error::OK);
  }

  virtual error::Error RandomBytes(void* bytes, size_t size) const {
    CHECK(size > 0);
    if (auto r = oe_random(bytes, size);
        r != OE_OK) {
      LOG(ERROR) << "oe_random: " << r;
      return COUNTED_ERROR(Env_RandomBytes);
    }
    return error::OK;
  }

  virtual std::pair<attestation::AttestationData, error::Error> Attest(
      context::Context* ctx,
      util::UnixSecs now,
      const e2e::Attestation& attestation) const {
    MEASURE_CPU(ctx, cpu_env_attest);
    attestation::AttestationData out;

    if (simulated_) {
      const size_t prefix_len = strlen(unattested_evidence_prefix);
      if (attestation.evidence().substr(0, prefix_len) != unattested_evidence_prefix) {
        LOG(ERROR) << "Failed to find attestation prefix in simulated environment";
        return std::make_pair(out, error::Env_AttestationFailure);
      }
      if (!out.ParseFromArray(attestation.evidence().data() + prefix_len, attestation.evidence().size() - prefix_len)) {
        LOG(ERROR) << "Failed to parse evidence in simulated environment";
        return std::make_pair(out, error::Env_AttestationFailure);
      }
      return std::make_pair(out, error::OK);
    }
    const uint8_t* evidence_data =
        reinterpret_cast<const uint8_t*>(attestation.evidence().data());
    const uint8_t* endorsements_data =
        reinterpret_cast<const uint8_t*>(attestation.endorsements().data());

    oe_claim_t* claims = nullptr;
    size_t claims_length = 0;

    oe_datetime_t now_datetime;
    SecsToOEDatetime(now, &now_datetime);
    oe_policy_t policy = {
      .type = OE_POLICY_ENDORSEMENTS_TIME,
      .policy = &now_datetime,
      .policy_size = sizeof(now_datetime),
    };
    if (auto r = oe_verify_evidence(
            &attestation::sgx_remote_uuid,
            evidence_data, attestation.evidence().size(),
            endorsements_data, attestation.endorsements().size(),
            &policy, 1, &claims, &claims_length);
        r != OE_OK) {
      LOG(ERROR) << "oe_verify_evidence: " << r;
      return std::make_pair(out, error::Env_AttestationFailure);
    }

    auto free_claims_known_size = [claims_length](oe_claim_t* ptr) {
      return oe_free_claims(ptr, claims_length);
    };
    std::unique_ptr<oe_claim_t, decltype(free_claims_known_size)> free_claims(
        claims, free_claims_known_size);

    // evidence is verified, now check individual fields
    error::Error err = ValidateStandardClaims(claims, claims_length);
    if (error::OK != err) {
      return std::make_pair(out, err);
    }

    PublicKey key;
    err = attestation::ReadKeyFromVerifiedClaims(claims, claims_length, &key);
    out.set_public_key(util::ByteArrayToString(key));
    return std::make_pair(out, err);
  }

  virtual error::Error SendMessage(context::Context* ctx, const std::string& msg) const {
    MEASURE_CPU(ctx, cpu_env_sendmessage);
    // We specifically don't log the actual result in this one case,
    // since SendMessage is used as a part of logging, and we don't
    // want to loop infinitely.
    if (OE_OK !=
        svr2_output_message(
            msg.size(), const_cast<uint8_t*>(
                            reinterpret_cast<const uint8_t*>(msg.data())))) {
      return COUNTED_ERROR(Env_SendMessage);
    }
    return error::OK;
  }

  virtual void Log(int level, const std::string& msg) const {
    oe_log_ocall(level, msg.c_str());
  }

  virtual void FlushAllLogsIfAble() const {
    // oe_log_ocall already sends everything effectively synchronously.
  }

  virtual error::Error UpdateEnvStats() const {
    oe_mallinfo_t info;
    if (auto r = oe_allocator_mallinfo(&info); r != OE_OK) {
      LOG(WARNING) << "oe_allocator_mallinfo: " << r;
      return COUNTED_ERROR(Env_MallinfoFailure);
    }
    GAUGE(env, total_heap_size)->Set(info.max_total_heap_size);
    GAUGE(env, allocated_heap_size)->Set(info.current_allocated_heap_size);
    GAUGE(env, peak_heap_size)->Set(info.peak_allocated_heap_size);
    return error::OK;
  }

 private:
  bool simulated_;
  std::string expected_mrenclave_;
  error::Error GetMRENCLAVE() {
    context::Context ctx;
    attestation::AttestationData data;
    data.mutable_public_key()->resize(sizeof(env::PublicKey));
    auto [attestation, err] = Evidence(&ctx, data);
    if (err != error::OK) {
      return err;
    }

    auto [claims, claims_length] = attestation::VerifyAndReadClaims(
        attestation.evidence(), attestation.endorsements());

    auto free_claims_known_size = [claims_length=claims_length](oe_claim_t* ptr) {
      return oe_free_claims(ptr, claims_length);
    };
    std::unique_ptr<oe_claim_t, decltype(free_claims_known_size)> free_claims(
        claims, free_claims_known_size);

    // read the MRENCLAVE - this is our MRENCLAVE and we expect all peers to
    // have the same value OE_CLAIM_UNIQUE_ID retrieves MRENCLAVE on SGX
    const oe_claim_t* claim;
    if ((claim = attestation::FindClaim(claims, claims_length,
                                        OE_CLAIM_UNIQUE_ID)) == nullptr) {
      return COUNTED_ERROR(Env_AttestationFailure);
    }
    expected_mrenclave_ = std::string(
        reinterpret_cast<const char*>(claim->value), claim->value_size);
    return error::OK;
  }

  error::Error ValidateStandardClaims(oe_claim_t* claims,
                                      size_t claims_length) const {
    const oe_claim_t* claim;

    // OE_CLAIM_UNIQUE_ID is MRENCLAVE for SGX
    if ((claim = attestation::FindClaim(claims, claims_length,
                                        OE_CLAIM_UNIQUE_ID)) == nullptr) {
      return COUNTED_ERROR(Env_MissingMRENCLAVE);
    }
    auto actual_mrenclave = std::string(
        reinterpret_cast<const char*>(claim->value), claim->value_size);

    // Don't need constant time, but we have it so we use it.
    if (!util::ConstantTimeEquals(actual_mrenclave, expected_mrenclave_)) {
      return COUNTED_ERROR(Env_WrongMRENCLAVE);
    }

    return error::OK;
  }

  static void SecsToOEDatetime(util::UnixSecs secs, oe_datetime_t* dt) {
    // Mostly copied from oe_datetime_now in OpenEnclave's common/datetime.c.
    // Unfortunately, they expose the ability to get from "now", but not
    // from an arbitrary timestamp.
    CHECK(dt != nullptr);
    struct tm timeinfo;

    gmtime_r(&secs, &timeinfo);

    dt->year = (uint32_t)timeinfo.tm_year + 1900;
    dt->month = (uint32_t)timeinfo.tm_mon + 1;
    dt->day = (uint32_t)timeinfo.tm_mday;
    dt->hours = (uint32_t)timeinfo.tm_hour;
    dt->minutes = (uint32_t)timeinfo.tm_min;
    dt->seconds = (uint32_t)timeinfo.tm_sec;
  }
};

}  // namespace sgx

void Init(bool is_simulated) {
  environment = std::make_unique<::svr2::env::sgx::Environment>(is_simulated);
  environment->Init();
}

}  // namespace svr2::env
