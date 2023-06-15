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

namespace svr2::env {
namespace sgx {

static const char* unattested_evidence_prefix = "UNATTESTED EVIDENCE:";
static const char* custom_claim_pk = "pk";
static const char* custom_claim_config = "config";
class Environment : public ::svr2::env::Environment {
 public:
  DELETE_COPY_AND_ASSIGN(Environment);
  Environment(bool simulated) : ::svr2::env::Environment(), simulated_(simulated) {
    if (!simulated_) {
      CHECK(OE_OK == oe_attester_initialize());
      CHECK(OE_OK == oe_verifier_initialize());
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
      const PublicKey& key,
      const enclaveconfig::RaftGroupConfig& config) const {
    MEASURE_CPU(ctx, cpu_env_evidence);
    e2e::Attestation attestation;
    if (simulated_) {
      attestation.set_evidence(
          unattested_evidence_prefix +
          std::string(reinterpret_cast<const char*>(key.data()), key.size()));
      return std::make_pair(attestation, error::OK);
    }
    std::string serialized_config;
    if (!config.SerializeToString(&serialized_config)) {
      return std::make_pair(e2e::Attestation(), COUNTED_ERROR(Env_SerializeConfigForEvidence));
    }

    uint8_t* custom_claims_buffer = NULL;
    size_t custom_claims_buffer_size = 0;
    oe_claim_t custom_claims[] = {
        {
          .name = const_cast<char*>(custom_claim_pk),
          .value = const_cast<uint8_t*>(key.data()),
          .value_size = key.size(),
        },
        {
          .name = const_cast<char*>(custom_claim_config),
          .value = reinterpret_cast<uint8_t*>(serialized_config.data()),
          .value_size = serialized_config.size(),
        },
    };
    if (OE_OK != oe_serialize_custom_claims(custom_claims, sizeof(custom_claims) / sizeof(custom_claims[0]),
                                            &custom_claims_buffer,
                                            &custom_claims_buffer_size)) {
      return std::make_pair(e2e::Attestation(),
                            COUNTED_ERROR(Env_SerializeCustomClaims));
    }
    std::unique_ptr<uint8_t, oe_result_t (*)(uint8_t*)> free_cc(
        custom_claims_buffer, oe_free_serialized_custom_claims);

    uint8_t* evidence_buffer = NULL;
    size_t evidence_buffer_size = 0;
    uint8_t* endorsements_buffer = NULL;
    size_t endorsements_buffer_size = 0;
    if (OE_OK != oe_get_evidence(&attestation::sgx_remote_uuid, 0, custom_claims_buffer,
                                 custom_claims_buffer_size, NULL, 0,
                                 &evidence_buffer, &evidence_buffer_size,
                                 &endorsements_buffer,
                                 &endorsements_buffer_size)) {
      return std::make_pair(e2e::Attestation(), error::Env_GetEvidence);
    }

    std::unique_ptr<uint8_t, oe_result_t (*)(uint8_t*)> free_evidence(
        evidence_buffer, oe_free_evidence);
    std::unique_ptr<uint8_t, oe_result_t (*)(uint8_t*)> free_endorsements(
        endorsements_buffer, oe_free_endorsements);

    std::string evidence((char*)evidence_buffer, evidence_buffer_size);
    std::string endorsements((char*)endorsements_buffer,
                             endorsements_buffer_size);

    attestation.set_evidence(evidence);
    attestation.set_endorsements(endorsements);
    return std::make_pair(attestation, error::OK);
  }

  virtual error::Error RandomBytes(void* bytes, size_t size) const {
    CHECK(size > 0);
    if (OE_OK != oe_random(bytes, size)) {
      return COUNTED_ERROR(Env_RandomBytes);
    }
    return error::OK;
  }

  virtual std::pair<PublicKey, error::Error> Attest(
      context::Context* ctx,
      util::UnixSecs now,
      const e2e::Attestation& attestation) const {
    MEASURE_CPU(ctx, cpu_env_attest);
    PublicKey out = {0};

    if (simulated_) {
      if (attestation.evidence().size() != strlen(unattested_evidence_prefix) + out.size() ||
          attestation.evidence().substr(0, strlen(unattested_evidence_prefix)) !=
              unattested_evidence_prefix) {
        return std::make_pair(out, error::Env_AttestationFailure);
      }
      memcpy(out.data(), attestation.evidence().data() + strlen(unattested_evidence_prefix),
             out.size());
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
    auto verify_err = oe_verify_evidence(
        &attestation::sgx_remote_uuid,
        evidence_data, attestation.evidence().size(),
        endorsements_data, attestation.endorsements().size(),
        &policy, 1, &claims, &claims_length);
    if (OE_OK != verify_err) {
      LOG(ERROR) << "oe_verify_evidence failed with code " << verify_err;
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

    err = attestation::ReadKeyFromVerifiedClaims(claims, claims_length, out);

    return std::make_pair(out, err);
  }

  virtual error::Error SendMessage(context::Context* ctx, const std::string& msg) const {
    MEASURE_CPU(ctx, cpu_env_sendmessage);
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

  virtual error::Error UpdateEnvStats() const {
    oe_mallinfo_t info;
    if (OE_OK != oe_allocator_mallinfo(&info)) {
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
    auto [attestation, err] = Evidence(&ctx, PublicKey{0}, enclaveconfig::RaftGroupConfig());
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
