// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

//TESTDEP gtest
//TESTDEP merkle
//TESTDEP sip
//TESTDEP context
//TESTDEP env
//TESTDEP env/test
//TESTDEP env
//TESTDEP util
//TESTDEP metrics
//TESTDEP proto
//TESTDEP protobuf-lite
//TESTDEP libsodium

#include <gtest/gtest.h>
#include "db/db4.h"
#include "env/env.h"
#include "util/log.h"
#include "util/constant.h"
#include "util/macros.h"
#include "util/endian.h"
#include "util/bytes.h"
#include "util/hex.h"
#include "proto/client3.pb.h"
#include "proto/clientlog.pb.h"
#include <memory>
#include <sodium/crypto_scalarmult_ristretto255.h>
#include <sodium/crypto_auth_hmacsha512.h>

#define ASSERT_AND_ASSIGN(var, val) ASSERT_AND_ASSIGN_CTR1(var, val, __COUNTER__)
#define ASSERT_AND_ASSIGN_CTR1(var, val, ctr) ASSERT_AND_ASSIGN_CTR2(var, val, ctr)
#define ASSERT_AND_ASSIGN_CTR2(var, val, ctr) \
  auto [var, __err##ctr] = (val); \
  ASSERT_EQ(__err##ctr, error::OK);

namespace svr2::db {

class DB4Test : public ::testing::Test {
 public:
  DB4Test() {}
 protected:
  static void SetUpTestCase() {
    env::Init(env::SIMULATED);
  }

  context::Context ctx;
  merkle::Tree merk;
};

DB4::RistrettoScalar RandomScalar() {
  DB4::RistrettoScalar s;
  crypto_core_ristretto255_scalar_random(s.data());
  return s;
}

template <class T1>
std::array<uint8_t, 64> SHA512(const T1& t1) {
  std::array<uint8_t, 64> sha512_hash;
  crypto_hash_sha512_state sha512_state;
  crypto_hash_sha512_init(&sha512_state);
  crypto_hash_sha512_update(&sha512_state, t1.data(), t1.size());
  crypto_hash_sha512_final(&sha512_state, sha512_hash.data());
  return sha512_hash;
}

template <class T1, class T2>
std::array<uint8_t, 64> SHA512(const T1& t1, const T2& t2) {
  std::array<uint8_t, 64> sha512_hash;
  crypto_hash_sha512_state sha512_state;
  crypto_hash_sha512_init(&sha512_state);
  crypto_hash_sha512_update(&sha512_state, t1.data(), t1.size());
  crypto_hash_sha512_update(&sha512_state, t2.data(), t2.size());
  crypto_hash_sha512_final(&sha512_state, sha512_hash.data());
  return sha512_hash;
}

DB4::RistrettoScalar Reduce(const std::array<uint8_t, 64>& v) {
  DB4::RistrettoScalar s;
  crypto_core_ristretto255_scalar_reduce(s.data(), v.data());
  return s;
}

template <class T1, class T2>
DB4::RistrettoScalar TestKDF(const T1& t1, const T2& t2) {
  return Reduce(SHA512(t1, t2));
}

template <size_t N>
class DB4Client {
 public:
  DB4Client() {
    CHECK(error::OK == env::environment->RandomBytes(id_.data(), id_.size()));
    CHECK(error::OK == env::environment->RandomBytes(input_.data(), input_.size()));
    k_oprf_ = RandomScalar();
    DB4::RistrettoPoint hash_pt;
    crypto_core_ristretto255_from_hash(hash_pt.data(), input_.data());
    CHECK(0 == crypto_scalarmult_ristretto255(k_auth_pt_.data(), k_oprf_.data(), hash_pt.data()));
    k_auth_ = TestKDF(input_, k_auth_pt_);


    // We compute k_1..k_n such that SUM(k_*) == k_oprf by using the fact that
    //   k1 + k2 + ... + kn = k_oprf
    //   -k_oprf + k1 + k2 + ... +  kn = 0
    //   -k_oprf + k2 + ... + kn = -k1
    crypto_core_ristretto255_scalar_negate(k_[0].data(), k_oprf_.data());
    for (int i = 1; i < N; i++) {
      k_[i] = RandomScalar();
      crypto_core_ristretto255_scalar_add(k_[0].data(), k_[0].data(), k_[i].data());
    }
    crypto_core_ristretto255_scalar_negate(k_[0].data(), k_[0].data());

    // Choose random aes_enc_, and choose aes_[i] such that they xor to aes_enc_.
    CHECK(error::OK == env::environment->RandomBytes(aes_enc_.data(), aes_enc_.size()));
    memcpy(aes_[0].data(), aes_enc_.data(), aes_enc_.size());
    for (int i = 1; i < N; i++) {
      CHECK(error::OK == env::environment->RandomBytes(aes_[i].data(), aes_[i].size()));
      for (int j = 0; j < aes_[0].size(); j++) {
        aes_[0][j] ^= aes_[i][j];
      }
    }
    k_enc_ = TestKDF(aes_enc_, k_auth_);

    // Choose random z_i_ such that they sum to 0.
    memset(z_[0].data(), 0, z_[0].size());
    for (int i = 1; i < N; i++) {
      z_[i] = RandomScalar();
      crypto_core_ristretto255_scalar_add(z_[0].data(), z_[0].data(), z_[i].data());
    }
    crypto_core_ristretto255_scalar_negate(z_[0].data(), z_[0].data());

    // Choose N secret and public keys.
    for (int i = 0; i < N; i++) {
      std::array<uint8_t, 1> index = {(uint8_t)('0' + i)};
      sk_[i] = TestKDF(k_auth_, index);
      crypto_scalarmult_ristretto255_base(pk_[i].data(), sk_[i].data());
    }
  }

  client::Request4 Create(int i) {
    client::Request4 r;
    r.mutable_create()->set_max_tries(10);
    r.mutable_create()->set_oprf_secretshare(util::ByteArrayToString(k_[i]));
    r.mutable_create()->set_zero_secretshare(util::ByteArrayToString(z_[i]));
    r.mutable_create()->set_auth_commitment(util::ByteArrayToString(pk_[i]));
    r.mutable_create()->set_encryption_secretshare(util::ByteArrayToString(aes_[i]));
    return r;
  }

  client::Request4 Restore1(int i, const DB4::RistrettoScalar& b) {
    DB4::RistrettoPoint e;
    crypto_core_ristretto255_from_hash(e.data(), input_.data());
    DB4::RistrettoPoint blinded;
    CHECK(0 == crypto_scalarmult_ristretto255(blinded.data(), b.data(), e.data()));

    client::Request4 r;
    r.mutable_restore1()->set_blinded(util::ByteArrayToString(blinded));
    return r;
  }

  client::Request4 Restore2(
      int i,
      const DB4::RistrettoScalar& b,
      const std::array<client::Response4::Restore1, N>& resps) {
    DB4::RistrettoScalar evaluated_sum = {0};
    for (int i = 0; i < N; i++) {
      DB4::RistrettoScalar s;
      CHECK(error::OK == util::StringIntoByteArray(resps[i].element(), &s));
      crypto_core_ristretto255_scalar_add(evaluated_sum.data(), evaluated_sum.data(), s.data());
    }

    DB4::RistrettoScalar b_inverse;
    crypto_core_ristretto255_scalar_invert(b_inverse.data(), b.data());

    DB4::RistrettoScalar unblinded;
    crypto_core_ristretto255_scalar_mul(unblinded.data(), b_inverse.data(), evaluated_sum.data());

    // With all of this unblinding, we should have been able to recreate
    // k_auth_pt.
    DB4::RistrettoPoint k_auth_pt;
    crypto_core_ristretto255_from_hash(k_auth_pt.data(), input_.data());
    CHECK(0 == crypto_scalarmult_ristretto255(k_auth_pt.data(), k_oprf_.data(), k_auth_pt.data()));
    CHECK(util::ConstantTimeEquals(k_auth_pt_, k_auth_pt));

    // From k_auth_pt, we could now derive sk_ and pk_.  But we already have them,
    // so let's not bother.

    auto rand = RandomScalar();
    DB4::RistrettoPoint proof_point;
    CHECK(0 == crypto_scalarmult_ristretto255_base(proof_point.data(), rand.data()));
    auto c = Reduce(SHA512(proof_point));
    DB4::RistrettoScalar proof_scalar;
    crypto_core_ristretto255_scalar_mul(proof_scalar.data(), c.data(), sk_[i].data());
    crypto_core_ristretto255_scalar_add(proof_scalar.data(), proof_scalar.data(), rand.data());

    client::Request4 r;
    r.mutable_restore2()->set_auth_point(util::ByteArrayToString(proof_point));
    r.mutable_restore2()->set_auth_scalar(util::ByteArrayToString(proof_scalar));
    return r;
  }

  bool EncryptionKeyMatches(int i, const client::Response4::Restore2& r) {
    return util::ConstantTimeEquals(r.encryption_secretshare(), aes_[i]);
  }

  const DB4::BackupID& id() const { return id_; }
  std::string authenticated_id() const { return util::ByteArrayToString(id_); }

 private:
  std::array<uint8_t, 64> input_;
  DB4::BackupID id_;
  DB4::RistrettoScalar k_oprf_;
  DB4::RistrettoPoint k_auth_pt_;
  DB4::RistrettoScalar k_auth_;
  std::array<DB4::RistrettoScalar, N> k_;
  std::array<DB4::RistrettoScalar, N> z_;
  DB4::AESKey aes_enc_;
  std::array<DB4::AESKey, N> aes_;
  std::array<DB4::RistrettoScalar, N> sk_;
  std::array<DB4::RistrettoPoint, N> pk_;
  DB4::RistrettoScalar k_enc_;
};

TEST_F(DB4Test, SingleBackupLifecycle) {
  ASSERT_EQ(1, 1);
  const size_t N = 3;
  DB4Client<N> client;
  std::array<std::unique_ptr<DB4>, N> dbs;
  std::array<std::unique_ptr<DB::ClientState>, N> states;
  for (int i = 0; i < N; i++) {
    dbs[i] = std::make_unique<DB4>(&merk);
    states[i] = dbs[i]->P()->NewClientState(client.authenticated_id());
  }
  for (int i = 0; i < N; i++) {
    LOG(INFO) << "Create." << i;
    auto req = client.Create(i);
    auto [resp, resp_err] = states[i]->ResponseFromRequest(&ctx, req);
    ASSERT_EQ(nullptr, resp);
    ASSERT_EQ(error::OK, resp_err);
    auto [log, log_err] = states[i]->LogFromRequest(&ctx, req);
    ASSERT_EQ(error::OK, log_err);
    ASSERT_NE(nullptr, log);
    auto effect = dbs[i]->Run(&ctx, *log);
    ASSERT_NE(nullptr, effect);
    auto resp2 = dynamic_cast<const client::Response4*>(states[i]->ResponseFromEffect(&ctx, *effect));
    ASSERT_NE(nullptr, resp2);
    ASSERT_EQ(resp2->create().status(), client::Response4::Create::OK);
    ASSERT_EQ(client::Response4::kCreate, resp2->inner_case());
  }

  DB4::RistrettoScalar b = RandomScalar();
  std::array<client::Response4::Restore1, N> restore1resp;
  for (int i = 0; i < N; i++) {
    LOG(INFO) << "Restore1." << i;
    auto req = client.Restore1(i, b);
    auto [resp, resp_err] = states[i]->ResponseFromRequest(&ctx, req);
    ASSERT_EQ(nullptr, resp);
    ASSERT_EQ(error::OK, resp_err);
    auto [log, log_err] = states[i]->LogFromRequest(&ctx, req);
    ASSERT_EQ(error::OK, log_err);
    ASSERT_NE(nullptr, log);
    auto effect = dbs[i]->Run(&ctx, *log);
    ASSERT_NE(nullptr, effect);
    auto resp2 = dynamic_cast<const client::Response4*>(states[i]->ResponseFromEffect(&ctx, *effect));
    ASSERT_NE(nullptr, resp2);
    ASSERT_EQ(client::Response4::kRestore1, resp2->inner_case());
    ASSERT_EQ(resp2->restore1().status(), client::Response4::Restore1::OK);
    ASSERT_EQ(resp2->restore1().tries_remaining(), 9);
    restore1resp[i].MergeFrom(resp2->restore1());
  }

  for (int i = 0; i < N; i++) {
    LOG(INFO) << "Restore2." << i;
    auto req = client.Restore2(i, b, restore1resp);
    auto [resp, resp_err] = states[i]->ResponseFromRequest(&ctx, req);
    auto r = dynamic_cast<const client::Response4*>(resp);
    ASSERT_NE(nullptr, r);
    ASSERT_EQ(error::OK, resp_err);
    ASSERT_EQ(client::Response4::kRestore2, r->inner_case());
    ASSERT_EQ(r->restore2().status(), client::Response4::Restore2::OK);
    ASSERT_TRUE(client.EncryptionKeyMatches(i, r->restore2()));
  }
}

}  // namespace svr2::db
