// Copyright 2024 Signal Messenger, LLC
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
//TESTDEP sha
//TESTDEP ristretto

#include <gtest/gtest.h>
#include "db/db4.h"
#include "env/env.h"
#include "sha/sha.h"
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

template <class T1, class T2>
ristretto::Scalar TestKDF(const T1& t1, const T2& t2) {
  return ristretto::Scalar::Reduce(sha::Sha512(t1, t2));
}

std::pair<const client::Response4*, error::Error> RunRequest(
    context::Context* ctx,
    DB4* db,
    DB::ClientState* state,
    const client::Request4& req) {
  auto [resp, resp_err] = state->ResponseFromRequest(ctx, req);
  if (resp_err != error::OK) { return std::make_pair(nullptr, resp_err); }
  if (resp) { return std::make_pair(dynamic_cast<const client::Response4*>(resp), error::OK); }
  auto [log, log_err] = state->LogFromRequest(ctx, req);
  if (log_err != error::OK) { return std::make_pair(nullptr, log_err); }
  auto effect = db->Run(ctx, *log);
  resp = dynamic_cast<const client::Response4*>(state->ResponseFromEffect(ctx, *effect));
  return std::make_pair(dynamic_cast<const client::Response4*>(resp), error::OK);
}

template <size_t N>
class DB4Client {
 public:
  DB4Client() {
    CHECK(error::OK == env::environment->RandomBytes(id_.data(), id_.size()));
    CHECK(error::OK == env::environment->RandomBytes(input_.data(), input_.size()));
    k_oprf_ = ristretto::Scalar::Random();
    ristretto::Point hash_pt;
    CHECK(hash_pt.FromHash(input_));
    CHECK(hash_pt.ScalarMult(k_oprf_, &k_auth_pt_));
    k_auth_ = TestKDF(input_, k_auth_pt_);

    // We compute k_1..k_n such that SUM(k_*) == k_oprf by using the fact that
    //   k1 + k2 + ... + kn = k_oprf
    //   -k_oprf + k1 + k2 + ... +  kn = 0
    //   -k_oprf + k2 + ... + kn = -k1
    k_[0] = k_oprf_.Negate();
    for (int i = 1; i < N; i++) {
      k_[i] = ristretto::Scalar::Random();
      k_[0] = k_[0].Add(k_[i]);
    }
    k_[0] = k_[0].Negate();

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
    z_[0] = ristretto::Scalar::Zero();
    for (int i = 1; i < N; i++) {
      z_[i] = ristretto::Scalar::Random();
      z_[0] = z_[0].Add(z_[i]);
    }
    z_[0] = z_[0].Negate();

    // Choose N secret and public keys.
    for (int i = 0; i < N; i++) {
      std::array<uint8_t, 1> index = {(uint8_t)i};
      sk_[i] = TestKDF(k_auth_, index);
      CHECK(pk_[i].ScalarMultBase(sk_[i]));
    }
  }

  client::Request4 Create(int i) {
    client::Request4 r;
    r.mutable_create()->set_max_tries(10);
    r.mutable_create()->set_oprf_secretshare(k_[i].ToString());
    r.mutable_create()->set_zero_secretshare(z_[i].ToString());
    r.mutable_create()->set_auth_commitment(pk_[i].ToString());
    r.mutable_create()->set_encryption_secretshare(util::ByteArrayToString(aes_[i]));
    return r;
  }

  client::Request4 Restore1(int i, const ristretto::Scalar& b) {
    ristretto::Point e;
    CHECK(e.FromHash(input_));
    ristretto::Point blinded;
    CHECK(e.ScalarMult(b, &blinded));

    client::Request4 r;
    r.mutable_restore1()->set_blinded(blinded.ToString());
    return r;
  }

  client::Request4 Restore2(
      int i,
      const ristretto::Scalar& b,
      const std::array<client::Response4::Restore1, N>& resps) {
    ristretto::Point evaluated_sum;
    for (int i = 0; i < N; i++) {
      ristretto::Point p;
      CHECK(p.FromString(resps[i].element()));
      if (i == 0) {
        evaluated_sum = p;
      } else {
        CHECK(evaluated_sum.Add(p, &evaluated_sum));
      }
    }

    ristretto::Scalar b_inverse;
    CHECK(b.Invert(&b_inverse));
    ristretto::Point unblinded;
    CHECK(evaluated_sum.ScalarMult(b_inverse, &unblinded));
    CHECK(util::ConstantTimeEquals(unblinded, k_auth_pt_));

    // From k_oprf_, we could now derive sk_ and pk_.  But we already have them,
    // so let's not bother.

    auto rand = ristretto::Scalar::Random();
    ristretto::Point proof_point;
    CHECK(proof_point.ScalarMultBase(rand));
    auto c = ristretto::Scalar::Reduce(sha::Sha512(proof_point));
    auto proof_scalar = rand.Add(c.Mult(sk_[i]));

    client::Request4 r;
    r.mutable_restore2()->set_auth_point(proof_point.ToString());
    r.mutable_restore2()->set_auth_scalar(proof_scalar.ToString());
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
  ristretto::Scalar k_oprf_;
  ristretto::Point k_auth_pt_;
  ristretto::Scalar k_auth_;
  std::array<ristretto::Scalar, N> k_;
  std::array<ristretto::Scalar, N> z_;
  DB4::AESKey aes_enc_;
  std::array<DB4::AESKey, N> aes_;
  std::array<ristretto::Scalar, N> sk_;
  std::array<ristretto::Point, N> pk_;
  ristretto::Scalar k_enc_;
};

TEST_F(DB4Test, SingleBackupLifecycle) {
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
    auto [resp, err] = RunRequest(&ctx, dbs[i].get(), states[i].get(), req);
    ASSERT_EQ(error::OK, err);
    ASSERT_EQ(resp->create().status(), client::Response4::Create::OK);
    ASSERT_EQ(client::Response4::kCreate, resp->inner_case());
  }

  ristretto::Scalar b = ristretto::Scalar::Random();
  std::array<client::Response4::Restore1, N> restore1resp;
  for (int i = 0; i < N; i++) {
    LOG(INFO) << "Restore1." << i;
    auto req = client.Restore1(i, b);
    auto [resp, err] = RunRequest(&ctx, dbs[i].get(), states[i].get(), req);
    ASSERT_EQ(error::OK, err);
    ASSERT_EQ(client::Response4::kRestore1, resp->inner_case());
    ASSERT_EQ(resp->restore1().status(), client::Response4::Restore1::OK);
    ASSERT_EQ(resp->restore1().tries_remaining(), 9);
    restore1resp[i].MergeFrom(resp->restore1());
  }

  for (int i = 0; i < N; i++) {
    LOG(INFO) << "Restore2." << i;
    auto req = client.Restore2(i, b, restore1resp);
    auto [resp, err] = RunRequest(&ctx, dbs[i].get(), states[i].get(), req);
    ASSERT_EQ(error::OK, err);
    ASSERT_EQ(client::Response4::kRestore2, resp->inner_case());
    ASSERT_EQ(resp->restore2().status(), client::Response4::Restore2::OK);
    ASSERT_TRUE(client.EncryptionKeyMatches(i, resp->restore2()));
  }
}

TEST_F(DB4Test, Restore1RemovesKey) {
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
    auto [resp, err] = RunRequest(&ctx, dbs[i].get(), states[i].get(), req);
    ASSERT_EQ(error::OK, err);
    ASSERT_EQ(resp->create().status(), client::Response4::Create::OK);
    ASSERT_EQ(client::Response4::kCreate, resp->inner_case());
  }

  for (int i = 0; i < 10; i++) {
    ristretto::Scalar b = ristretto::Scalar::Random();
    auto req = client.Restore1(0, b);
    auto [resp, err] = RunRequest(&ctx, dbs[0].get(), states[0].get(), req);
    ASSERT_EQ(error::OK, err);
    ASSERT_EQ(client::Response4::kRestore1, resp->inner_case());
    ASSERT_EQ(resp->restore1().status(), client::Response4::Restore1::OK);
    ASSERT_EQ(resp->restore1().tries_remaining(), 10-i-1);
  }
  // Verify that after the last try, we get a MISSING error.
  {
    ristretto::Scalar b = ristretto::Scalar::Random();
    auto req = client.Restore1(0, b);
    auto [resp, err] = RunRequest(&ctx, dbs[0].get(), states[0].get(), req);
    ASSERT_EQ(error::OK, err);
    ASSERT_EQ(client::Response4::kRestore1, resp->inner_case());
    ASSERT_EQ(resp->restore1().status(), client::Response4::Restore1::MISSING);
  }
}

TEST_F(DB4Test, QueryClearsRestoreState) {
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
    auto [resp, err] = RunRequest(&ctx, dbs[i].get(), states[i].get(), req);
    ASSERT_EQ(error::OK, err);
    ASSERT_EQ(resp->create().status(), client::Response4::Create::OK);
    ASSERT_EQ(client::Response4::kCreate, resp->inner_case());
  }

  ristretto::Scalar b = ristretto::Scalar::Random();
  std::array<client::Response4::Restore1, N> restore1resp;
  for (int i = 0; i < N; i++) {
    LOG(INFO) << "Restore1." << i;
    auto req = client.Restore1(i, b);
    auto [resp, err] = RunRequest(&ctx, dbs[i].get(), states[i].get(), req);
    ASSERT_EQ(error::OK, err);
    ASSERT_EQ(client::Response4::kRestore1, resp->inner_case());
    ASSERT_EQ(resp->restore1().status(), client::Response4::Restore1::OK);
    ASSERT_EQ(resp->restore1().tries_remaining(), 9);
    restore1resp[i].MergeFrom(resp->restore1());
  }

  { int i = 0;
    LOG(INFO) << "Query." << i;
    client::Request4 req;
    req.mutable_query();
    auto [resp, err] = RunRequest(&ctx, dbs[i].get(), states[i].get(), req);
    ASSERT_EQ(error::OK, err);
    ASSERT_EQ(client::Response4::kQuery, resp->inner_case());
    ASSERT_EQ(resp->query().status(), client::Response4::Query::OK);
    ASSERT_EQ(resp->query().tries_remaining(), 9);
  }

  { int i = 0;
    LOG(INFO) << "Restore2." << i;
    auto req = client.Restore2(i, b, restore1resp);
    auto [resp, err] = RunRequest(&ctx, dbs[i].get(), states[i].get(), req);
    ASSERT_EQ(error::OK, err);
    ASSERT_EQ(client::Response4::kRestore2, resp->inner_case());
    ASSERT_EQ(resp->restore2().status(), client::Response4::Restore2::RESTORE1_MISSING);
  }
}

TEST_F(DB4Test, RemoveRemovesRow) {
  const size_t N = 3;
  DB4Client<N> client;
  std::array<std::unique_ptr<DB4>, N> dbs;
  std::array<std::unique_ptr<DB::ClientState>, N> states;
  for (int i = 0; i < N; i++) {
    dbs[i] = std::make_unique<DB4>(&merk);
    states[i] = dbs[i]->P()->NewClientState(client.authenticated_id());
  }
  { int i = 0;
    LOG(INFO) << "Create." << i;
    auto req = client.Create(i);
    auto [resp, err] = RunRequest(&ctx, dbs[i].get(), states[i].get(), req);
    ASSERT_EQ(error::OK, err);
    ASSERT_EQ(resp->create().status(), client::Response4::Create::OK);
    ASSERT_EQ(client::Response4::kCreate, resp->inner_case());
  }

  { int i = 0;
    LOG(INFO) << "Remove." << i;
    client::Request4 req;
    req.mutable_remove();
    auto [resp, err] = RunRequest(&ctx, dbs[i].get(), states[i].get(), req);
    ASSERT_EQ(error::OK, err);
    ASSERT_EQ(client::Response4::kRemove, resp->inner_case());
  }

  ristretto::Scalar b = ristretto::Scalar::Random();
  { int i = 0;
    LOG(INFO) << "Restore1." << i;
    auto req = client.Restore1(i, b);
    auto [resp, err] = RunRequest(&ctx, dbs[i].get(), states[i].get(), req);
    ASSERT_EQ(error::OK, err);
    ASSERT_EQ(client::Response4::kRestore1, resp->inner_case());
    ASSERT_EQ(resp->restore1().status(), client::Response4::Restore1::MISSING);
  }
}

TEST_F(DB4Test, MaxTriesZeroKeepsTriesTheSame) {
  const size_t N = 3;
  DB4Client<N> client;
  std::array<std::unique_ptr<DB4>, N> dbs;
  std::array<std::unique_ptr<DB::ClientState>, N> states;
  for (int i = 0; i < N; i++) {
    dbs[i] = std::make_unique<DB4>(&merk);
    states[i] = dbs[i]->P()->NewClientState(client.authenticated_id());
  }
  { int i = 0;
    LOG(INFO) << "Create." << i;
    auto req = client.Create(i);
    auto [resp, err] = RunRequest(&ctx, dbs[i].get(), states[i].get(), req);
    ASSERT_EQ(error::OK, err);
    ASSERT_EQ(resp->create().status(), client::Response4::Create::OK);
    ASSERT_EQ(client::Response4::kCreate, resp->inner_case());
    ASSERT_EQ(resp->create().tries_remaining(), 10);
  }

  ristretto::Scalar b = ristretto::Scalar::Random();
  { int i = 0;
    LOG(INFO) << "Restore1." << i;
    auto req = client.Restore1(i, b);
    auto [resp, err] = RunRequest(&ctx, dbs[i].get(), states[i].get(), req);
    ASSERT_EQ(error::OK, err);
    ASSERT_EQ(client::Response4::kRestore1, resp->inner_case());
    ASSERT_EQ(resp->restore1().status(), client::Response4::Restore1::OK);
    ASSERT_EQ(resp->restore1().tries_remaining(), 9);
  }

  { int i = 0;
    LOG(INFO) << "Create." << i;
    auto req = client.Create(i);
    req.mutable_create()->set_max_tries(0);
    auto [resp, err] = RunRequest(&ctx, dbs[i].get(), states[i].get(), req);
    ASSERT_EQ(error::OK, err);
    ASSERT_EQ(resp->create().status(), client::Response4::Create::OK);
    ASSERT_EQ(client::Response4::kCreate, resp->inner_case());
    ASSERT_EQ(resp->create().tries_remaining(), 9);
  }
}

}  // namespace svr2::db
