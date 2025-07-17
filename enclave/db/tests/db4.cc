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
#include <map>
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

template <class T1, class T2>
ristretto::Scalar TestKDF(const T1& t1, const T2& t2) {
  return ristretto::Scalar::Reduce(sha::Sha512(t1, t2));
}

std::pair<const client::Response4*, error::Error> RunRequest(
    context::Context* ctx,
    DB4* db,
    DB::ClientState* state,
    const client::Request4& req,
    DB::HandshakeHash handshake_hash) {
  state->set_handshake_hash(handshake_hash);
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
    aes_enc_ = {0};
    for (int i = 0; i < N; i++) {
      CHECK(error::OK == env::environment->RandomBytes(aes_[i].data(), aes_[i].size()));
      for (int j = 0; j < sizeof(DB4::AESKey); j++) {
        aes_enc_[j] ^= aes_[i][j];
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

    // Choose random version #
    uint8_t version[8];
    CHECK(error::OK == env::environment->RandomBytes(version, sizeof(version)));
    version_ = util::BigEndian64FromBytes(version);
  }

  client::Request4 Create(int i, int tries) {
    client::Request4 r;
    r.mutable_create()->set_max_tries(tries);
    r.mutable_create()->set_oprf_secretshare(k_[i].ToString());
    r.mutable_create()->set_zero_secretshare(z_[i].ToString());
    r.mutable_create()->set_auth_commitment(pk_[i].ToString());
    r.mutable_create()->set_encryption_secretshare(util::ByteArrayToString(aes_[i]));
    r.mutable_create()->set_version(version_);
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

  std::array<client::Request4, N> RotateStart(uint64_t* version) {
    // Create N scalars that sum to zero
    std::array<ristretto::Scalar, N> scalars;
    for (int i = 1; i < N; i++) {
      scalars[i] = ristretto::Scalar::Random();
      if (i == 1) {
        scalars[0] = scalars[i];
      } else {
        scalars[0] = scalars[0].Add(scalars[i]);
      }
    }
    scalars[0] = scalars[0].Negate();
    // Create N keys that XOR to zero
    std::array<DB4::AESKey, N> encs;
    encs[0] = {0};
    for (int i = 1; i < N; i++) {
      CHECK(error::OK == env::environment->RandomBytes(encs[i].data(), encs[i].size()));
      for (int j = 0; j < sizeof(DB4::AESKey); j++) {
        encs[0][j] ^= encs[i][j];
      }
    }
    uint8_t v[8];
    CHECK(error::OK == env::environment->RandomBytes(v, sizeof(v)));
    *version = util::BigEndian64FromBytes(v);

    std::array<client::Request4, N> out;
    for (int i = 0; i < N; i++) {
      auto r = out[i].mutable_rotate_start();
      r->set_version(*version);
      r->set_oprf_secretshare_delta(scalars[i].ToString());
      r->set_encryption_secretshare_delta(util::ByteArrayToString(encs[i]));
    }
    return out;
  }

  client::Request4 Restore2(
      int i,
      const ristretto::Scalar& b,
      const std::string& blinded,
      const std::array<client::Response4::Restore1, N>& resps,
      std::array<uint8_t, 32> handshake_hash) {
    // Find which version to use by figuring out which version appears
    // in all of the responses.
    std::map<uint64_t, std::set<int>> versions;
    for (int i = 0; i < N; i++) {
      for (int j = 0; j < resps[i].auth_size(); j++) {
        versions[resps[i].auth(j).version()].insert(i);
        LOG(INFO) << "Version " << resps[i].auth(j).version() << " in " << i;
      }
    }
    uint64_t v = 0;
    for (auto iter : versions) {
      if (iter.second.size() == N) {
        v = iter.first;
        break;
      }
    }
    CHECK(v != 0);

    ristretto::Point evaluated_sum;
    for (int i = 0; i < N; i++) {
      ristretto::Point p;
      for (int j = 0; j < resps[i].auth_size(); j++) {
        const auto& a = resps[i].auth(j);
        if (a.version() != v) continue;
        CHECK(p.FromString(a.element()));
        if (i == 0) {
          evaluated_sum = p;
        } else {
          CHECK(evaluated_sum.Add(p, &evaluated_sum));
        }
        break;
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
    auto c = ristretto::Scalar::Reduce(sha::Sha512(proof_point, blinded, handshake_hash));
    auto proof_scalar = rand.Add(c.Mult(sk_[i]));

    client::Request4 r;
    r.mutable_restore2()->set_auth_point(proof_point.ToString());
    r.mutable_restore2()->set_auth_scalar(proof_scalar.ToString());
    r.mutable_restore2()->set_version(v);
    return r;
  }

  const DB4::BackupID& id() const { return id_; }
  std::string authenticated_id() const { return util::ByteArrayToString(id_); }

  bool EncryptionKeyMatches(const std::array<client::Response4::Restore2, N>& restores) {
    DB4::AESKey a = {0};
    DB4::AESKey b;
    for (int i = 0; i < N; i++) {
      CHECK(error::OK == util::StringIntoByteArray(restores[i].encryption_secretshare(), &b));
      for (int j = 0; j < sizeof(DB4::AESKey); j++) {
        a[j] ^= b[j];
      }
    }
    return util::ConstantTimeEquals(a, aes_enc_);
  }

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
  uint64_t version_;
};

const size_t N = 3;

class DB4Test : public ::testing::Test {
 public:
  DB4Test() {}
 protected:

  static void SetUpTestCase() {
    env::Init(env::SIMULATED);
  }

  void SetUp() {
    for (int i = 0; i < N; i++) {
      dbs[i] = std::make_unique<DB4>(&merk);
      states[i] = dbs[i]->P()->NewClientState(client.authenticated_id());
    }
  }

  context::Context ctx;
  merkle::Tree merk;
  DB4Client<N> client;
  std::array<std::unique_ptr<DB4>, N> dbs;
  std::array<std::unique_ptr<DB::ClientState>, N> states;

  void VerifyRestore() {
    ristretto::Scalar b = ristretto::Scalar::Random();
    std::array<client::Response4::Restore1, N> restore1resp;
    std::array<std::string, N> blinded_points;
    std::array<DB::HandshakeHash, N> handshake_hashes{ {0} };
    for (int i = 0; i < N; i++) {
      LOG(INFO) << "Restore1." << i;
      CHECK(error::OK == env::environment->RandomBytes(handshake_hashes[i].data(), handshake_hashes[i].size()));
      auto req = client.Restore1(i, b);
      blinded_points[i] = req.restore1().blinded();
      auto [resp, err] = RunRequest(&ctx, dbs[i].get(), states[i].get(), req, handshake_hashes[i]);
      ASSERT_EQ(error::OK, err);
      ASSERT_EQ(client::Response4::kRestore1, resp->inner_case());
      ASSERT_EQ(resp->restore1().status(), client::Response4::OK);
      restore1resp[i].MergeFrom(resp->restore1());
    }

    std::array<client::Response4::Restore2, N> restore2resp;
    for (int i = 0; i < N; i++) {
      LOG(INFO) << "Restore2." << i;
      auto req = client.Restore2(i, b, blinded_points[i], restore1resp, handshake_hashes[i]);
      auto [resp, err] = RunRequest(&ctx, dbs[i].get(), states[i].get(), req, handshake_hashes[i]);
      ASSERT_EQ(error::OK, err);
      ASSERT_EQ(client::Response4::kRestore2, resp->inner_case());
      ASSERT_EQ(resp->restore2().status(), client::Response4::OK);
      restore2resp[i].MergeFrom(resp->restore2());
    }
    ASSERT_TRUE(client.EncryptionKeyMatches(restore2resp));
  }

  void Create(int tries) {
    for (int i = 0; i < N; i++) {
      LOG(INFO) << "Create." << i;
      auto req = client.Create(i, tries);
      auto [resp, err] = RunRequest(&ctx, dbs[i].get(), states[i].get(), req, std::array<uint8_t, 32>{0});
      ASSERT_EQ(error::OK, err);
      ASSERT_EQ(resp->create().status(), client::Response4::OK);
      ASSERT_EQ(client::Response4::kCreate, resp->inner_case());
    }
  }
};

TEST_F(DB4Test, SingleBackupLifecycle) {
  Create(10);
  VerifyRestore();
}

TEST_F(DB4Test, Restore1RemovesKey) {
  Create(10);
  std::array<uint8_t, 32> handshake_hash{0};
  for (int i = 0; i < 10; i++) {
    ristretto::Scalar b = ristretto::Scalar::Random();
    auto req = client.Restore1(0, b);
    auto [resp, err] = RunRequest(&ctx, dbs[0].get(), states[0].get(), req, handshake_hash);
    ASSERT_EQ(error::OK, err);
    ASSERT_EQ(client::Response4::kRestore1, resp->inner_case());
    ASSERT_EQ(resp->restore1().status(), client::Response4::OK);
    ASSERT_EQ(resp->restore1().tries_remaining(), 10-i-1);
  }
  // Verify that after the last try, we get a MISSING error.
  {
    ristretto::Scalar b = ristretto::Scalar::Random();
    auto req = client.Restore1(0, b);
    auto [resp, err] = RunRequest(&ctx, dbs[0].get(), states[0].get(), req, handshake_hash);
    ASSERT_EQ(error::OK, err);
    ASSERT_EQ(client::Response4::kRestore1, resp->inner_case());
    ASSERT_EQ(resp->restore1().status(), client::Response4::MISSING);
  }
}

TEST_F(DB4Test, QueryClearsRestoreState) {
  Create(10);

  ristretto::Scalar b = ristretto::Scalar::Random();
  std::array<client::Response4::Restore1, N> restore1resp;
  std::array<std::string, N> blinded_points;
  std::array<std::array<uint8_t, 32>,N> handshake_hashes{ {0} };
  for (int i = 0; i < N; i++) {
    LOG(INFO) << "Restore1." << i;
    auto req = client.Restore1(i, b);
    CHECK(error::OK == env::environment->RandomBytes(handshake_hashes[i].data(), handshake_hashes[i].size()));
    blinded_points[i] = req.restore1().blinded();
    auto [resp, err] = RunRequest(&ctx, dbs[i].get(), states[i].get(), req, handshake_hashes[i]);
    ASSERT_EQ(error::OK, err);
    ASSERT_EQ(client::Response4::kRestore1, resp->inner_case());
    ASSERT_EQ(resp->restore1().status(), client::Response4::OK);
    ASSERT_EQ(resp->restore1().tries_remaining(), 9);
    restore1resp[i].MergeFrom(resp->restore1());
  }

  { int i = 0;
    LOG(INFO) << "Query." << i;
    client::Request4 req;
    req.mutable_query();
    auto [resp, err] = RunRequest(&ctx, dbs[i].get(), states[i].get(), req, handshake_hashes[i]);
    ASSERT_EQ(error::OK, err);
    ASSERT_EQ(client::Response4::kQuery, resp->inner_case());
    ASSERT_EQ(resp->query().status(), client::Response4::OK);
    ASSERT_EQ(resp->query().tries_remaining(), 9);
  }

  { int i = 0;
    LOG(INFO) << "Restore2." << i;
    auto req = client.Restore2(i, b, blinded_points[i], restore1resp, handshake_hashes[i]);
    auto [resp, err] = RunRequest(&ctx, dbs[i].get(), states[i].get(), req, handshake_hashes[i]);
    ASSERT_EQ(error::OK, err);
    ASSERT_EQ(client::Response4::kRestore2, resp->inner_case());
    ASSERT_EQ(resp->restore2().status(), client::Response4::RESTORE1_MISSING);
  }
}

TEST_F(DB4Test, RemoveRemovesRow) {
  Create(10);
  std::array<uint8_t, 32> handshake_hash{42};
  { int i = 0;
    LOG(INFO) << "Remove." << i;
    client::Request4 req;
    req.mutable_remove();
    auto [resp, err] = RunRequest(&ctx, dbs[i].get(), states[i].get(), req, handshake_hash);
    ASSERT_EQ(error::OK, err);
    ASSERT_EQ(client::Response4::kRemove, resp->inner_case());
  }

  ristretto::Scalar b = ristretto::Scalar::Random();
  { int i = 0;
    LOG(INFO) << "Restore1." << i;
    auto req = client.Restore1(i, b);
    auto [resp, err] = RunRequest(&ctx, dbs[i].get(), states[i].get(), req, handshake_hash);
    ASSERT_EQ(error::OK, err);
    ASSERT_EQ(client::Response4::kRestore1, resp->inner_case());
    ASSERT_EQ(resp->restore1().status(), client::Response4::MISSING);
  }
}

TEST_F(DB4Test, RemoveRemovesRotation) {
  Create(10);
  std::array<uint8_t, 32> handshake_hash{42};

  uint64_t v;
  auto rotate_start = client.RotateStart(&v);
  for (int i = 0; i < N; i++) {
    VerifyRestore();
    LOG(INFO) << "RotateStart." << i;
    auto [resp, err] = RunRequest(&ctx, dbs[i].get(), states[i].get(), rotate_start[i], handshake_hash);
    ASSERT_EQ(error::OK, err);
    ASSERT_EQ(client::Response4::kRotateStart, resp->inner_case());
    ASSERT_EQ(resp->rotate_start().status(), client::Response4::OK);
  }

  rotate_start = client.RotateStart(&v);
  for (int i = 0; i < N; i++) {
    VerifyRestore();
    LOG(INFO) << "RotateStart." << i;
    auto [resp, err] = RunRequest(&ctx, dbs[i].get(), states[i].get(), rotate_start[i], handshake_hash);
    ASSERT_EQ(error::OK, err);
    ASSERT_EQ(client::Response4::kRotateStart, resp->inner_case());
    ASSERT_EQ(resp->rotate_start().status(), client::Response4::ALREADY_ROTATING);
  }

  { int i = 0;
    LOG(INFO) << "Remove." << i;
    client::Request4 req;
    req.mutable_remove();
    auto [resp, err] = RunRequest(&ctx, dbs[i].get(), states[i].get(), req, handshake_hash);
    ASSERT_EQ(error::OK, err);
    ASSERT_EQ(client::Response4::kRemove, resp->inner_case());
  }

  Create(10);
  rotate_start = client.RotateStart(&v);
  for (int i = 0; i < N; i++) {
    VerifyRestore();
    LOG(INFO) << "RotateStart." << i;
    auto [resp, err] = RunRequest(&ctx, dbs[i].get(), states[i].get(), rotate_start[i], handshake_hash);
    ASSERT_EQ(error::OK, err);
    ASSERT_EQ(client::Response4::kRotateStart, resp->inner_case());
    ASSERT_EQ(resp->rotate_start().status(), client::Response4::OK);
  }
}

TEST_F(DB4Test, MaxTriesZeroKeepsTriesTheSame) {
  Create(10);
  std::array<uint8_t, 32> handshake_hash{42};

  ristretto::Scalar b = ristretto::Scalar::Random();
  { int i = 0;
    LOG(INFO) << "Restore1." << i;
    auto req = client.Restore1(i, b);
    auto [resp, err] = RunRequest(&ctx, dbs[i].get(), states[i].get(), req, handshake_hash);
    ASSERT_EQ(error::OK, err);
    ASSERT_EQ(client::Response4::kRestore1, resp->inner_case());
    ASSERT_EQ(resp->restore1().status(), client::Response4::OK);
    ASSERT_EQ(resp->restore1().tries_remaining(), 9);
  }

  { int i = 0;
    LOG(INFO) << "Create." << i;
    auto req = client.Create(i, 0);
    auto [resp, err] = RunRequest(&ctx, dbs[i].get(), states[i].get(), req, handshake_hash);
    ASSERT_EQ(error::OK, err);
    ASSERT_EQ(resp->create().status(), client::Response4::OK);
    ASSERT_EQ(client::Response4::kCreate, resp->inner_case());
    ASSERT_EQ(resp->create().tries_remaining(), 9);
  }
}

TEST_F(DB4Test, RotateLifecycle) {
  Create(255);
  std::array<uint8_t, 32> handshake_hash{42};

  uint64_t v;
  auto rotate_start = client.RotateStart(&v);
  for (int i = 0; i < N; i++) {
    VerifyRestore();
    LOG(INFO) << "RotateStart." << i;
    auto [resp, err] = RunRequest(&ctx, dbs[i].get(), states[i].get(), rotate_start[i], handshake_hash);
    ASSERT_EQ(error::OK, err);
    ASSERT_EQ(client::Response4::kRotateStart, resp->inner_case());
    ASSERT_EQ(resp->rotate_start().status(), client::Response4::OK);
  }
  client::Request4 commit;
  commit.mutable_rotate_commit()->set_version(v);
  for (int i = 0; i < N; i++) {
    VerifyRestore();
    LOG(INFO) << "RotateCommit." << i;
    auto [resp, err] = RunRequest(&ctx, dbs[i].get(), states[i].get(), commit, handshake_hash);
    ASSERT_EQ(error::OK, err);
    ASSERT_EQ(client::Response4::kRotateCommit, resp->inner_case());
    ASSERT_EQ(resp->rotate_commit().status(), client::Response4::OK);
  }
    VerifyRestore();
}

TEST_F(DB4Test, SingleServerBackupRestore) {
  DB4Client<1> client;
  LOG(INFO) << "Create";
  merkle::Tree merk;
  auto db = std::make_unique<DB4>(&merk);
  auto state = db->P()->NewClientState(client.authenticated_id());
  DB::HandshakeHash handshake_hash{1};

  {
    auto req = client.Create(0, 10);
    auto [resp, err] = RunRequest(&ctx, db.get(), state.get(), req, handshake_hash);
    ASSERT_EQ(error::OK, err);
    ASSERT_EQ(client::Response4::kCreate, resp->inner_case());
    ASSERT_EQ(resp->create().status(), client::Response4::OK);
  }
  {
    ristretto::Scalar b = ristretto::Scalar::Random();
    auto req1 = client.Restore1(0, b);
    auto [resp1, err1] = RunRequest(&ctx, db.get(), state.get(), req1, handshake_hash);
    ASSERT_EQ(error::OK, err1);
    ASSERT_EQ(client::Response4::kRestore1, resp1->inner_case());
    ASSERT_EQ(resp1->restore1().status(), client::Response4::OK);
    const std::array<client::Response4::Restore1, 1> resps{resp1->restore1()};

    auto req2 = client.Restore2(0, b, req1.restore1().blinded(), resps, handshake_hash);
    auto [resp2, err2] = RunRequest(&ctx, db.get(), state.get(), req2, handshake_hash);
    ASSERT_EQ(error::OK, err2);
    ASSERT_EQ(client::Response4::kRestore2, resp2->inner_case());
    ASSERT_EQ(resp2->restore2().status(), client::Response4::OK);
    const std::array<client::Response4::Restore2, 1> restores{resp2->restore2()};

    ASSERT_TRUE(client.EncryptionKeyMatches(restores));
  }
}

}  // namespace svr2::db
