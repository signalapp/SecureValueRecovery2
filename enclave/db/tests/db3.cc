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
#include "db/db3.h"
#include "env/env.h"
#include "util/log.h"
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

class DB3Test : public ::testing::Test {
 public:
  DB3Test() : db(&merk) {}
 protected:
  static void SetUpTestCase() {
    env::Init(env::SIMULATED);
  }

  context::Context ctx;
  merkle::Tree merk;
  DB3 db;
  static std::string backup_id;
};

std::string DB3Test::backup_id("BACKUP7890123456");

TEST_F(DB3Test, SingleBackupLifecycle) {
  std::string blinded_element;
  blinded_element.resize(DB3::ELEMENT_SIZE);
  crypto_core_ristretto255_random(
      reinterpret_cast<uint8_t*>(blinded_element.data()));
  std::string evaluated_element;
  int tries = 3;
  {
    client::Log3 log;
    log.set_backup_id(backup_id);
    auto b = log.mutable_req()->mutable_create();
    b->set_max_tries(3);
    b->set_blinded_element(blinded_element);
    auto priv = DB3::ClientState::NewKey();
    log.set_create_privkey(util::ByteArrayToString(priv));

    auto resp = dynamic_cast<client::Response3*>(db.Run(&ctx, log));
    auto r = resp->create();
    ASSERT_EQ(client::CreateResponse::OK, r.status());
    evaluated_element = r.evaluated_element();
  }
  {
    client::Log3 log;
    log.set_backup_id(backup_id);
    log.mutable_req()->mutable_query();

    auto resp = dynamic_cast<client::Response3*>(db.Run(&ctx, log));
    auto r = resp->query();
    ASSERT_EQ(client::QueryResponse::OK, r.status());
    ASSERT_EQ(3, r.tries_remaining());
  }
  for (int i = 0; i < tries; i++) {
    client::Log3 log;
    log.set_backup_id(backup_id);
    auto b = log.mutable_req()->mutable_evaluate();
    b->set_blinded_element(blinded_element);

    auto resp = dynamic_cast<client::Response3*>(db.Run(&ctx, log));
    auto r = resp->evaluate();
    ASSERT_EQ(client::EvaluateResponse::OK, r.status());
    EXPECT_EQ(r.tries_remaining(), tries - i - 1);
    EXPECT_EQ(r.evaluated_element(), evaluated_element);
  }
  {
    client::Log3 log;
    log.set_backup_id(backup_id);
    auto b = log.mutable_req()->mutable_evaluate();
    b->set_blinded_element(blinded_element);

    auto resp = dynamic_cast<client::Response3*>(db.Run(&ctx, log));
    auto r = resp->evaluate();
    ASSERT_EQ(client::EvaluateResponse::MISSING, r.status());
  }
}

TEST_F(DB3Test, Remove) {
  std::string blinded_element;
  blinded_element.resize(DB3::ELEMENT_SIZE);
  crypto_core_ristretto255_random(
      reinterpret_cast<uint8_t*>(blinded_element.data()));
  std::string evaluated_element;
  int tries = 3;
  {
    client::Log3 log;
    log.set_backup_id(backup_id);
    auto b = log.mutable_req()->mutable_create();
    b->set_max_tries(3);
    b->set_blinded_element(blinded_element);
    auto priv = DB3::ClientState::NewKey();
    log.set_create_privkey(util::ByteArrayToString(priv));

    auto resp = dynamic_cast<client::Response3*>(db.Run(&ctx, log));
    auto r = resp->create();
    ASSERT_EQ(client::CreateResponse::OK, r.status());
    evaluated_element = r.evaluated_element();
  }
  {
    client::Log3 log;
    log.set_backup_id(backup_id);
    auto b = log.mutable_req()->mutable_remove();

    db.Run(&ctx, log);
  }
  {
    client::Log3 log;
    log.set_backup_id(backup_id);
    auto b = log.mutable_req()->mutable_evaluate();
    b->set_blinded_element(blinded_element);

    auto resp = dynamic_cast<client::Response3*>(db.Run(&ctx, log));
    auto r = resp->evaluate();
    ASSERT_EQ(client::EvaluateResponse::MISSING, r.status());
  }
}

// IETF VOPRF v21 test vectors (https://www.ietf.org/archive/id/draft-irtf-cfrg-voprf-21.html)

const std::string context_string_prefix{"OPRFV1-"};
const std::string ciphersuite_identifier{"ristretto255-SHA512"};

static const size_t PRIVATE_KEY_SIZE = 32;
static const size_t PUBLIC_KEY_SIZE = 32;
static const size_t SHA512_BLOCK_BYTES = 128;
static const size_t SHA512_OUTPUT_BYTES = 64;

// https://www.rfc-editor.org/rfc/rfc8017
std::string I2OSP(uint64_t x, size_t n) {
  std::string X;
  X.resize(n);
  for(size_t i = 0; i < n; ++i) {
    X[n-1-i] = x%256;
    x /= 256;
  }
  return X;
}

/*
def CreateContextString(mode, identifier):
  return "OPRFV1-" || I2OSP(mode, 1) || "-" || identifier
*/
std::string context_string() {
  auto mode = I2OSP(0x00, 1);
  return context_string_prefix + mode + "-" + ciphersuite_identifier;
}

std::string sha512_hash(std::string s) {
  crypto_hash_sha512_state sha;
  crypto_hash_sha512_init(&sha);
  crypto_hash_sha512_update(&sha, reinterpret_cast<uint8_t*>(s.data()), s.size());
  std::array<uint8_t, SHA512_OUTPUT_BYTES> out;
  crypto_hash_sha512_final(&sha, out.data());
  return util::ByteArrayToString(out);
}

std::string strxor(const std::string& lhs, const std::string& rhs) {
  CHECK(lhs.size() == rhs.size());
  std::string result;
  result.resize(rhs.size());
  for(size_t i = 0; i < lhs.size(); ++i) {
    result[i] = lhs[i] ^ rhs[i];
  }
  return result;
}

template<size_t N>
bool is_zero(const std::array<uint8_t, N>& arr) {
  bool result = true;
  for(size_t i = 0; i < N; ++i) {
    result = result && (arr[i] == 0);
  }
  return result;
}

// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-12#name-expand_message_xmd
template<size_t N> 
std::array<uint8_t, N> ExpandMessageXMD_SHA512(std::string msg, std::string dst) {
  auto ell = N / SHA512_OUTPUT_BYTES + ((N%SHA512_OUTPUT_BYTES == 0) ? 0 : 1);
  CHECK(ell <= 255);
  LOG(DEBUG) << "expand_message_xmd blocks: " << ell;
  std::array<uint8_t, N> result{0};

  auto dst_prime = dst + I2OSP(dst.size(),1);
  auto z_pad = I2OSP(0, SHA512_BLOCK_BYTES);
  auto l_i_b_str = I2OSP(N,2);
  auto msg_prime = z_pad + msg + l_i_b_str + I2OSP(0,1) + dst_prime;
  auto b_0 = sha512_hash(msg_prime);
  auto b_1 = sha512_hash(b_0 + I2OSP(1,1) + dst_prime);
  auto bytes_to_copy = std::min(b_1.size(), N);
  std::copy(b_1.data(), b_1.data()+ bytes_to_copy, result.data());
  auto b_last = b_1;
  for(size_t i = 2; i <= ell; ++i) {
    auto b_next = sha512_hash(
      strxor(b_0, b_last)
      + I2OSP(i,1)
      + dst_prime
    );
    auto bytes_to_copy = std::min(SHA512_OUTPUT_BYTES, N - (i-1)*SHA512_OUTPUT_BYTES);
    LOG(DEBUG) << "copying " << bytes_to_copy << " bytes";
    std::copy(b_next.data(), b_next.data() + bytes_to_copy, result.data() + (i-1)*SHA512_OUTPUT_BYTES);
    b_last = b_next;
  }
  return result;
}

std::array<uint8_t, PRIVATE_KEY_SIZE> HashToScalar(const std::string& data) {
  std::string dst = std::string{"HashToScalar-"} + context_string();
  auto uniform_bytes = ExpandMessageXMD_SHA512<64>(data, dst);
  std::array<uint8_t, PRIVATE_KEY_SIZE> s;
  // TODO: verify that this interprets numbers in little-endian order
  crypto_core_ristretto255_scalar_reduce(s.data(), uniform_bytes.data());
  return s;
}

std::pair<std::array<uint8_t, PUBLIC_KEY_SIZE>, std::array<uint8_t, PRIVATE_KEY_SIZE>>
DeriveKeyPair(std::string seed, std::string info) {
  std::string derive_input = seed + I2OSP(info.size(),2) + info;
  size_t counter = 0;
  std::array<uint8_t, PRIVATE_KEY_SIZE> sk{0};
  std::array<uint8_t, PUBLIC_KEY_SIZE> pk{0};

  std::string dst = std::string{"DeriveKeyPair"} + context_string();
  while(is_zero(sk)) {
    LOG(DEBUG) << "derive key pair attempt " << counter;
    CHECK(counter < 255);
    auto uniform_bytes = 
      ExpandMessageXMD_SHA512<64>(derive_input + I2OSP(counter,1), dst);
    crypto_core_ristretto255_scalar_reduce(sk.data(), uniform_bytes.data());
    counter += 1;
  }
  CHECK(0 == crypto_scalarmult_ristretto255_base(pk.data(), sk.data()));

  return std::make_pair(pk, sk);
}

std::array<uint8_t, PUBLIC_KEY_SIZE> HashToGroup(std::string input) {
  std::string dst = std::string{"HashToGroup-"} + context_string();
  auto uniform_bytes = ExpandMessageXMD_SHA512<64>(input, dst);
  std::array<uint8_t, PUBLIC_KEY_SIZE> result{};
  crypto_core_ristretto255_from_hash(result.data(), uniform_bytes.data());
  return result;
}

TEST_F(DB3Test, IETF_A_1_1) {
  ASSERT_AND_ASSIGN(seed, util::HexToBytes("a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3"));
  ASSERT_AND_ASSIGN(key_info, util::HexToBytes("74657374206b6579"));
  auto sk_expected = "5ebcea5ee37023ccb9fc2d2019f9d7737be85591ae8652ffa9ef0f4d37063b0e";

  auto cs = context_string();
  for(size_t i = 0; i < cs.size(); ++i) {
    LOG(DEBUG) << " (" << static_cast<int>(cs[i]) << ") " << cs[i] ;
  }
  LOG(DEBUG) << cs;

  auto [pk, sk] = DeriveKeyPair(seed, key_info);
  auto sk_hex = util::BytesToHex(sk.data(), PRIVATE_KEY_SIZE);
  EXPECT_EQ(sk_hex, sk_expected);
}

TEST_F(DB3Test, EXPAND_MESSAGE_XMD_1) {
  std::string dst{"QUUX-V01-CS02-with-expander-SHA512-256"};
  std::string msg{"abc"};
  size_t len_in_bytes = 0x80;
  auto uniform_bytes = ExpandMessageXMD_SHA512<0x80>(msg, dst);
  auto hex = util::BytesToHex(uniform_bytes.data(), uniform_bytes.size());

  EXPECT_EQ(util::BytesToHex(uniform_bytes.data(), uniform_bytes.size()), "7f1dddd13c08b543f2e2037b14cefb255b44c83cc397c1786d975653e36a6b11bdd7732d8b38adb4a0edc26a0cef4bb45217135456e58fbca1703cd6032cb1347ee720b87972d63fbf232587043ed2901bce7f22610c0419751c065922b488431851041310ad659e4b23520e1772ab29dcdeb2002222a363f0c2b1c972b3efe1");
}

TEST_F(DB3Test, EXPAND_MESSAGE_XMD_2) {
  std::string dst{"QUUX-V01-CS02-with-expander-SHA512-256"};
  std::string msg{"abcdef0123456789"};
  size_t len_in_bytes = 0x20;
  auto uniform_bytes = ExpandMessageXMD_SHA512<0x20>(msg, dst);
  LOG(DEBUG) << util::BytesToHex(uniform_bytes.data(), uniform_bytes.size());

  EXPECT_EQ(util::BytesToHex(uniform_bytes.data(), uniform_bytes.size()), "087e45a86e2939ee8b91100af1583c4938e0f5fc6c9db4b107b83346bc967f58");
}

TEST_F(DB3Test, IETF_A_1_1_1) {
  ASSERT_AND_ASSIGN(sk, util::HexToBytes("5ebcea5ee37023ccb9fc2d2019f9d7737be85591ae8652ffa9ef0f4d37063b0e"));
  ASSERT_AND_ASSIGN(input, util::HexToBytes("00"));
  ASSERT_AND_ASSIGN(blind, util::HexToBytes("64d37aed22a27f5191de1c1d69fadb899d8862b58eb4220029e036ec4c1f6706"));
  ASSERT_AND_ASSIGN(blinded_element_expected, util::HexToBytes("609a0ae68c15a3cf6903766461307e5c8bb2f95e7e6550e1ffa2dc99e412803c"));
  std::string evaluation_element_hex = "7ec6578ae5120958eb2db1745758ff379e77cb64fe77b0b2d8cc917ea0869c7e";
  std::string output_hex = "527759c3d9366f277d8c6020418d96bb393ba2afb20ff90df23fb7708264e2f3ab9135e3bd69955851de4b1f9fe8a0973396719b7912ba9ee8aa7d0b5e24bcf6";

  // Compute blinded element
  std::array<uint8_t, 32> blinded_element; 
  std::array<uint8_t, PUBLIC_KEY_SIZE> elt = HashToGroup(input);
  auto ret = crypto_scalarmult_ristretto255(blinded_element.data(), reinterpret_cast<uint8_t*>(blind.data()), elt.data());
  EXPECT_EQ(util::BytesToHex(blinded_element.data(), PUBLIC_KEY_SIZE), "609a0ae68c15a3cf6903766461307e5c8bb2f95e7e6550e1ffa2dc99e412803c");

  // send to server to evaluate
  std::string evaluated_element;
  int tries = 3;
  {
    client::Log3 log;
    log.set_backup_id(backup_id);
    auto b = log.mutable_req()->mutable_create();
    b->set_max_tries(3);
    b->set_blinded_element(util::ByteArrayToString(blinded_element));
    log.set_create_privkey(sk);

    auto resp = dynamic_cast<client::Response3*>(db.Run(&ctx, log));
    auto r = resp->create();
    ASSERT_EQ(client::CreateResponse::OK, r.status());
    evaluated_element = r.evaluated_element();
    auto [ee_data, err] = util::StringToByteArray<PUBLIC_KEY_SIZE>(evaluated_element);
    EXPECT_EQ(util::BytesToHex(ee_data.data(), ee_data.size()), evaluation_element_hex);
  }
}


TEST_F(DB3Test, IETF_A_1_1_2) {
  ASSERT_AND_ASSIGN(seed, util::HexToBytes("a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3"));
  ASSERT_AND_ASSIGN(key_info, util::HexToBytes("74657374206b6579"));
  ASSERT_AND_ASSIGN(sk, util::HexToBytes("5ebcea5ee37023ccb9fc2d2019f9d7737be85591ae8652ffa9ef0f4d37063b0e"));
  ASSERT_AND_ASSIGN(input, util::HexToBytes("5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a"));
  ASSERT_AND_ASSIGN(blind, util::HexToBytes("64d37aed22a27f5191de1c1d69fadb899d8862b58eb4220029e036ec4c1f6706"));
  ASSERT_AND_ASSIGN(blinded_element_expected, util::HexToBytes("da27ef466870f5f15296299850aa088629945a17d1f5b7f5ff043f76b3c06418"));
  auto evaluation_element_hex = "b4cbf5a4f1eeda5a63ce7b77c7d23f461db3fcab0dd28e4e17cecb5c90d02c25";
  auto output_hex = "f4a74c9c592497375e796aa837e907b1a045d34306a749db9f34221f7e750cb4f2a6413a6bf6fa5e19ba6348eb673934a722a7ede2e7621306d18951e7cf2c73";

 // Compute blinded element
  std::array<uint8_t, 32> blinded_element; 
  std::array<uint8_t, PUBLIC_KEY_SIZE> elt = HashToGroup(input);
  auto ret = crypto_scalarmult_ristretto255(blinded_element.data(), reinterpret_cast<uint8_t*>(blind.data()), elt.data());
  EXPECT_EQ(util::BytesToHex(blinded_element.data(), PUBLIC_KEY_SIZE), "da27ef466870f5f15296299850aa088629945a17d1f5b7f5ff043f76b3c06418");

  // send to server to evaluate
  std::string evaluated_element;
  int tries = 3;
  {
    client::Log3 log;
    log.set_backup_id(backup_id);
    auto b = log.mutable_req()->mutable_create();
    b->set_max_tries(3);
    b->set_blinded_element(util::ByteArrayToString(blinded_element));
    log.set_create_privkey(sk);

    auto resp = dynamic_cast<client::Response3*>(db.Run(&ctx, log));
    auto r = resp->create();
    ASSERT_EQ(client::CreateResponse::OK, r.status());
    evaluated_element = r.evaluated_element();
    auto [ee_data, err] = util::StringToByteArray<PUBLIC_KEY_SIZE>(evaluated_element);
    EXPECT_EQ(util::BytesToHex(ee_data.data(), ee_data.size()), evaluation_element_hex);
  }
}

TEST_F(DB3Test, LoadRowsThenRecover) {
  std::string blinded_element;
  blinded_element.resize(DB3::ELEMENT_SIZE);
  crypto_core_ristretto255_random(
      reinterpret_cast<uint8_t*>(blinded_element.data()));
  std::string evaluated_element;
  int tries = 3;
  {
    client::Log3 log;
    log.set_backup_id(backup_id);
    auto b = log.mutable_req()->mutable_create();
    b->set_max_tries(3);
    b->set_blinded_element(blinded_element);
    auto priv = DB3::ClientState::NewKey();
    log.set_create_privkey(util::ByteArrayToString(priv));

    auto resp = dynamic_cast<client::Response3*>(db.Run(&ctx, log));
    auto r = resp->create();
    ASSERT_EQ(client::CreateResponse::OK, r.status());
    evaluated_element = r.evaluated_element();
  }
  merkle::Tree m2;
  DB3 db2(&m2);
  // Replicate db->db2.
  {
    google::protobuf::RepeatedPtrField<std::string> rows;
    auto [s, err] = db.RowsAsProtos(&ctx, "", 2, &rows);
    ASSERT_EQ(error::OK, err);
    ASSERT_EQ(1, rows.size());
    ASSERT_EQ("BACKUP7890123456", s);

    auto [s2, err2] = db2.LoadRowsFromProtos(&ctx, rows);
    ASSERT_EQ(error::OK, err2);
    ASSERT_EQ("BACKUP7890123456", s2);
  }
  {
    client::Log3 log;
    log.set_backup_id(backup_id);
    auto b = log.mutable_req()->mutable_evaluate();
    b->set_blinded_element(blinded_element);

    auto resp = dynamic_cast<client::Response3*>(db2.Run(&ctx, log));
    auto r = resp->evaluate();
    ASSERT_EQ(client::EvaluateResponse::OK, r.status());
    EXPECT_EQ(r.tries_remaining(), 2);
    EXPECT_EQ(r.evaluated_element(), evaluated_element);
  }
}

TEST_F(DB3Test, LoadManyRows) {
  std::string blinded_element;
  blinded_element.resize(DB3::ELEMENT_SIZE);
  crypto_core_ristretto255_random(
      reinterpret_cast<uint8_t*>(blinded_element.data()));
  std::string evaluated_element;
  client::Log3 log;
  log.set_backup_id(backup_id);
  auto b = log.mutable_req()->mutable_create();
  b->set_max_tries(3);
  b->set_blinded_element(blinded_element);
  auto priv = DB3::ClientState::NewKey();
  log.set_create_privkey(util::ByteArrayToString(priv));
  for (size_t i = 0; i <= 10000; i++) {
    if (i % 1000000 == 0) LOG(INFO) << i;
    util::BigEndian64Bytes(i, reinterpret_cast<uint8_t*>(log.mutable_backup_id()->data()));
    auto resp = dynamic_cast<client::Response3*>(db.Run(&ctx, log));
    auto r = resp->create();
    ASSERT_EQ(client::CreateResponse::OK, r.status());
    evaluated_element = r.evaluated_element();
  }
}

TEST_F(DB3Test, ReplicateManyRows) {
  std::string blinded_element;
  blinded_element.resize(DB3::ELEMENT_SIZE);
  crypto_core_ristretto255_random(
      reinterpret_cast<uint8_t*>(blinded_element.data()));
  std::string evaluated_element;
  int tries = 3;
  {
    client::Log3 log;
    log.set_backup_id(backup_id);
    auto b = log.mutable_req()->mutable_create();
    b->set_max_tries(3);
    b->set_blinded_element(blinded_element);
    auto priv = DB3::ClientState::NewKey();
    log.set_create_privkey(util::ByteArrayToString(priv));

    auto resp = dynamic_cast<client::Response3*>(db.Run(&ctx, log));
    auto r = resp->create();
    ASSERT_EQ(client::CreateResponse::OK, r.status());
    evaluated_element = r.evaluated_element();
  }
  merkle::Tree m2;
  DB3 db2(&m2);
  // Replicate db->db2.
  google::protobuf::RepeatedPtrField<std::string> rows;
  auto [s, err] = db.RowsAsProtos(&ctx, "", 2, &rows);
  ASSERT_EQ(error::OK, err);
  ASSERT_EQ(1, rows.size());
  ASSERT_EQ("BACKUP7890123456", s);

  e2e::DB3RowState rowstate;
  ASSERT_TRUE(rowstate.ParseFromString(rows.Get(0)));

  for (size_t i = 0; i < 10000; i++) {
    if (i % 1000000 == 0) LOG(INFO) << i;
    util::BigEndian64Bytes(i, reinterpret_cast<uint8_t*>(rowstate.mutable_backup_id()->data()));
    rowstate.SerializeToString(rows.Mutable(0));
    auto [s2, err2] = db2.LoadRowsFromProtos(&ctx, rows);
    ASSERT_EQ(error::OK, err2);
  }
}

TEST_F(DB3Test, KnownKey) {
  // std::string blinded_element("\xa8\xca\x6c\x4f\x49\x7d\xc1\x0a\x01\x77\xf7\x44\x76\x15\xd7\x46\xc4\xf6\x0f\xc7\x0e\x4f\xee\xd5\x63\x0c\x71\x27\x08\x75\x81\x54", 32);
  std::string blinded_element("\x46\x32\x3c\xfb\xf6\x3c\x3f\x7b\x59\xcb\x43\xba\x7b\x14\x2e\xae\x7b\x09\x02\xff\xc2\x20\x85\x90\x9b\x52\x74\xde\x9b\xce\xad\x72", 32);
  {
    client::Log3 log;
    log.set_backup_id(backup_id);
    auto b = log.mutable_req()->mutable_create();
    b->set_max_tries(3);
    b->set_blinded_element(blinded_element);
    auto priv = DB3::ClientState::NewKey();
    log.set_create_privkey(util::ByteArrayToString(priv));

    ASSERT_EQ(db3_protocol.ValidateClientLog(log), error::OK);
    auto resp = dynamic_cast<client::Response3*>(db.Run(&ctx, log));
    auto r = resp->create();
    ASSERT_EQ(client::CreateResponse::OK, r.status());
  }
}

TEST_F(DB3Test, BitFlipKey) {
  std::string blinded_element("\x46\x32\x3c\xfb\xf6\x3c\x3f\x7b\x59\xcb\x43\xba\x7b\x14\x2e\xae\x7b\x09\x02\xff\xc2\x20\x85\x90\x9b\x52\x74\xde\x9b\xce\xad\x72", 32);
  auto priv = DB3::ClientState::NewKey();
  CHECK(priv.size() == DB3::SCALAR_SIZE);
  int failures = 0;
  // bytes
  for (int i = 0; i < DB3::SCALAR_SIZE; i++) {
    // bits
    for (int j = 0; j < 8; j++) {
      std::string backup_id("\0BACKUP890123456", 16);
      backup_id[0] += i * 8 + j;
      client::Log3 log;
      log.set_backup_id(backup_id);
      auto b = log.mutable_req()->mutable_create();
      b->set_max_tries(3);
      b->set_blinded_element(blinded_element);
      auto priv2 = priv;
      priv2[i] ^= 1 << j;
      log.set_create_privkey(util::ByteArrayToString(priv2));
      auto resp = dynamic_cast<client::Response3*>(db.Run(&ctx, log));
      auto r = resp->create();
      if (r.status() != client::CreateResponse::OK) {
        failures++;
      }
    }
  }
  ASSERT_EQ(failures, 0);
}

TEST_F(DB3Test, BitFlipElement) {
  std::string blinded_element("\x46\x32\x3c\xfb\xf6\x3c\x3f\x7b\x59\xcb\x43\xba\x7b\x14\x2e\xae\x7b\x09\x02\xff\xc2\x20\x85\x90\x9b\x52\x74\xde\x9b\xce\xad\x72", 32);
  auto priv = DB3::ClientState::NewKey();
  CHECK(priv.size() == DB3::SCALAR_SIZE);
  int failures = 0;
  // bytes
  for (int i = 0; i < DB3::SCALAR_SIZE; i++) {
    // bits
    for (int j = 0; j < 8; j++) {
      std::string backup_id("\0BACKUP890123456", 16);
      backup_id[0] += i * 8 + j;
      client::Log3 log;
      log.set_backup_id(backup_id);
      auto b = log.mutable_req()->mutable_create();
      b->set_max_tries(3);
      auto b2 = blinded_element;
      b2[i] ^= 1 << j;
      b->set_blinded_element(b2);
      log.set_create_privkey(util::ByteArrayToString(priv));
      auto resp = dynamic_cast<client::Response3*>(db.Run(&ctx, log));
      auto r = resp->create();
      ASSERT_TRUE(r.status() == client::CreateResponse::OK || r.status() == client::CreateResponse::ERROR);
      if (r.status() != client::CreateResponse::OK) {
        failures++;
      }
    }
  }
  // Lots of element encodings are invalid, we expect there to be lots of failures when we bitflip them:
  ASSERT_EQ(failures, 184);
}

}  // namespace svr2::db
