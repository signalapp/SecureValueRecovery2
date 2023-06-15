// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

//TESTDEP gtest
//TESTDEP noise
//TESTDEP noise-c
//TESTDEP noisewrap
//TESTDEP env
//TESTDEP util
//TESTDEP env/test
//TESTDEP env
//TESTDEP context
//TESTDEP metrics
//TESTDEP proto
//TESTDEP protobuf-lite
//TESTDEP libsodium

#include <gtest/gtest.h>
#include <noise/protocol/cipherstate.h>
#include "noise/noise.h"
#include "env/env.h"
#include "util/log.h"
#include "proto/error.pb.h"
#include "util/cpu.h"

namespace svr2::noise {

class CipherStateTest : public ::testing::Test {
 protected:
  static void SetUpTestCase() {
    env::Init(env::SIMULATED);
  }

  void EncryptDecrypt(const std::string& plaintext, std::string* ciphertext_out, int type) {
    std::array<uint8_t, 32> key = {1};
    NoiseCipherState* s1n;
    NoiseCipherState* s2n;
    ASSERT_EQ(NOISE_ERROR_NONE, noise_cipherstate_new_by_id(&s1n, type));
    ASSERT_EQ(NOISE_ERROR_NONE, noise_cipherstate_init_key(s1n, key.data(), key.size()));
    ASSERT_EQ(NOISE_ERROR_NONE, noise_cipherstate_new_by_id(&s2n, type));
    ASSERT_EQ(NOISE_ERROR_NONE, noise_cipherstate_init_key(s2n, key.data(), key.size()));
    noise::CipherState s1 = noise::WrapCipherState(s1n);
    noise::CipherState s2 = noise::WrapCipherState(s2n);
    auto [ciphertext, enc_err] = noise::Encrypt(s1n, plaintext);
    ASSERT_EQ(error::OK, enc_err);
    auto [computed_plaintext, dec_err] = noise::Decrypt(s2n, ciphertext);
    ASSERT_EQ(error::OK, dec_err);
    ASSERT_EQ(plaintext, computed_plaintext);
    ciphertext_out->swap(ciphertext);
  }
};

TEST_F(CipherStateTest, EncryptDecrypt) {
  std::string ciphertext;
  EncryptDecrypt("", &ciphertext, NOISE_CIPHER_CHACHAPOLY);
  ASSERT_EQ(16, ciphertext.size());
  EncryptDecrypt("a", &ciphertext, NOISE_CIPHER_CHACHAPOLY);
  ASSERT_EQ(17, ciphertext.size());

  EncryptDecrypt("this is a test of the emergency broadcast system", &ciphertext, NOISE_CIPHER_CHACHAPOLY);

  std::string s;

  s.resize(65535-16, 'a');
  EncryptDecrypt(s, &ciphertext, NOISE_CIPHER_CHACHAPOLY);
  ASSERT_EQ(ciphertext.size(), 65535);

  s.resize(65535-15, 'a');
  EncryptDecrypt(s, &ciphertext, NOISE_CIPHER_CHACHAPOLY);
  ASSERT_EQ(ciphertext.size(), 65535-15+32);

  s.resize((65535-16)*10, 'a');
  EncryptDecrypt(s, &ciphertext, NOISE_CIPHER_CHACHAPOLY);
  ASSERT_EQ(ciphertext.size(), 65535*10);
}

TEST_F(CipherStateTest, BenchmarkChaChaPoly) {
  std::string plaintext;
  std::string ciphertext;
  plaintext.resize(1 << 20, 'a');
  auto start = util::asm_rdtsc();
  int times = 100;
  for (int i = 0; i < times; i++) {
    EncryptDecrypt(plaintext, &ciphertext, NOISE_CIPHER_CHACHAPOLY);
  }
  LOG(INFO) << "took " << ((util::asm_rdtsc() - start) * 1.0 / (times * plaintext.size())) << " cycles/byte";
}

TEST_F(CipherStateTest, BenchmarkAesGcm) {
  std::string plaintext;
  std::string ciphertext;
  plaintext.resize(1 << 20, 'a');
  auto start = util::asm_rdtsc();
  int times = 100;
  for (int i = 0; i < times; i++) {
    EncryptDecrypt(plaintext, &ciphertext, NOISE_CIPHER_AESGCM);
  }
  LOG(INFO) << "took " << ((util::asm_rdtsc() - start) * 1.0 / (times * plaintext.size())) << " cycles/byte";
}

}  // namespace svr2::noise
