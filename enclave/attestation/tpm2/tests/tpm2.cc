// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

//TESTDEP gtest
//TESTDEP attestation/tpm2
//TESTDEP util
//TESTDEP env
//TESTDEP env/test
//TESTDEP context
//TESTDEP metrics
//TESTDEP proto
//TESTDEP protobuf-lite
//TESTDEP libsodium
//TESTDEP boringssl

#include <gtest/gtest.h>
#include "env/env.h"
#include "util/log.h"
#include "util/hex.h"
#include "attestation/tpm2/tpm2.h"
#include <openssl/pem.h>

namespace svr2::attestation::tpm2 {

class AttestTPM2Test : public ::testing::Test {
 protected:
  static void SetUpTestCase() {
    env::Init(env::SIMULATED);
  }
  void SetUp() {
    auto [report, err1] = util::HexToBytes(
        "ff54434780180022000b90c39c7239c4"
        "5a6bbdd2344abfbd4dc923c88d274664"
        "890bc4ddf7427e51a6e9002011223344"
        "55667788990011223344556677889900"
        "11223344556677889900112200000000"
        "0a3a80e3000000030000000001202003"
        "120012000300000001000b03ffffff00"
        "200692355dd87c9e09e3e5a0323b238d"
        "1cccfbfcfe4a0c72ff34bfa6ee432a54"
        "2b");
    CHECK(err1 == error::OK);
    valid_report = report;
    auto [sig, err2] = util::HexToBytes(
        "0014000b0100846f2fe3c9463e9f6085"
        "1f55be82d1c5bd2d180263ee043ab9aa"
        "353fb024fefd49ea12984b6418fd4bdf"
        "ba1f973f32c5d7a87286d60ed21f5aa8"
        "7ec00f016c07ac704fc5a8ed74a68540"
        "a758214efad68bf3555f362a0afe6d8b"
        "bf47bffef2c7e4a858091cae4cb6bed2"
        "c788a6f3453658be40d4762b38f9e9df"
        "26a9568e9acc2d3d54d14dc0ff5ff527"
        "96af562440bf2770fbd00d1e5dc4eadb"
        "8f0b66c2bff28e8722c5965af2f2ca74"
        "c8f30d761a7f3dfe5f1663b7305808f4"
        "849d5e0d66652310b3f8aeb8145e36dc"
        "e08533d12ccf63f77e22e59e53ed4f82"
        "7446bd66b3611d265ea50103e1cc7332"
        "9a8e03795d1321663aeb421ef34f266c"
        "006c2192bebf");
    CHECK(err2 == error::OK);
    valid_sig = sig;
    auto [pcrs, err3] = util::HexToBytes(
        "428bdf83481b6c700bdf76ce0074e459"
        "0140d8aa4a63dabf244a2f83aea2fe24"
        "a71e3aec461ccee150ef13a48f4fb4cc"
        "8cebea82476a072823eb155ec371ef67"
        "3d458cfe55cc03ea1f443f1562beec8d"
        "f51c75e14a9fcf9a7234a13f198e7969"
        "3d458cfe55cc03ea1f443f1562beec8d"
        "f51c75e14a9fcf9a7234a13f198e7969"
        "767e7b175d0761b00a4c2ef3d8df2ffe"
        "ebd7db935fab8f47702ab420a0eb50aa"
        "1d2b80738e3c3f269ca460b7f29e1aab"
        "b2bf521358bb89d944da94c0a4c31842"
        "f90ea7bfc15f3aa043ea27dea7526fea"
        "85e68ca0ddf3828c9ce9d365043a98d4"
        "32fe42b385b47cb22c906b8a7e4f134e"
        "9f2270818f90e94072d1101ef72f1c00"
        "00000000000000000000000000000000"
        "00000000000000000000000000000000"
        "676fe738b1b1c5889403bf6eb911d80c"
        "7b07fab18dcd63b023beb28a457c7cc2"
        "ed31212a972b8bf8568173953800288a"
        "a6be129df751946cf7f6962a403b64ee"
        "00000000000000000000000000000000"
        "00000000000000000000000000000000"
        "f1a142c53586e7e2223ec74e5f4d1a49"
        "42956b1fd9ac78fafcdf85117aa345da"
        "00000000000000000000000000000000"
        "00000000000000000000000000000000"
        "e3991b7ddd47be7e92726a832d6874c5"
        "349b52b789fa0db8b558c69fea29574e"
        "00000000000000000000000000000000"
        "00000000000000000000000000000000"
        "00000000000000000000000000000000"
        "00000000000000000000000000000000"
        "ffffffffffffffffffffffffffffffff"
        "ffffffffffffffffffffffffffffffff"
        "ffffffffffffffffffffffffffffffff"
        "ffffffffffffffffffffffffffffffff"
        "ffffffffffffffffffffffffffffffff"
        "ffffffffffffffffffffffffffffffff"
        "ffffffffffffffffffffffffffffffff"
        "ffffffffffffffffffffffffffffffff"
        "ffffffffffffffffffffffffffffffff"
        "ffffffffffffffffffffffffffffffff"
        "ffffffffffffffffffffffffffffffff"
        "ffffffffffffffffffffffffffffffff"
        "00000000000000000000000000000000"
        "00000000000000000000000000000000");
    CHECK(err3 == error::OK);
    valid_pcrs = pcrs;
    LOG(INFO) << "PCRs: " << util::ToHex(valid_pcrs);
    bssl::UniquePtr<BIO> cert_bio(BIO_new_mem_buf(R"EOF(
-----BEGIN CERTIFICATE-----
MIID6zCCAtOgAwIBAgIQRZpt4djQQ8uIzpH1vaHjLDANBgkqhkiG9w0BAQsFADAl
MSMwIQYDVQQDExpHbG9iYWwgVmlydHVhbCBUUE0gQ0EgLSAwMTAeFw0yMzEwMTgw
MDAwMDBaFw0yNDEwMTYwMDAwMDBaMDYxNDAyBgNVBAMTKzc5MDA1YWMwZTEyMS5D
b25maWRlbnRpYWxWTS5BenVyZS5NaWNyb3NvZnQwggEiMA0GCSqGSIb3DQEBAQUA
A4IBDwAwggEKAoIBAQCj+qpcAADclXRB7K/ZZIeDuW9GiXX+THZ8jRm2cZEeAH5F
G6oO9bvusEWEL50fM7UiqXfjwIJJZWtERXZuQow5BtmspIZGIbYWh1ZYWP1yy+h+
zUtFevdp/qgShf4kshS8L6NLswwj+t3i/Dvpj4vgrRhxHeWT4wOfB+MEdqYv9hnU
iv4HKB+Luw/SVBAUcAWbcC40aI5NQ8Vw+sXP0gEQvhfplkPcHeePkabZJHysUsRH
khsz5PgA8MMMxVR2tQIGXpm0w3FkCXcD+4uqZM7lAnCE9Hr/k7oq4D8IF8PUhri0
XSiRliQKuQLwHGE/Ta/jmYJjYE2P4ct4eRDUL7ZpAgMBAAGjggEEMIIBADAOBgNV
HQ8BAf8EBAMCB4AwGAYDVR0gBBEwDzANBgsrBgEEAYI3bIFIATAcBgNVHSUEFTAT
BgorBgEEAYI3CgMMBgVngQUIAzAdBgNVHQ4EFgQUIPitRC9jY+0ZAKPz1m3+w7ve
pyIwGgYKKwYBBAGCNw0CAwQMFgo2LjIuOTIwMC4yMFoGCSsGAQQBgjcVFARNMEsC
AQUMD01OWjIyMTA4MDUwMTAwOQwaV09SS0dST1VQXE1OWjIyMTA4MDUwMTAwOSQM
GVZ0cG1NYW5hZ2VtZW50U2VydmljZS5leGUwHwYDVR0jBBgwFoAU//bO56jBSGko
y4pL8tiBgbVtgIEwDQYJKoZIhvcNAQELBQADggEBAIpV7zdG8vlFcomFvU9rZvRl
rFiuMrFjxHdc3dSO/TRNRup+HEMEVCSAFz/VvVWDnICgSDL7xJgHfzupV49fYpSL
QueeRhh87ivdd2/Djpi+UjHbdoi5z9Yu2RFJSB4rB38tB9D/QNOQQfeqf3KZlmNe
1zHvjVbaY3OkvBcntqsNfsxlunZeDnwawKIT5MEAfoABHB8n2MZxkS7iDoNiYGWV
/vpDzENlhbbHv/9B91ynT+PAaCWCqDqsQrjZZdEd9+RX6rcmQA42+MPwWbB6DZq1
FaPXEzSg3JzkaZdUy0iCC0bPgrN5CUoSqhSILrTRjyd7Vh1TNCoNmpZxNkIB3R0=
-----END CERTIFICATE-----
)EOF", -1));
    CHECK(cert_bio.get() != nullptr);
    valid_cert.reset(PEM_read_bio_X509(cert_bio.get(), nullptr, nullptr, nullptr));
    CHECK(valid_cert.get() != nullptr);
  }

  std::string valid_report;
  std::string valid_sig;
  std::string valid_pcrs;
  bssl::UniquePtr<X509> valid_cert;
};

TEST_F(AttestTPM2Test, ParseValidReport) {
  auto [r, err] = Report::FromString(valid_report);
  ASSERT_EQ(err, error::OK);
  EXPECT_EQ(r.firmware_version(), 0x2020031200120003ULL);
  EXPECT_EQ(util::ToHex(r.key_hash()), "90c39c7239c45a6bbdd2344abfbd4dc923c88d274664890bc4ddf7427e51a6e9");
  EXPECT_EQ(util::ToHex(r.nonce()), "1122334455667788990011223344556677889900112233445566778899001122");
  EXPECT_EQ(util::ToHex(r.pcr_digest()), "0692355dd87c9e09e3e5a0323b238d1cccfbfcfe4a0c72ff34bfa6ee432a542b");
}

TEST_F(AttestTPM2Test, ParseShortReport) {
  auto [r, err] = Report::FromString(valid_report.substr(0, valid_report.size() - 1));
  ASSERT_EQ(err, error::AttestationTPM2_ParseReport);
}

TEST_F(AttestTPM2Test, ParseLongReport) {
  auto [r, err] = Report::FromString(valid_report + "a");
  ASSERT_EQ(err, error::AttestationTPM2_ParseReport);
}

TEST_F(AttestTPM2Test, ParsePCRs) {
  PCRs pcrs;
  EXPECT_EQ(error::AttestationTPM2_ParsePCRs, PCRsFromString(std::string(32*24-1, 'a'), &pcrs));
  EXPECT_EQ(error::AttestationTPM2_ParsePCRs, PCRsFromString(std::string(32*24+1, 'a'), &pcrs));

  std::string valid(32*24, 'a');
  for (size_t i = 0; i < 24; i++) {
    valid[i*32] = i;
  }
  EXPECT_EQ(error::OK, PCRsFromString(valid, &pcrs));
  for (size_t i = 0; i < 24; i++) {
    EXPECT_EQ(pcrs[i][0], i);
    for (size_t j = 1; j < 32; j++) {
      EXPECT_EQ(pcrs[i][j], 'a');
    }
  }
}

TEST_F(AttestTPM2Test, ParseSig) {
  auto [s, err] = Signature::FromString(valid_sig);
  ASSERT_EQ(err, error::OK);
}

TEST_F(AttestTPM2Test, VerifySig) {
  auto [r, err1] = Report::FromString(valid_report);
  ASSERT_EQ(error::OK, err1);
  auto [s, err2] = Signature::FromString(valid_sig);
  ASSERT_EQ(error::OK, err2);
  ASSERT_EQ(error::OK, s.VerifyReport(r, valid_cert.get()));
}

TEST_F(AttestTPM2Test, VerifyPCRs) {
  auto [r, err1] = Report::FromString(valid_report);
  ASSERT_EQ(error::OK, err1);
  PCRs pcrs;
  ASSERT_EQ(error::OK, PCRsFromString(valid_pcrs, &pcrs));
  ASSERT_EQ(error::OK, r.VerifyPCRs(pcrs));
  pcrs[3][7] = '\xff';
  ASSERT_EQ(error::AttestationTPM2_PCRVerify, r.VerifyPCRs(pcrs));
}

}  // namespace svr2::attestation::sev
