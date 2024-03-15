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

TEST_F(AttestTPM2Test, VerifyGCP) {
  // These values taken from host/cmd/get_gcp_akcert on a GCP confidential VM
  auto [report_str, err1] = util::HexToBytes(
      "ff54434780180022000b36f9b6516c7519faa1c86b87c1abf4f05506f7765d24"
      "ca5b9e0a0397656509f80020aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      "aaaaaaaaaaaaaaaaaaaaaaaa0000000018fc100f0000000f0000000001201605"
      "110016280000000001000b03ffffff0020cc7b6704c6d383c91eb05f3e2743b7"
      "dbce85c97aca505dfa3461c2e18d8e54f7");
  ASSERT_EQ(err1, error::OK);
  auto [sig_str, err2] = util::HexToBytes(
      "0014000b01008050c6e2d9577f1c5239d5caad5e44c4cdfd3286405da97cd877"
      "5bb4b18aa8490596e2d2f183546f72d2b14e8b8f2263f0e9f00922af83443789"
      "b09b9d074740ca62fe71eddf6392450a9583f95d6fa0db9f6472f813e31b4f20"
      "9b83a8dc93af578ad63019345f22ae902f3a8ad7d5751dcb16ce9bd7fd96514b"
      "2b677b34175d6b8404385ff5b8b7a15576dab6489eb5a03369c2bd1c80b259cb"
      "292d4079e331af22f78f544341c0276331a1dcf5b315a1d8cdffadb9422b1e83"
      "7c8737549d31b618d5e042790f723d3ab6995fab42749f732f76a0a5a68c41f3"
      "f85352f06fe713fdbd2f2bba9bd552f02266fbd34e522c0dd112b4b9245eb049"
      "e50de45f873e");
  ASSERT_EQ(err2, error::OK);
  auto [pcr_str, err3] = util::HexToBytes(
      "50597a27846e91d025eef597abbc89f72bff9af849094db97b0684d8bc4c515e"
      "7f2e3afd9d4fbd191b8d23b50e6f8a0955a149fb7b7d7fa8220422af93bb9932"
      "3d458cfe55cc03ea1f443f1562beec8df51c75e14a9fcf9a7234a13f198e7969"
      "3d458cfe55cc03ea1f443f1562beec8df51c75e14a9fcf9a7234a13f198e7969"
      "6f179a3a1cd181fa2ce43e3490a8a6595d230a71c7293d0283a88232d19b0e9a"
      "3571540f29ebabef4ca257b6a4446e93729441b19156c8f6e846a051e97ed00e"
      "3d458cfe55cc03ea1f443f1562beec8df51c75e14a9fcf9a7234a13f198e7969"
      "a32d83c766792cadc6d2e7e117729d1da62488210b75fb88d2a319a8c56978da"
      "ba5fb657c8ec92ddbb327933c3d12ba24e6d138f53fe72cd634e761ae3aa0afb"
      "d16e4a62378c43889d90d7f718e584a99123860b181b387f2d29daba3ea93c85"
      "b59b1898b07c43af648efff38b2e4cb0e8e8b07331d9ac712cd7bfe647cf2b91"
      "0000000000000000000000000000000000000000000000000000000000000000"
      "0000000000000000000000000000000000000000000000000000000000000000"
      "0000000000000000000000000000000000000000000000000000000000000000"
      "6eb05e8a8a6272a8e4b925a67c650daa13c12b1a80cc797d40fd345e29660161"
      "0000000000000000000000000000000000000000000000000000000000000000"
      "0000000000000000000000000000000000000000000000000000000000000000"
      "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
      "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
      "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
      "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
      "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
      "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
      "0000000000000000000000000000000000000000000000000000000000000000");
  ASSERT_EQ(err3, error::OK);
  auto [report, err4] = Report::FromString(report_str);
  ASSERT_EQ(err4, error::OK);
  auto [sig, err5] = Signature::FromString(sig_str);
  ASSERT_EQ(err5, error::OK);
  PCRs pcrs;
  ASSERT_EQ(error::OK, PCRsFromString(pcr_str, &pcrs));
  ASSERT_EQ(error::OK, report.VerifyPCRs(pcrs));
  auto [cert_str, err6] = util::HexToBytes(
      "308205fc308203e4a003020102021360d00cfafb665172ce28fa89eec2a89e39"
      "fc6d300d06092a864886f70d01010b0500308186310b30090603550406130255"
      "53311330110603550408130a43616c69666f726e696131163014060355040713"
      "0d4d6f756e7461696e205669657731133011060355040a130a476f6f676c6520"
      "4c4c4331153013060355040b130c476f6f676c6520436c6f7564311e301c0603"
      "5504031315454b2f414b20434120496e7465726d6564696174653020170d3234"
      "303232343033343730305a180f32303534303231363033343635395a30723116"
      "30140603550407130d75732d63656e7472616c312d61311e301c060355040a13"
      "15476f6f676c6520436f6d7075746520456e67696e65311b3019060355040b13"
      "127369676e616c2d7365762d74657374696e67311b3019060355040313123739"
      "3831303134343735343138333939333730820122300d06092a864886f70d0101"
      "0105000382010f003082010a0282010100a68227ddad3e02e6abb81ffe2c851b"
      "1b6979f6f59fc72df43e889ed233e542b5d3d95c81cd1842541cc79bf0b041c8"
      "83df06cbb003d3f28dd03d942e3c198af0089f6a07da3f1d3fab105b04757281"
      "4a19e4b50f40b457ce98940dfbf4fe7e904f3c156370e781a4e5a33c522e1beb"
      "ae4aeef87c042eed21b031787aed5c7190407b96c23907269a43a38ce96d7f4e"
      "691781232c0e3c37df24b973950642300268abdc7f6522cd7c3880f6cb29a422"
      "178efed8630907906fa0f606beb06985fe7310ff53f63a8dabb431951ddb7a32"
      "6e921f49452d8071558e552cfa06cefdb7e87de09e153d7138694264f3d43b9f"
      "ee698d629e415481821027c766429f78390203010001a38201723082016e300e"
      "0603551d0f0101ff040403020780300c0603551d130101ff04023000301d0603"
      "551d0e041604141d1de200475cdc32eb9d96ec48be0b28ecc86a27301f060355"
      "1d23041830168014e966735467661befdd65bfe5e85ce3910b9b055230818d06"
      "082b06010505070101048180307e307c06082b06010505073002867068747470"
      "3a2f2f7072697661746563612d636f6e74656e742d36333362656239342d3030"
      "30302d323563312d613964372d3030316131313462613665382e73746f726167"
      "652e676f6f676c65617069732e636f6d2f633539613232353839616234336135"
      "37653361342f63612e637274307e060a2b06010401d6790201150470306e0c0d"
      "75732d63656e7472616c312d610205370f8b6f260c127369676e616c2d736576"
      "2d74657374696e6702080b136d09bb74d8410c166772616d2d656b636572742d"
      "31373038373436343131a020301ea003020100a1030101ffa2030101ffa30301"
      "0100a403010100a503010100300d06092a864886f70d01010b05000382020100"
      "5ec08bba24f33a561103a11946f61050b3cc584d8c8e7a9fed5776d0d364cac9"
      "38baea2f53a96ce24cb16442b17ed0652b63546ce11783dc4ea3551685d16f47"
      "f519db48d90a09c914bc1bf62b84f7fceab9e1c035e03fc5d0bf0d394a3ba9b9"
      "ac829465c34d32680a59e1fc2b977b79eccc252cb783946fa25c6ffefd9e4b73"
      "8ed854aa14c82bd2b9e03ed4e811b5cd8b0753fd81d47cc94d2e2c0dbd306e82"
      "a3e644b828fa0496a7306073a71fdf28e134b5449de69806fdbce1d89a538f32"
      "ddae3197f638b4d5096cf4060b45044c24a7a259f38dd4eb7be7feb9a886bc84"
      "c7758c9a7ff2f66a9afe6066ae619a522851f03174b8e70d2ed5bd972b58d235"
      "ca740b7d84dc580fb42b16fbe7493dfaf828c5d82d607a6c9e6d71651909c932"
      "c9f46b32c8af70a65855d6f94630cdb90647d01bb2b769801724c9f047630557"
      "76bc825f7ec8b5079086dd9a825e8fade447c13e20769fa68c450635a286d4c5"
      "ad470b2ee6ea4af0319e6b5baa3f4532d68f2e4c82035f206503f78c1e6f3639"
      "3a0469a9f0654297ffa9a8616b7b0d7f4cf8ed9269a0de94eff9a1c661ec11d0"
      "bc0bd6bc5f1ae57cfb537da2bbaa953d43a812777acfb74aa2f455c386ce4f67"
      "b6b025e8e56581d1200c50460ffd927b6d94fb60c1442c52d1be73689ceef60d"
      "850b330870d3c3c777b8b5505aac48c8161251da25b6fab1372d1b9f46442e16");
  ASSERT_EQ(error::OK, err6);
  auto cert_start = reinterpret_cast<const uint8_t*>(cert_str.data());
  bssl::UniquePtr<X509> cert(d2i_X509(nullptr, &cert_start, cert_str.size()));
  ASSERT_TRUE(cert);
  ASSERT_EQ(error::OK, sig.VerifyReport(report, cert.get()));
}

}  // namespace svr2::attestation::sev
