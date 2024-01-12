// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

#include <string.h>
#include <array>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/base.h>
#include <openssl/ecdsa.h>

#include "attestation/sev/sev.h"
#include "util/log.h"
#include "util/hex.h"
#include "util/bytes.h"
#include "util/constant.h"
#include "proto/error.pb.h"
#include "metrics/metrics.h"
#include "sevtypes/sevtypes.h"
#include "minimums/minimums.h"

namespace svr2::attestation::sev {
namespace {

// From https://www.amd.com/system/files/TechDocs/56421-guest-hypervisor-communication-block-standardization.pdf section 4.1.8.1
struct cert_table {
  struct {
    uint8_t guid[16];
    uint32_t offset;
    uint32_t length;
  } cert_table_entry[0];
};

typedef std::array<uint8_t, 16> UUID;
typedef std::vector<uint8_t> Certificate;

// From https://www.amd.com/system/files/TechDocs/56421-guest-hypervisor-communication-block-standardization.pdf section 4.1.8.1
constexpr UUID UUID_VCEK = {0x63, 0xda, 0x75, 0x8d, 0xe6, 0x64, 0x45, 0x64, 0xad, 0xc5, 0xf4, 0xb9, 0x3b, 0xe8, 0xac, 0xcd};
constexpr UUID UUID_ASK  = {0x4a, 0xb7, 0xb3, 0x79, 0xbb, 0xac, 0x4f, 0xe4, 0xa0, 0x2f, 0x05, 0xae, 0xf3, 0x27, 0xc7, 0x82};
constexpr UUID UUID_ARK  = {0xc0, 0xb4, 0x06, 0xa4, 0xa8, 0x03, 0x49, 0x52, 0x97, 0x43, 0x3f, 0xb6, 0x01, 0x4c, 0xd0, 0xae};
constexpr UUID UUID_VLEK = {0xa8, 0x07, 0x4b, 0xc2, 0xa2, 0x5a, 0x48, 0x3e, 0xaa, 0xe6, 0x39, 0xc0, 0x45, 0xa0, 0xb8, 0xa1};
constexpr UUID UUID_CRL  = {0x92, 0xf8, 0x1b, 0xc3, 0x58, 0x11, 0x4d, 0x3d, 0x97, 0xff, 0xd1, 0x9f, 0x88, 0xdc, 0x67, 0xea};

std::pair<const attestation_report*, error::Error> ReportFromUnverifiedEvidence(const std::string& evidence) {
  if (evidence.size() < sizeof(attestation_report)) {
    return std::make_pair(nullptr, COUNTED_ERROR(AttestationSEV_EvidenceTooSmallForReport));
  }
  auto report = reinterpret_cast<const attestation_report*>(evidence.data());
  return std::make_pair(report, error::OK);
}

// AMD Root Key (ARK) for Milan processors.
const char* ARK_MILAN_PEM = R"EOF(
-----BEGIN CERTIFICATE-----
MIIGYzCCBBKgAwIBAgIDAQAAMEYGCSqGSIb3DQEBCjA5oA8wDQYJYIZIAWUDBAIC
BQChHDAaBgkqhkiG9w0BAQgwDQYJYIZIAWUDBAICBQCiAwIBMKMDAgEBMHsxFDAS
BgNVBAsMC0VuZ2luZWVyaW5nMQswCQYDVQQGEwJVUzEUMBIGA1UEBwwLU2FudGEg
Q2xhcmExCzAJBgNVBAgMAkNBMR8wHQYDVQQKDBZBZHZhbmNlZCBNaWNybyBEZXZp
Y2VzMRIwEAYDVQQDDAlBUkstTWlsYW4wHhcNMjAxMDIyMTcyMzA1WhcNNDUxMDIy
MTcyMzA1WjB7MRQwEgYDVQQLDAtFbmdpbmVlcmluZzELMAkGA1UEBhMCVVMxFDAS
BgNVBAcMC1NhbnRhIENsYXJhMQswCQYDVQQIDAJDQTEfMB0GA1UECgwWQWR2YW5j
ZWQgTWljcm8gRGV2aWNlczESMBAGA1UEAwwJQVJLLU1pbGFuMIICIjANBgkqhkiG
9w0BAQEFAAOCAg8AMIICCgKCAgEA0Ld52RJOdeiJlqK2JdsVmD7FktuotWwX1fNg
W41XY9Xz1HEhSUmhLz9Cu9DHRlvgJSNxbeYYsnJfvyjx1MfU0V5tkKiU1EesNFta
1kTA0szNisdYc9isqk7mXT5+KfGRbfc4V/9zRIcE8jlHN61S1ju8X93+6dxDUrG2
SzxqJ4BhqyYmUDruPXJSX4vUc01P7j98MpqOS95rORdGHeI52Naz5m2B+O+vjsC0
60d37jY9LFeuOP4Meri8qgfi2S5kKqg/aF6aPtuAZQVR7u3KFYXP59XmJgtcog05
gmI0T/OitLhuzVvpZcLph0odh/1IPXqx3+MnjD97A7fXpqGd/y8KxX7jksTEzAOg
bKAeam3lm+3yKIcTYMlsRMXPcjNbIvmsBykD//xSniusuHBkgnlENEWx1UcbQQrs
+gVDkuVPhsnzIRNgYvM48Y+7LGiJYnrmE8xcrexekBxrva2V9TJQqnN3Q53kt5vi
Qi3+gCfmkwC0F0tirIZbLkXPrPwzZ0M9eNxhIySb2npJfgnqz55I0u33wh4r0ZNQ
eTGfw03MBUtyuzGesGkcw+loqMaq1qR4tjGbPYxCvpCq7+OgpCCoMNit2uLo9M18
fHz10lOMT8nWAUvRZFzteXCm+7PHdYPlmQwUw3LvenJ/ILXoQPHfbkH0CyPfhl1j
WhJFZasCAwEAAaN+MHwwDgYDVR0PAQH/BAQDAgEGMB0GA1UdDgQWBBSFrBrRQ/fI
rFXUxR1BSKvVeErUUzAPBgNVHRMBAf8EBTADAQH/MDoGA1UdHwQzMDEwL6AtoCuG
KWh0dHBzOi8va2RzaW50Zi5hbWQuY29tL3ZjZWsvdjEvTWlsYW4vY3JsMEYGCSqG
SIb3DQEBCjA5oA8wDQYJYIZIAWUDBAICBQChHDAaBgkqhkiG9w0BAQgwDQYJYIZI
AWUDBAICBQCiAwIBMKMDAgEBA4ICAQC6m0kDp6zv4Ojfgy+zleehsx6ol0ocgVel
ETobpx+EuCsqVFRPK1jZ1sp/lyd9+0fQ0r66n7kagRk4Ca39g66WGTJMeJdqYriw
STjjDCKVPSesWXYPVAyDhmP5n2v+BYipZWhpvqpaiO+EGK5IBP+578QeW/sSokrK
dHaLAxG2LhZxj9aF73fqC7OAJZ5aPonw4RE299FVarh1Tx2eT3wSgkDgutCTB1Yq
zT5DuwvAe+co2CIVIzMDamYuSFjPN0BCgojl7V+bTou7dMsqIu/TW/rPCX9/EUcp
KGKqPQ3P+N9r1hjEFY1plBg93t53OOo49GNI+V1zvXPLI6xIFVsh+mto2RtgEX/e
pmMKTNN6psW88qg7c1hTWtN6MbRuQ0vm+O+/2tKBF2h8THb94OvvHHoFDpbCELlq
HnIYhxy0YKXGyaW1NjfULxrrmxVW4wcn5E8GddmvNa6yYm8scJagEi13mhGu4Jqh
3QU3sf8iUSUr09xQDwHtOQUVIqx4maBZPBtSMf+qUDtjXSSq8lfWcd8bLr9mdsUn
JZJ0+tuPMKmBnSH860llKk+VpVQsgqbzDIvOLvD6W1Umq25boxCYJ+TuBoa4s+HH
CViAvgT9kf/rBq1d+ivj6skkHxuzcxbk1xv6ZGxrteJxVH7KlX7YRdZ6eARKwLe4
AFZEAwoKCQ==
-----END CERTIFICATE-----
)EOF";
// AMD Root Key (ARK) for Genoa processors.
const char* ARK_GENOA_PEM = R"EOF(
-----BEGIN CERTIFICATE-----
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
/wMz1R1BHg==
-----END CERTIFICATE-----
)EOF";

bssl::UniquePtr<STACK_OF(X509)> RootsOfTrust() {
  bssl::UniquePtr<STACK_OF(X509)> root_stack(sk_X509_new_null());
  CHECK(root_stack.get() != nullptr);
  for (auto ark : {ARK_MILAN_PEM, ARK_GENOA_PEM}) {
    bssl::UniquePtr<BIO> ark_milan_bio(BIO_new_mem_buf(ark, -1));
    CHECK(ark_milan_bio.get() != nullptr);
    bssl::UniquePtr<X509> ark_milan_x509(PEM_read_bio_X509(ark_milan_bio.get(), nullptr, nullptr, nullptr));
    CHECK(ark_milan_x509.get() != nullptr);
    CHECK(0 != sk_X509_push(root_stack.get(), ark_milan_x509.get()));
    ark_milan_x509.release();  // owned by root_stack
  }
  return root_stack;
}

const bssl::UniquePtr<STACK_OF(X509)> roots_of_trust = RootsOfTrust();

const uint32_t FLAGS_KEY_MASK = (0x04 | 0x08);
const uint32_t FLAGS_KEY_VCEK = 0x00;

error::Error ValidateReport(const attestation_report& report) {
  if (report.policy & POLICY_MIGRATE_MA_MASK) {
    return COUNTED_ERROR(AttestationSEV_MigrationAllowed);
  } else if (report.policy & POLICY_DEBUG_MASK) {
    return COUNTED_ERROR(AttestationSEV_DebugEnabled);
  } else if (
      report.version != 2 ||
      report.signature_algo != SIG_ALGO_ECDSA_P384_SHA384 ||
      (report.flags & FLAGS_KEY_MASK) != FLAGS_KEY_VCEK) {
    return COUNTED_ERROR(AttestationSEV_UnsupportedReport);
  }
  return error::OK;
}

error::Error AllowRemote(const attestation_report& local, const attestation_report& remote) {
  RETURN_IF_ERROR(ValidateReport(remote));
  if (!util::ConstantTimeEqualsBytes(local.measurement, remote.measurement, sizeof(local.measurement))) {
    return COUNTED_ERROR(AttestationSEV_MeasurementMismatch);
  } else if (!util::ConstantTimeEqualsBytes(local.host_data, remote.host_data, sizeof(local.host_data))) {
    return COUNTED_ERROR(AttestationSEV_HostDataMismatch);
  }
  return error::OK;
}

}  // namespace

minimums::MinimumValues MinimumsFromReport(const attestation_report& report) {
  minimums::MinimumValues v;
  auto map = *v.mutable_val();
  map["sev_platform_version_boot_loader"] = minimums::Minimums::U64(report.platform_version.boot_loader);
  map["sev_platform_version_tee"] = minimums::Minimums::U64(report.platform_version.tee);
  map["sev_platform_version_snp"] = minimums::Minimums::U64(report.platform_version.snp);
  map["sev_platform_version_microcode"] = minimums::Minimums::U64(report.platform_version.microcode);
  map["sev_reported_tcb_boot_loader"] = minimums::Minimums::U64(report.reported_tcb.boot_loader);
  map["sev_reported_tcb_tee"] = minimums::Minimums::U64(report.reported_tcb.tee);
  map["sev_reported_tcb_snp"] = minimums::Minimums::U64(report.reported_tcb.snp);
  map["sev_reported_tcb_microcode"] = minimums::Minimums::U64(report.reported_tcb.microcode);
  return v;
}

bool EndorsementsFromFile(const char* filename, SevSnpEndorsements* endorsements) {
  int f = open(filename, O_RDONLY | O_CLOEXEC);
  if (f < 0) {
    LOG(ERROR) << "Opening " << filename << ": " << strerror(errno);
    return false;
  }
  std::string in;
  std::string buf;
  bool out = false;
  while (true) {
    buf.resize(1024);
    ssize_t n = read(f, buf.data(), buf.size());
    if (n < 0) {
      LOG(ERROR) << "Reading " << filename << ": " << strerror(errno);
      break;
    }
    if (n == 0) {
      if (endorsements->ParseFromString(in)) {
        LOG(INFO) << "Successfully read and parsed " << filename;
        out = true;
      } else {
        LOG(ERROR) << "Failed to parse " << filename;
      }
      break;
    }
    buf.resize(n);
    in.append(buf);
  }
  close(f);
  return out;
}

error::Error CertificatesToEndorsements(const uint8_t* certs, uint32_t certs_size, SevSnpEndorsements* endorsements) {
  auto t = reinterpret_cast<const cert_table*>(certs);

  const uint32_t entry_size = sizeof(t->cert_table_entry[0]);
  uint8_t terminator[entry_size] = {0};

  for (size_t i = 0; ; i++) {
    uint32_t entry_end = entry_size * (i+1);
    if (entry_end > certs_size) {
      return COUNTED_ERROR(AttestationSEV_CertsTableEntryTooLarge);
    }
    auto entry = t->cert_table_entry[i];
    if (memcmp(terminator, &entry, sizeof(entry)) == 0) {
      LOG(DEBUG) << "Certificates pulled from SNP_GET_EXT_REPORT: " << i;
      break;
    }
    uint32_t cert_end = entry.offset + entry.length;
    if (entry.offset > certs_size || cert_end > certs_size) {
      return COUNTED_ERROR(AttestationSEV_CertsTableCertTooLarge);
    }
    UUID uuid;
    memcpy(uuid.data(), entry.guid, 16);
    Certificate cert;
    cert.resize(entry.length);
    memcpy(cert.data(), certs + entry.offset, entry.length);
    LOG(INFO) << "Certificate: " << util::ToHex(uuid);
    switch (uuid[0]) {
      case UUID_VCEK[0]:
        if (uuid == UUID_VCEK) { endorsements->set_vcek(util::ByteVectorToString(cert)); }
        break;
      case UUID_ASK[0]:
        if (uuid == UUID_ASK) { endorsements->set_ask(util::ByteVectorToString(cert)); }
        break;
      case UUID_ARK[0]:
        if (uuid == UUID_ARK) { endorsements->set_ark(util::ByteVectorToString(cert)); }
        break;
      case UUID_VLEK[0]:
        if (uuid == UUID_VLEK) { endorsements->set_vlek(util::ByteVectorToString(cert)); }
        break;
      case UUID_CRL[0]:
        if (uuid == UUID_CRL) { endorsements->set_crl(util::ByteVectorToString(cert)); }
        break;
      default:
        LOG(WARNING) << "Unknown UUID " << util::ToHex(uuid) << ", ignoring";
        break;
    }
  }

  return error::OK;
}

std::pair<attestation_report, error::Error> ReportFromUnverifiedAttestation(const e2e::Attestation& attestation) {
  auto [report, err] = ReportFromUnverifiedEvidence(attestation.evidence());
  attestation_report out;
  if (err != error::OK) {
    return std::make_pair(out, err);
  }
  memcpy(&out, report, sizeof(out));
  return std::make_pair(out, ValidateReport(out));
}

std::pair<attestation::AttestationData, error::Error> DataFromVerifiedAttestation(const attestation_report& local, const e2e::Attestation& attestation, util::UnixSecs now) {
  auto [report, err] = ReportFromUnverifiedEvidence(attestation.evidence());
  attestation::AttestationData out;
  if (err != error::OK) {
    return std::make_pair(out, err);
  }
  if (auto err = AllowRemote(local, *report); err != error::OK) {
    return std::make_pair(out, err);
  }
  SevSnpEndorsements endorsements;
  if (!endorsements.ParseFromString(attestation.endorsements())) {
    return std::make_pair(out, COUNTED_ERROR(AttestationSEV_ParseEndorsements));
  }

  // Get VCEK and ASK from endorsements.
  auto vcek_start = reinterpret_cast<const uint8_t*>(endorsements.vcek().data());
  auto ask_start = reinterpret_cast<const uint8_t*>(endorsements.ask().data());
  bssl::UniquePtr<X509> vcek(d2i_X509(nullptr, &vcek_start, endorsements.vcek().size()));
  bssl::UniquePtr<X509> ask(d2i_X509(nullptr, &ask_start, endorsements.ask().size()));
  if (!vcek || !ask) {
    return std::make_pair(out, COUNTED_ERROR(AttestationSEV_EndorsementBadCert));
  }
  bssl::UniquePtr<EVP_PKEY> vcek_pub(X509_get_pubkey(vcek.get()));
  if (!vcek_pub) {
    return std::make_pair(out, COUNTED_ERROR(AttestationSEV_CryptoAllocate));
  }

  // Verify VCEK.
  bssl::UniquePtr<X509_STORE_CTX> ctx(X509_STORE_CTX_new());
  bssl::UniquePtr<X509_STORE> store(X509_STORE_new());
  bssl::UniquePtr<STACK_OF(X509)> intermediates(sk_X509_new_null());
  if (!ctx || !store || !intermediates ||
      0 == sk_X509_push(intermediates.get(), ask.get())) {
    return std::make_pair(out, COUNTED_ERROR(AttestationSEV_CryptoAllocate));
  }
  ask.release();  // now owned by [intermediates]
  if (!X509_STORE_CTX_init(ctx.get(), store.get(), vcek.get(), intermediates.get())) {
    return std::make_pair(out, COUNTED_ERROR(AttestationSEV_CryptoStoreInit));
  }
  // X509_STORE_CTX_set0_trusted_stack does not take ownership of roots_of_trust stack.
  X509_STORE_CTX_set0_trusted_stack(ctx.get(), roots_of_trust.get());
  X509_VERIFY_PARAM *param = X509_STORE_CTX_get0_param(ctx.get());
  X509_VERIFY_PARAM_set_time_posix(param, now);
  if (1 != X509_verify_cert(ctx.get())) {
    auto err = X509_STORE_CTX_get_error(ctx.get());
    LOG(ERROR) << "SEV attestation verify_cert err=" << err << ": " << X509_verify_cert_error_string(err);
    return std::make_pair(out, COUNTED_ERROR(AttestationSEV_CertificateChainVerify));
  }

  // Extract ECDSA signature from report.
  bssl::UniquePtr<ECDSA_SIG> sig(ECDSA_SIG_new());
  bssl::UniquePtr<BIGNUM> r(BN_le2bn(report->signature.r, 48, nullptr));
  bssl::UniquePtr<BIGNUM> s(BN_le2bn(report->signature.s, 48, nullptr));
  if (!sig || !r || !s) {
    return std::make_pair(out, COUNTED_ERROR(AttestationSEV_CryptoAllocate));
  }
  if (1 != ECDSA_SIG_set0(sig.get(), r.get(), s.get())) {
    return std::make_pair(out, COUNTED_ERROR(AttestationSEV_CryptoAllocate));
  }
  r.release();  // now owned by sig
  s.release();  // now owned by sig

  // Compute message digest.
  bssl::UniquePtr<EVP_MD_CTX> md_ctx(EVP_MD_CTX_new());
  if (!md_ctx) {
    return std::make_pair(out, COUNTED_ERROR(AttestationSEV_CryptoAllocate));
  } 
  EVP_MD_CTX_init(md_ctx.get());
  uint8_t md[48];
  unsigned int md_size = sizeof(md);
  auto verify_from = reinterpret_cast<const uint8_t*>(report);
  auto verify_to = reinterpret_cast<const uint8_t*>(&report->signature);
  if (1 != EVP_DigestInit(md_ctx.get(), EVP_sha384()) ||
      1 != EVP_DigestUpdate(md_ctx.get(), verify_from, verify_to - verify_from) ||
      1 != EVP_DigestFinal(md_ctx.get(), md, &md_size) ||
      md_size != sizeof(md)) {
    return std::make_pair(out, COUNTED_ERROR(AttestationSEV_CryptoMessageDigest));
  }

  // Use VCEK to verify signature.
  EC_KEY* ec_key_not_owned = EVP_PKEY_get0_EC_KEY(vcek_pub.get());
  if (1 != ECDSA_do_verify(md, md_size, sig.get(), ec_key_not_owned)) {
    LOG(ERROR) << "SEV attestation signature verification failed";
    return std::make_pair(out, COUNTED_ERROR(AttestationSEV_SignatureVerify));
  }

  out.mutable_public_key()->resize(sizeof(env::PublicKey));
  memcpy(out.mutable_public_key()->data(), report->report_data, sizeof(env::PublicKey));
  minimums::MinimumValues mins = minimums::Minimums::CombineValues(out.minimum_values(), MinimumsFromReport(*report));
  *out.mutable_minimum_values() = std::move(mins);
  return std::make_pair(out, error::OK);
}

}  // namespace svr2::attestation::sev
