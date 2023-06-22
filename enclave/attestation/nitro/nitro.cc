// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

#include "attestation/nitro/nitro.h"
#include <cbor.h>
#include "util/log.h"
#include "util/macros.h"
#include "metrics/metrics.h"

#define ASSIGN_OR_RETURN(var, val) ASSIGN_OR_RETURN_CTR1(var, val, __COUNTER__)
#define ASSIGN_OR_RETURN_CTR1(var, val, ctr) ASSIGN_OR_RETURN_CTR2(var, val, ctr)
#define ASSIGN_OR_RETURN_CTR2(var, val, ctr) \
  auto [var, __err_##ctr] = (val); \
  if (__err_##ctr != error::OK) { \
    LOG(VERBOSE) << "ASSIGN_OR_RETURN(" << #var << ", " << #val << ") -> " << __err_##ctr; \
    return __err_##ctr; \
  }

namespace svr2::attestation::nitro {

namespace {

std::pair<TextString, error::Error> CborTextString(CborValue* v) {
  TextString out;
  size_t size = 0;
  if (CborTextStringType != cbor_value_get_type(v) ||
      CborNoError != cbor_value_get_string_length(v, &size)) {
    return std::make_pair(std::move(out), COUNTED_ERROR(AttestationNitro_CoseFormat));
  }
  out.resize(size);
  if (CborNoError != cbor_value_copy_text_string(v, out.data(), &size, v) ||
      size != out.size()) {
    return std::make_pair(std::move(out), COUNTED_ERROR(AttestationNitro_CoseFormat));
  }
  return std::make_pair(std::move(out), error::OK);
}

std::pair<ByteString, error::Error> CborByteString(CborValue* v) {
  ByteString out;
  size_t size = 0;
  if (CborNullType == cbor_value_get_type(v)) {
    if (CborNoError != cbor_value_advance(v)) {
      return std::make_pair(std::move(out), COUNTED_ERROR(AttestationNitro_CoseFormat));
    } else {
      return std::make_pair(std::move(out), error::OK);
    }
  }
  if (CborByteStringType != cbor_value_get_type(v) ||
      CborNoError != cbor_value_get_string_length(v, &size)) {
    return std::make_pair(std::move(out), COUNTED_ERROR(AttestationNitro_CoseFormat));
  }
  out.resize(size);
  if (CborNoError != cbor_value_copy_byte_string(v, out.data(), &size, v) ||
      size != out.size()) {
    return std::make_pair(std::move(out), COUNTED_ERROR(AttestationNitro_CoseFormat));
  }
  return std::make_pair(std::move(out), error::OK);
}

std::pair<int64_t, error::Error> CborInt(CborValue* v) {
  int64_t out = 0;
  if (CborIntegerType != cbor_value_get_type(v) ||
      CborNoError != cbor_value_get_int64_checked(v, &out) ||
      CborNoError != cbor_value_advance(v)) {
    return std::make_pair(0, COUNTED_ERROR(AttestationNitro_CoseFormat));
  }
  return std::make_pair(out, error::OK);
}

// From https://aws-nitro-enclaves.amazonaws.com/AWS_NitroEnclaves_Root-G1.zip
// Zip hash (SHA256): 8cf60e2b2efca96c6a9e71e851d00c1b6991cc09eadbe64a6a1d1b1eb9faff7c
const char* ROOT_CERTIFICATE_PEM = R"EOF(
-----BEGIN CERTIFICATE-----
MIICETCCAZagAwIBAgIRAPkxdWgbkK/hHUbMtOTn+FYwCgYIKoZIzj0EAwMwSTEL
MAkGA1UEBhMCVVMxDzANBgNVBAoMBkFtYXpvbjEMMAoGA1UECwwDQVdTMRswGQYD
VQQDDBJhd3Mubml0cm8tZW5jbGF2ZXMwHhcNMTkxMDI4MTMyODA1WhcNNDkxMDI4
MTQyODA1WjBJMQswCQYDVQQGEwJVUzEPMA0GA1UECgwGQW1hem9uMQwwCgYDVQQL
DANBV1MxGzAZBgNVBAMMEmF3cy5uaXRyby1lbmNsYXZlczB2MBAGByqGSM49AgEG
BSuBBAAiA2IABPwCVOumCMHzaHDimtqQvkY4MpJzbolL//Zy2YlES1BR5TSksfbb
48C8WBoyt7F2Bw7eEtaaP+ohG2bnUs990d0JX28TcPQXCEPZ3BABIeTPYwEoCWZE
h8l5YoQwTcU/9KNCMEAwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUkCW1DdkF
R+eWw5b6cp3PmanfS5YwDgYDVR0PAQH/BAQDAgGGMAoGCCqGSM49BAMDA2kAMGYC
MQCjfy+Rocm9Xue4YnwWmNJVA44fA0P5W2OpYow9OYCVRaEevL8uO1XYru5xtMPW
rfMCMQCi85sWBbJwKKXdS6BptQFuZbT73o/gBh1qUxl/nNr12UO8Yfwr6wPLb+6N
IwLz3/Y=
-----END CERTIFICATE-----
)EOF";

bssl::UniquePtr<STACK_OF(X509)> RootsOfTrust() {
  printf("parsing root cert\n");
  bssl::UniquePtr<BIO> root_bio(BIO_new_mem_buf(ROOT_CERTIFICATE_PEM, -1));
  CHECK(root_bio.get() != nullptr);
  bssl::UniquePtr<X509> root_x509(PEM_read_bio_X509(root_bio.get(), nullptr, nullptr, nullptr));
  CHECK(root_x509.get() != nullptr);
  bssl::UniquePtr<STACK_OF(X509)> root_stack(sk_X509_new_null());
  CHECK(root_stack.get() != nullptr);
  CHECK(0 != sk_X509_push(root_stack.get(), root_x509.get()));
  root_x509.release();  // owned by root_stack
  return root_stack;
}

const char COSE_SIGN1_NAME[] = "Signature1";

const bssl::UniquePtr<STACK_OF(X509)> roots_of_trust = RootsOfTrust();

}  // namespace

void CoseSign1::Clear() {
  protected_header.clear();
  payload.clear();
  signature.clear();
}

error::Error CoseSign1::ParseFromBytes(const uint8_t* in, size_t size) {
  Clear();
  CborParser p;
  CborValue array;
  if (CborNoError != cbor_parser_init(in, size, 0, &p, &array)) {
    return COUNTED_ERROR(AttestationNitro_CborError);
  }
  size_t array_size = 0;
  CborValue elts;
  if (CborArrayType != cbor_value_get_type(&array) ||
      CborNoError != cbor_value_get_array_length(&array, &array_size) ||
      4 != array_size ||
      CborNoError != cbor_value_enter_container(&array, &elts)) {
    return COUNTED_ERROR(AttestationNitro_CoseFormat);
  }
  // Extract all elements.
  ASSIGN_OR_RETURN(pheader_bytes, CborByteString(&elts));
  this->protected_header = pheader_bytes;
  CborValue uheader_map;
  if (CborMapType != cbor_value_get_type(&elts) ||
      CborNoError != cbor_value_enter_container(&elts, &uheader_map) ||
      !cbor_value_at_end(&uheader_map) ||
      CborNoError != cbor_value_leave_container(&elts, &uheader_map)) {
    return COUNTED_ERROR(AttestationNitro_CoseFormat);
  }
  ASSIGN_OR_RETURN(payload, CborByteString(&elts));
  this->payload = payload;
  ASSIGN_OR_RETURN(signature, CborByteString(&elts));
  this->signature = signature;
  if (!cbor_value_at_end(&elts)) {
    return COUNTED_ERROR(AttestationNitro_CborError);
  }
  if (!Valid()) return COUNTED_ERROR(AttestationNitro_CoseFormat);
  return error::OK;
}

bool CoseSign1::Valid() const {
  // Check that protected header is as expected.
  CborParser pheader_p;
  CborValue pheader_v;
  if (CborNoError != cbor_parser_init(protected_header.data(), protected_header.size(), 0, &pheader_p, &pheader_v) ||
      CborMapType != cbor_value_get_type(&pheader_v)) {
    return false;
  }
  CborValue pheader_map;
  if (CborNoError != cbor_value_enter_container(&pheader_v, &pheader_map)) {
    return false;
  }
  // Nitro promises to only have one protected header, which should be the algorithm set
  // to 384.
  ASSIGN_OR_RETURN(key, CborInt(&pheader_map));
  ASSIGN_OR_RETURN(val, CborInt(&pheader_map));
  if (!cbor_value_at_end(&pheader_map)) return false;
  if (key != 1 /* signing algorithm */ || val != -35 /* ecdsa p-384 */) return false;
  if (CborNoError != cbor_value_leave_container(&pheader_v, &pheader_map) ||
      !cbor_value_at_end(&pheader_map)) {
    return false;
  }
  // Check validity of other fields.
  return payload.size() > 0 && signature.size() == 96;
}

std::pair<ByteString, error::Error> CoseSign1::SigningBytes() const {
  std::vector<uint8_t> buf(protected_header.size() + payload.size() + sizeof(COSE_SIGN1_NAME) + 128);
  CborEncoder enc;
  cbor_encoder_init(&enc, buf.data(), buf.size(), 0);
  CborEncoder enc_array;
  if (CborNoError != cbor_encoder_create_array(&enc, &enc_array, 4) ||
      CborNoError != cbor_encode_text_stringz(&enc_array, COSE_SIGN1_NAME) ||
      CborNoError != cbor_encode_byte_string(&enc_array, protected_header.data(), protected_header.size()) ||
      CborNoError != cbor_encode_byte_string(&enc_array, nullptr, 0) ||
      CborNoError != cbor_encode_byte_string(&enc_array, payload.data(), payload.size()) ||
      CborNoError != cbor_encoder_close_container(&enc, &enc_array)) {
    return std::make_pair(std::move(buf), COUNTED_ERROR(AttestationNitro_CoseSignatureEncode));
  }
  size_t encoded_size = cbor_encoder_get_buffer_size(&enc, buf.data());
  buf.resize(encoded_size);
  return std::make_pair(std::move(buf), error::OK);
}

void AttestationDoc::Clear() {
  module_id.clear();
  digest.clear();
  timestamp = 0;
  pcrs.clear();
  certificate.clear();
  cabundle.clear();
  public_key.clear();
  user_data.clear();
  nonce.clear();
}

error::Error AttestationDoc::ParseFromBytes(const uint8_t* in, size_t size) {
  Clear();
  CborParser payload_p;
  CborValue payload_v;
  if (CborNoError != cbor_parser_init(in, size, 0, &payload_p, &payload_v) ||
      CborMapType != cbor_value_get_type(&payload_v)) {
    return COUNTED_ERROR(AttestationNitro_AttestationParse);
  }
  CborValue payload;
  if (CborNoError != cbor_value_enter_container(&payload_v, &payload)) {
    return COUNTED_ERROR(AttestationNitro_CborError);
  }
  while (!cbor_value_at_end(&payload)) {
    ASSIGN_OR_RETURN(key, CborTextString(&payload));
    if (key == "module_id" || key == "digest") {
      ASSIGN_OR_RETURN(val, CborTextString(&payload));
      if (key == "module_id") {
        this->module_id = std::move(val);
      } else if (key == "digest") {
        this->digest = std::move(val);
      }
    } else if (key == "certificate" || key == "public_key" || key == "user_data" || key == "nonce") {
      ASSIGN_OR_RETURN(val, CborByteString(&payload));
      if (key == "certificate") {
        this->certificate = std::move(val);
      } else if (key == "public_key") {
        this->public_key = std::move(val);
      } else if (key == "user_data") {
        this->user_data = std::move(val);
      } else if (key == "nonce") {
        this->nonce = std::move(val);
      }
    } else if (key == "pcrs") {
      if (CborMapType != cbor_value_get_type(&payload)) {
        return COUNTED_ERROR(AttestationNitro_AttestationParse);
      }
      CborValue payload_map;
      if (CborNoError != cbor_value_enter_container(&payload, &payload_map)) {
        return COUNTED_ERROR(AttestationNitro_CborError);
      }
      while (!cbor_value_at_end(&payload_map)) {
        ASSIGN_OR_RETURN(key, CborInt(&payload_map));
        ASSIGN_OR_RETURN(val, CborByteString(&payload_map));
        this->pcrs[key] = std::move(val);
      }
      if (CborNoError != cbor_value_leave_container(&payload, &payload_map)) {
        return COUNTED_ERROR(AttestationNitro_CborError);
      }
    } else if (key == "cabundle") {
      if (CborArrayType != cbor_value_get_type(&payload)) {
        return COUNTED_ERROR(AttestationNitro_AttestationParse);
      }
      CborValue payload_array;
      if (CborNoError != cbor_value_enter_container(&payload, &payload_array)) {
        return COUNTED_ERROR(AttestationNitro_CborError);
      }
      while (!cbor_value_at_end(&payload_array)) {
        ASSIGN_OR_RETURN(val, CborByteString(&payload_array));
        this->cabundle.emplace_back(std::move(val));
      }
      if (CborNoError != cbor_value_leave_container(&payload, &payload_array)) {
        return COUNTED_ERROR(AttestationNitro_CborError);
      }
    } else if (key == "timestamp") {
      ASSIGN_OR_RETURN(val, CborInt(&payload));
      this->timestamp = val;
    } else {
      return COUNTED_ERROR(AttestationNitro_AttestationParse);
    }
  }
  if (!Valid()) return COUNTED_ERROR(AttestationNitro_AttestationParse);
  return error::OK;
}

bool AttestationDoc::Valid() const {
  // Implements part of the checking in
  // https://github.com/aws/aws-nitro-enclaves-nsm-api/blob/main/docs/attestation_process.md,
  // the rest is implemented as the bytes are parsed in ParseFromBytes.
  if (module_id.size() == 0) return false;
  if (digest != "SHA384") return false;
  if (timestamp <= 0) return false;
  if (pcrs.size() < 1 || pcrs.size() > 32) return false;
  for (auto iter : pcrs) {
    if (iter.first < 0 || iter.first >= 32) return false;
    switch (iter.second.size()) {
      case 32:
      case 48:
      case 64:
        break;
      default:
        return false;
    }
  }
  if (certificate.size() < 1 || certificate.size() > 1024) return false;
  for (size_t i = 0; i < cabundle.size(); i++) {
    const auto& cert = cabundle[i];
    if (cert.size() < 1 || cert.size() > 1024) return false;
  }
  if (cabundle.size() == 0) return false;
  if (public_key.size() > 1024) return false;
  if (user_data.size() > 512) return false;
  if (nonce.size() > 512) return false;
  return true;
}

std::pair<bssl::UniquePtr<X509>, error::Error> AttestationDoc::Certificate() const {
  bssl::UniquePtr<X509> certificate;
  const uint8_t* data = this->certificate.data();
  certificate.reset(d2i_X509(nullptr, &data, this->certificate.size()));
  if (!certificate) return std::make_pair(nullptr, COUNTED_ERROR(AttestationNitro_CertificateDecode));
  if (data != this->certificate.data() + this->certificate.size()) return std::make_pair(nullptr, COUNTED_ERROR(AttestationNitro_CertificateDecode));
  return std::make_pair(std::move(certificate), error::OK);
}

std::pair<bssl::UniquePtr<STACK_OF(X509)>, error::Error> AttestationDoc::CABundle() const {
  bssl::UniquePtr<STACK_OF(X509)> cabundle(sk_X509_new_null());
  if (!cabundle) return std::make_pair(nullptr, COUNTED_ERROR(AttestationNitro_CryptoAllocate));
  for (size_t i = 0; i < this->cabundle.size(); i++) {
    const auto& cert = this->cabundle[i];
    const uint8_t* data = cert.data();
    bssl::UniquePtr<X509> parsed(d2i_X509(nullptr, &data, cert.size()));
    if (!parsed) return std::make_pair(nullptr, COUNTED_ERROR(AttestationNitro_CertificateDecode));
    if (data != cert.data() + cert.size()) return std::make_pair(nullptr, COUNTED_ERROR(AttestationNitro_CertificateDecode));
    if (0 == sk_X509_push(cabundle.get(), parsed.get())) return std::make_pair(nullptr, COUNTED_ERROR(AttestationNitro_CryptoAllocate));
    parsed.release();  // now owned by [cabundle]
  }
  return std::make_pair(std::move(cabundle), error::OK);
}

error::Error Verify(const AttestationDoc& doc, const CoseSign1& from, util::UnixSecs now) {
  ASSIGN_OR_RETURN(certificate, doc.Certificate());
  ASSIGN_OR_RETURN(cabundle, doc.CABundle());
  ASSIGN_OR_RETURN(data_to_verify, from.SigningBytes());

  bssl::UniquePtr<X509_STORE_CTX> ctx(X509_STORE_CTX_new());
  bssl::UniquePtr<X509_STORE> store(X509_STORE_new());
  if (!ctx || !store) return COUNTED_ERROR(AttestationNitro_CryptoAllocate);

  if (!X509_STORE_CTX_init(ctx.get(), store.get(), certificate.get(), cabundle.get())) return COUNTED_ERROR(AttestationNitro_CryptoStoreInit);
  // X509_STORE_CTX_set0_trusted_stack does not take ownership of roots_of_trust stack.
  X509_STORE_CTX_set0_trusted_stack(ctx.get(), roots_of_trust.get());
  X509_VERIFY_PARAM *param = X509_STORE_CTX_get0_param(ctx.get());
  X509_VERIFY_PARAM_set_time_posix(param, now);
  if (1 != X509_verify_cert(ctx.get())) {
    auto err = X509_STORE_CTX_get_error(ctx.get());
    LOG(ERROR) << "nitro attestation verify_cert err=" << err << ": " << X509_verify_cert_error_string(err);
    return COUNTED_ERROR(AttestationNitro_CertificateChainVerify);
  }

  bssl::UniquePtr<EVP_PKEY> pkey(X509_get_pubkey(certificate.get()));
  if (!pkey) return COUNTED_ERROR(AttestationNitro_CryptoAllocate);

  // Our signature is not ASN1, so we have to use lower-level ECDSA
  // functions for verification.  First, we compute our SHA384 digest...
  bssl::UniquePtr<EVP_MD_CTX> md_ctx(EVP_MD_CTX_new());
  if (!md_ctx) return COUNTED_ERROR(AttestationNitro_CryptoAllocate);
  EVP_MD_CTX_init(md_ctx.get());
  uint8_t md[48];
  unsigned int md_size = sizeof(md);
  if (1 != EVP_DigestInit(md_ctx.get(), EVP_sha384()) ||
      1 != EVP_DigestUpdate(md_ctx.get(), data_to_verify.data(), data_to_verify.size()) ||
      1 != EVP_DigestFinal(md_ctx.get(), md, &md_size) ||
      md_size != sizeof(md)) {
    return COUNTED_ERROR(AttestationNitro_CryptoMessageDigest);
  }

  // ... then we extract the signature's (R,S) values ...
  bssl::UniquePtr<ECDSA_SIG> sig(ECDSA_SIG_new());
  if (from.signature.size() != 48 * 2) return COUNTED_ERROR(AttestationNitro_CoseFormat);
  bssl::UniquePtr<BIGNUM> r(BN_bin2bn(from.signature.data(), 48, nullptr));
  bssl::UniquePtr<BIGNUM> s(BN_bin2bn(from.signature.data() + 48, 48, nullptr));
  if (!sig || !r || !s) return COUNTED_ERROR(AttestationNitro_CryptoAllocate);
  if (1 != ECDSA_SIG_set0(sig.get(), r.get(), s.get())) return COUNTED_ERROR(AttestationNitro_CoseSignatureVerify);
  r.release();  // now owned by sig
  s.release();  // now owned by sig

  // ... and finally we verify the message digest against signature.
  EC_KEY* ec_key_not_owned = EVP_PKEY_get0_EC_KEY(pkey.get());
  if (1 != ECDSA_do_verify(md, md_size, sig.get(), ec_key_not_owned)) {
    return COUNTED_ERROR(AttestationNitro_CoseSignatureVerify);
  }

  return error::OK;
}

}  // namespace svr2::attestation::nitro
