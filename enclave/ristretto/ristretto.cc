// Copyright 2024 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

#include "ristretto/ristretto.h"
#include "proto/error.pb.h"
#include "util/bytes.h"

namespace svr2::ristretto {

namespace {

template <class T>
const uint8_t* U8(const T& p) {
  return reinterpret_cast<const uint8_t*>(p.data());
}
template <class T>
uint8_t* U8(T& p) {
  return reinterpret_cast<uint8_t*>(p.data());
}

}  // namespace

bool Point::FromHash(const std::array<uint8_t, crypto_core_ristretto255_HASHBYTES>& h) {
  return 0 == crypto_core_ristretto255_from_hash(U8(*this), U8(h));
}
Scalar Scalar::Random() {
  Scalar s;
  crypto_core_ristretto255_scalar_random(s.data());
  return s;
}
Scalar Scalar::Zero() {
  Scalar s;
  memset(s.data(), 0, s.size());
  return s;
}
Scalar Scalar::Add(const Scalar& a) const {
  Scalar s;
  crypto_core_ristretto255_scalar_add(U8(s), U8(a), U8(*this));
  return s;
}
Scalar Scalar::Negate() const {
  Scalar s;
  crypto_core_ristretto255_scalar_negate(U8(s), U8(*this));
  return s;
}
Scalar Scalar::Mult(const Scalar& a) const {
  Scalar s;
  crypto_core_ristretto255_scalar_mul(U8(s), U8(a), U8(*this));
  return s;
}
bool Scalar::Invert(Scalar* s) const {
  return 0 == crypto_core_ristretto255_scalar_invert(U8(*s), U8(*this));
}
Scalar Scalar::Reduce(const std::array<uint8_t, crypto_core_ristretto255_NONREDUCEDSCALARBYTES>& h) {
  Scalar s;
  crypto_core_ristretto255_scalar_reduce(U8(s), U8(h));
  return s;
}

std::string Scalar::ToString() const {
  return util::ByteArrayToString(s_);
}

bool Point::ScalarMult(const Scalar& n, Point* p) const {
  return 0 == crypto_scalarmult_ristretto255(U8(*p), U8(n), U8(*this));
}
bool Point::ScalarMultBase(const Scalar& n) {
  return 0 == crypto_scalarmult_ristretto255_base(U8(*this), U8(n));
}
bool Point::Add(const Point& a, Point* c) const {
  return 0 == crypto_core_ristretto255_add(U8(*c), U8(a), U8(*this));
}
bool Point::Valid() const {
  return crypto_core_ristretto255_is_valid_point(U8(*this));
}

// Pulled from private libsodium includes.
extern "C" {
int sc25519_is_canonical(const unsigned char s[32]);
}  // extern "C"

bool Scalar::Valid() const {
  return sc25519_is_canonical(U8(*this));
}

bool Scalar::FromString(const std::string& in) {
  if (in.size() != size()) return false;
  if (error::OK != util::StringIntoByteArray(in, &s_)) return false;
  return Valid();
}

bool Point::FromString(const std::string& in) {
  if (in.size() != size()) return false;
  if (error::OK != util::StringIntoByteArray(in, &p_)) return false;
  return Valid();
}

std::string Point::ToString() const {
  return util::ByteArrayToString(p_);
}

}  // namespace svr2::ristretto
