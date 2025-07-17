// Copyright 2024 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

#ifndef __SVR2_RISTRETTO_RISTRETTO_H__
#define __SVR2_RISTRETTO_RISTRETTO_H__

#include <stdint.h>
#include <array>
#include <sodium/crypto_core_ristretto255.h>
#include <sodium/crypto_scalarmult_ristretto255.h>
#include <string>
#include <type_traits>
#include <string.h>

namespace svr2::ristretto {

class Scalar {
 public:
  Scalar() : s_{0} {};
  Scalar(const Scalar& other) = default;
  Scalar(Scalar&& other) = default;
  Scalar& operator=(const Scalar&) = default;

  static Scalar Random();
  static Scalar Zero();
  static Scalar Reduce(const std::array<uint8_t, crypto_core_ristretto255_NONREDUCEDSCALARBYTES>& h);
  bool FromString(const std::string& s);

  Scalar Add(const Scalar& a) const;
  Scalar Negate() const;
  Scalar Mult(const Scalar& a) const;
  bool Invert(Scalar* s) const
      __attribute__ ((warn_unused_result));
  bool Valid() const;
  bool IsZero() const;

  const uint8_t* data() const { return s_.data(); }
  uint8_t* data() { return s_.data(); }
  size_t size() const { return s_.size(); }
  void Clear() { memset(data(), 0, size()); }
  std::string ToString() const;

 private:
  std::array<uint8_t, crypto_scalarmult_ristretto255_SCALARBYTES> s_;
};
static_assert(std::is_standard_layout_v<Scalar> == true);
static_assert(sizeof(Scalar) == crypto_scalarmult_ristretto255_SCALARBYTES);

class Point {
 public:
  Point() : p_{0} {};
  Point(const Point& other) = default;
  Point(Point&& other) = default;
  Point& operator=(const Point&) = default;

  bool FromHash(const std::array<uint8_t, crypto_core_ristretto255_HASHBYTES>& h)
      __attribute__ ((warn_unused_result));
  bool ScalarMultBase(const Scalar& n)
      __attribute__ ((warn_unused_result));
  bool FromString(const std::string& s);

  bool ScalarMult(const Scalar& n, Point* p) const
      __attribute__ ((warn_unused_result));
  bool Add(const Point& a, Point* c) const
      __attribute__ ((warn_unused_result));
  bool Valid() const;

  const uint8_t* data() const { return p_.data(); }
  uint8_t* data() { return p_.data(); }
  size_t size() const { return p_.size(); }
  void Clear() { memset(data(), 0, size()); }
  std::string ToString() const;
 
 private:
  std::array<uint8_t, crypto_scalarmult_ristretto255_BYTES> p_;
};
static_assert(std::is_standard_layout_v<Point> == true);
static_assert(sizeof(Point) == crypto_scalarmult_ristretto255_BYTES);

}  // namespace svr2::ristretto

#endif  // __SVR2_RISTRETTO_RISTRETTO_H__
