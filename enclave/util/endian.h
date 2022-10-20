// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

#ifndef __SVR2_UTIL_ENDIAN_H__
#define __SVR2_UTIL_ENDIAN_H__

namespace svr2::util {

inline uint64_t BigEndian64FromBytes(const uint8_t in[8]) {
  return ((uint64_t)in[0]) << (8*7) |
         ((uint64_t)in[1]) << (8*6) |
         ((uint64_t)in[2]) << (8*5) |
         ((uint64_t)in[3]) << (8*4) |
         ((uint64_t)in[4]) << (8*3) |
         ((uint64_t)in[5]) << (8*2) |
         ((uint64_t)in[6]) << (8*1) |
         ((uint64_t)in[7]) << (8*0);
}

inline uint32_t BigEndian32FromBytes(const uint8_t in[4]) {
  return ((uint32_t)in[0]) << (8*3) |
         ((uint32_t)in[1]) << (8*2) |
         ((uint32_t)in[2]) << (8*1) |
         ((uint32_t)in[3]) << (8*0);
}

inline uint64_t BigEndian64FromBytes(const char* in) {
  return BigEndian64FromBytes(reinterpret_cast<const uint8_t*>(in));
}

inline void BigEndian64Bytes(uint64_t v, uint8_t out[8]) {
  out[0] = v >> (8*7);
  out[1] = v >> (8*6);
  out[2] = v >> (8*5);
  out[3] = v >> (8*4);
  out[4] = v >> (8*3);
  out[5] = v >> (8*2);
  out[6] = v >> (8*1);
  out[7] = v >> (8*0);
}

inline void BigEndian32Bytes(uint32_t v, uint8_t out[4]) {
  out[0] = v >> (8*3);
  out[1] = v >> (8*2);
  out[2] = v >> (8*1);
  out[3] = v >> (8*0);
}

inline void LittleEndian64Bytes(uint64_t v, uint8_t out[8]) {
  out[0] = v >> (8*0);
  out[1] = v >> (8*1);
  out[2] = v >> (8*2);
  out[3] = v >> (8*3);
  out[4] = v >> (8*4);
  out[5] = v >> (8*5);
  out[6] = v >> (8*6);
  out[7] = v >> (8*7);
}

}  // namespace svr2::util

#endif  // __SVR2_UTIL_ENDIAN_H__
