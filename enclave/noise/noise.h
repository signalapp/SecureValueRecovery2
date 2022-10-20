// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

#ifndef __SVR2_NOISE_NOISE_H__
#define __SVR2_NOISE_NOISE_H__

#include <string>
#include <noise/protocol/buffer.h>
#include <noise/protocol/handshakestate.h>
#include <noise/protocol/dhstate.h>
#include <noise/protocol/cipherstate.h>
#include <noise/protocol/randstate.h>
#include "proto/error.pb.h"

// This module provides simple RAII wrappers around noise-c pointers.
// The pointers are exposed publicly as .state, allowing use of noise_* functions
// directly on them, but with the guarantee that when the *State objects fall
// out of scope, the correct noise_*_free function will be called on them.

#include "util/macros.h"

namespace svr2::noise {

const size_t HANDSHAKE_INIT_SIZE = 64;

inline uint8_t* StrU8Ptr(std::string* s) {
  return reinterpret_cast<uint8_t*>(s->data());
}
inline const uint8_t* StrU8Ptr(const std::string& s) {
  return reinterpret_cast<const uint8_t*>(s.data());
}

inline NoiseBuffer BufferOutputFromString(std::string* s) {
  NoiseBuffer b;
  noise_buffer_set_output(b, StrU8Ptr(s), s->size());
  return b;
}

inline NoiseBuffer BufferInputFromString(std::string* s) {
  NoiseBuffer b;
  noise_buffer_set_input(b, StrU8Ptr(s), s->size());
  return b;
}

inline NoiseBuffer BufferInoutFromString(std::string* s, size_t substr) {
  CHECK(substr <= s->size());
  NoiseBuffer b;
  noise_buffer_set_inout(b, StrU8Ptr(s), substr, s->size());
  return b;
}

typedef std::unique_ptr<NoiseHandshakeState, int(*)(NoiseHandshakeState*)> HandshakeState;
inline HandshakeState WrapHandshakeState(NoiseHandshakeState* s) {
  return HandshakeState(s, noise_handshakestate_free);
}

typedef std::unique_ptr<NoiseDHState, int(*)(NoiseDHState*)> DHState;
inline DHState WrapDHState(NoiseDHState* s) {
  return DHState(s, noise_dhstate_free);
}

DHState CloneDHState(const DHState& s);

typedef std::unique_ptr<NoiseCipherState, int(*)(NoiseCipherState*)> CipherState;
inline CipherState WrapCipherState(NoiseCipherState* s) {
  return CipherState(s, noise_cipherstate_free);
}

// Encrypt the given string.
std::pair<std::string, error::Error> Encrypt(NoiseCipherState* cs, const std::string& plaintext);
// Decrypt the given string.
std::pair<std::string, error::Error> Decrypt(NoiseCipherState* cs, const std::string& ciphertext);

}  // namespace svr2::noise

#endif  // __SVR2_NOISE_NOISE_H__
