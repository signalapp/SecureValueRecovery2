// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

#include "noise/noise.h"
#include <string.h>
#include "util/log.h"
#include "metrics/metrics.h"

namespace svr2::noise {

static size_t max_message_size = 65535;

std::pair<std::string, error::Error> Encrypt(NoiseCipherState* cs, const std::string& plaintext) {
  std::string ciphertext;
  size_t mac_size = noise_cipherstate_get_mac_length(cs);
  size_t max_encrypt_size = max_message_size - mac_size;
  size_t orig_size = plaintext.size();
  // We need to fit our plaintext into some number of Noise output packets.
  // Each of those packets cannot be larger than max_message_size, and must
  // contain some amount of ciphertext along with Noise's added MAC.
  // Thus, we have to add some amount of size equivilent to a multiple of
  // mac_size to the size of plaintext to get the final size of *ciphertext.
  // Examples of input sizes and output sizes, around the max_message_size
  // boundary, are:
  //   size == 1                               : add mac_size * 1 -> [cleartext(1B)][mac]
  //   size == max_message_size - mac_size     : add mac_size * 1 -> [cleartext(max_msg_sizeB)][mac]
  //   size == max_message_size - mac_size + 1 : add mac_size * 2 -> [cleartext(max_msg_sizeB)][mac1][cleartext(1B)][mac2]
  size_t num_macs = orig_size / max_encrypt_size + 1;
  if (orig_size % max_encrypt_size == 0 && num_macs > 1) num_macs--;
  size_t macs_size = mac_size * num_macs;
  size_t final_size = orig_size + macs_size;
  ciphertext.resize(final_size, 0);
  size_t plaintext_start = 0;
  for (size_t start = 0; start < final_size; start += max_message_size) {
    size_t plaintext_size = std::min(max_encrypt_size, plaintext.size() - plaintext_start);
    memcpy(StrU8Ptr(&ciphertext) + start, StrU8Ptr(plaintext) + plaintext_start, plaintext_size);
    plaintext_start += plaintext_size;
    NoiseBuffer buf;
    noise_buffer_set_inout(buf, StrU8Ptr(&ciphertext) + start, plaintext_size, plaintext_size + mac_size);
    if (NOISE_ERROR_NONE != noise_cipherstate_encrypt(cs, &buf)) {
      return std::make_pair("", COUNTED_ERROR(Peers_Encrypt));
    }
  }
  return std::make_pair(ciphertext, error::OK);
}

std::pair<std::string, error::Error> Decrypt(NoiseCipherState* cs, const std::string& ciphertext) {
  std::string plaintext(ciphertext.size(), 0);
  size_t plaintext_start = 0;
  // Data comes in as [ciphertext][mac][ciphertext][mac].
  for (size_t start = 0; start < ciphertext.size(); start += max_message_size) {
    size_t size = std::min(max_message_size, ciphertext.size() - start);
    memcpy(StrU8Ptr(&plaintext) + plaintext_start, StrU8Ptr(ciphertext) + start, size);
    NoiseBuffer buf;
    noise_buffer_set_inout(buf, StrU8Ptr(&plaintext) + plaintext_start, size, size);
    if (NOISE_ERROR_NONE != noise_cipherstate_decrypt(cs, &buf)) {
      return std::make_pair("", COUNTED_ERROR(Peers_Decrypt));
    }
    plaintext_start += buf.size;
  }
  plaintext.resize(plaintext_start, 0);
  return std::make_pair(plaintext, error::OK);
}

DHState CloneDHState(const DHState& s) {
  NoiseDHState* sp = nullptr;
  auto dh_id = noise_dhstate_get_dh_id(s.get());
  CHECK(NOISE_ERROR_NONE == noise_dhstate_new_by_id(&sp, dh_id));
  CHECK(NOISE_ERROR_NONE == noise_dhstate_copy(sp, s.get()));
  return WrapDHState(sp);
}

}  // namespace svr2::noise
