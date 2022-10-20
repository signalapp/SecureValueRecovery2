// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

#include <ostream>
#include <functional>

#include "peerid/peerid.h"
#include "sip/halfsiphash.h"
#include "util/log.h"
#include "metrics/metrics.h"
#include "util/hex.h"

namespace svr2::peerid {

static std::array<uint8_t, 32> zero_id = {0};

size_t PeerIDHasher::operator()(const PeerID& id) const {
  return Hash(id.id_.data(), id.id_.size());
}

PeerID::PeerID(const uint8_t array[32]) {
  std::copy(array, array+32, id_.begin());
}
PeerID::PeerID() : id_({0}) {}
error::Error PeerID::FromString(const std::string& s) {
  if (s.size() != id_.size()) {
    return COUNTED_ERROR(Peers_InvalidID);
  }
  std::copy(s.begin(), s.end(), id_.begin());
  return error::OK;
}
bool PeerID::Valid() const {
  // https://cr.yp.to/ecdh.html#validate
  return id_ != zero_id;
}
void PeerID::ToString(std::string* s) const {
  s->resize(32, 0);
  std::copy(id_.begin(), id_.end(), s->begin());
}
std::string PeerID::DebugString() const {
  return util::PrefixToHex(id_, 4);
}

std::ostream& operator<<(std::ostream& os, const PeerID& peer_id) {
  os << peer_id.DebugString();
  return os;
}

}  // namespace svr2::peerid
