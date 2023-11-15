// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

#ifndef __SVR2_PEERID_PEERID_H__
#define __SVR2_PEERID_PEERID_H__

#include <string>
#include <array>
#include <memory>

#include "context/context.h"
#include "proto/error.pb.h"
#include "sip/hasher.h"

namespace svr2::peerid {

class PeerID;

class PeerIDHasher : public sip::Half {
 public:
  size_t operator()(const PeerID& id) const;
};

class PeerID {
 public:
  PeerID(PeerID&& moved) = default;
  PeerID(const PeerID& copied) = default;
  PeerID& operator=(const PeerID& other) = default;
  PeerID();  // all zeros, invalid
  PeerID(const uint8_t array[32]);
  error::Error FromString(const std::string& s);
  void ToString(std::string* s) const;
  const std::array<uint8_t, 32>& Get() const { return id_; }
  bool Valid() const;
  bool operator==(const PeerID& other) const { return id_ == other.id_; }
  bool operator!=(const PeerID& other) const { return id_ != other.id_; }
  bool operator<(const PeerID& other) const { return id_ < other.id_; }
  std::string DebugString() const;
  std::string AsString() const { std::string out; ToString(&out); return out; }
  
  // Prints DebugString() to an ostream. Overload is acceptable because
  // PeerID represents a value and DebugString() does not expose any implementation
  // details of the object (https://google.github.io/styleguide/cppguide.html#Streams)
  friend std::ostream& operator<<(std::ostream& os, const PeerID& peer_id);


 private:
  std::array<uint8_t, 32> id_;
  friend class PeerIDHasher;
};

}  // namespace svr2::peerid

#endif  // __SVR2_PEERID_PEERID_H__
