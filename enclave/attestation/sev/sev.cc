// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

#include <string.h>
#include <stdint.h>
#include "util/log.h"
#include "util/hex.h"
#include "proto/error.pb.h"
#include "metrics/metrics.h"

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

}  // namespace

#define MAX(a, b) ((a) > (b) ? (a) : (b))

error::Error ResizeCertificates(const uint8_t* certs, uint32_t* certs_size) {
  auto t = reinterpret_cast<const cert_table*>(certs);
  const uint32_t entry_size = sizeof(t->cert_table_entry[0]);
  uint8_t terminator[entry_size] = {0};
  uint32_t max_size = 0;
  for (size_t i = 0; ; i++) {
    uint32_t entry_end = entry_size * (i+1);
    if (entry_end > *certs_size) {
      return COUNTED_ERROR(SevAttest_CertsTableEntryTooLarge);
    }
    auto entry = t->cert_table_entry[i];
    max_size = MAX(max_size, entry_end);
    if (memcmp(terminator, &entry, sizeof(entry)) == 0) {
      LOG(INFO) << "Certificates total: " << i;
      break;
    }
    uint32_t cert_end = entry.offset + entry.length;
    if (cert_end > *certs_size) {
      return COUNTED_ERROR(SevAttest_CertsTableCertTooLarge);
    }
    max_size = MAX(max_size, entry.offset + entry.length);
    LOG(INFO) << "Certificate: " << util::BytesToHex(entry.guid, sizeof(entry.guid));
  }
  *certs_size = max_size;
  return error::OK;
}

}  // namespace svr2::attestation::sev
