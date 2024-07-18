// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

#include "db/db.h"
#include "db/db2.h"
#include "db/db3.h"

#include <memory>

namespace svr2::db {

const std::string DB::GLOBAL_KEY("");

const DB::Protocol* DB::P(enclaveconfig::DatabaseVersion version) {
  switch (version) {
    case enclaveconfig::DATABASE_VERSION_SVR2:
      return &db2_protocol;
    case enclaveconfig::DATABASE_VERSION_SVR3:
      return &db3_protocol;
    default:
      return nullptr;
  }
}

}  // namespace svr2::db
