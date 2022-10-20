// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

#include "db/db.h"
#include "db/db2.h"
#include "db/db3.h"

#include <memory>

namespace svr2::db {

std::unique_ptr<DB> DB::New(enclaveconfig::DatabaseVersion version) {
  std::unique_ptr<db::DB> out;
  switch (version) {
    case enclaveconfig::DATABASE_VERSION_SVR2:
      out.reset(new db::DB2());
      break;
    case enclaveconfig::DATABASE_VERSION_SVR3:
      out.reset(new db::DB3());
      break;
    default:
      return nullptr;
  }
  return out;
}

}  // namespace svr2::db
