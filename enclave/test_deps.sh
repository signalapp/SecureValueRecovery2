#!/bin/bash

for testfile in `find ./ -type f | grep /tests/ | grep cc$`; do
  testfile="$(echo "$testfile" | sed 's#./##')"
  testname="$(echo "$testfile" | sed 's/\.cc$/\.test/')"
  echo 1>&2 "TEST: $testfile -> $testname"
  deps="build/$(dirname $(dirname "$testfile"))/TEST.a$(grep '^//TESTDEP ' "$testfile" | awk '{printf " build/%s/TEST.a",$2}')"
  echo 1>&2 "  Deps: $deps"
  args="$(grep '^//TESTARG ' "$testfile" | awk '{printf "%s ",$2}')"
  echo 1>&2 "  Args: $args"
  echo "build/$testname: $testfile $deps"
  echo -e '\t$(QUIET) echo -e "BUILD\t$@"'
  echo -e '\t$(QUIET) mkdir -p \$(@D)'
  echo -e "\t\$(QUIET) \$(CXX) \$(TEST_CXXFLAGS) -o \$@ $testfile -Wl,--start-group $deps -Wl,--end-group $args \$(TEST_LDFLAGS)"
  echo "test: build/$testname.success"
  echo ".PRECIOUS: build/$testname build/$testname.out"
done | tee .testdepends
