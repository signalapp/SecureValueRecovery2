#!/bin/bash

OUT=0
for pattern in '*.c' '*.cc' '*.h' '*.go' '*.proto' '*.sh' 'Makefile*'; do
  for file in `find ./ -name $pattern -type f |
      grep -v -f <(cat .gitmodules |
      grep path |
      awk '{print $3}') |
      egrep -v 'gopath|enclave/build|host/enclave/c'`; do
    if ! grep -q Copyright $file; then
      OUT=1
      echo "Missing copyright in '$file'" 1>&2
    fi
  done
done
exit $OUT
