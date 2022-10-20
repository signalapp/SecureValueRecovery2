#!/bin/bash
#
# Given a compiler and a header file, return what directory that header is located in.
#
set -e
if [[ $# != 2 ]]; then
  echo 1>&2 "Usage: $0 <compiler> <header>"
  exit 1
fi
COMPILER=$1
HEADER=$2
LISTING=""
"$COMPILER" -E -x c++ - -v </dev/null 2>&1 | while read line
do
  if [[ $line == "#include <...> search starts here:" ]]; then
    LISTING=1
  elif [[ $line == "End of search list." ]]; then
    exit 1
  elif [[ $LISTING != "" ]]; then
    if ls "$line/$HEADER" >/dev/null 2>/dev/null; then
      echo "$line"
      exit 0
    fi
  fi
done
