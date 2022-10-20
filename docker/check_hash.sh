#!/bin/bash
set -e
EXPECTED_HASH="$(cat sha256."$(basename "$1")")"
ACTUAL_HASH="$(sha256sum "$1")"
echo "Checking hash for '$1'"
echo "Expected: '$EXPECTED_HASH'"
echo "Actual:   '$ACTUAL_HASH'"
exec [ "$EXPECTED_HASH" == "$ACTUAL_HASH" ]
