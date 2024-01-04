#!/bin/bash
set -x -e -o pipefail
ENCLAVE_INFO="$(mktemp)"
nitro-cli run-enclave --eif-path "$ENCLAVE_PATH" --cpu-count ${CPUS:-2} --memory ${RAM:-1024} | tee $ENCLAVE_INFO
ENCLAVE_CID="$(cat $ENCLAVE_INFO | jq .EnclaveCID)"
echo "Available releases:"
ls -la /releases/
exec /bin/svr2 --enclave_type nitro --nitro_cid "$ENCLAVE_CID" --nitro_port 27427 "$@"
