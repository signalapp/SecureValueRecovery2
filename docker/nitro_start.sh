#!/bin/bash
set -x -e -o pipefail

echo "Available releases:"
ls -la /releases/

ENCLAVE_INFO="$(mktemp)"
if ! nitro-cli run-enclave --eif-path "$ENCLAVE_PATH" --cpu-count ${CPUS:-2} --memory ${RAM:-1024} | tee $ENCLAVE_INFO; then
  echo "ERROR RUNNING ENCLAVE"
  for file in /var/log/nitro_enclaves/err*.log; do
    echo "=== Error file: $file ==="
    cat $file
  done
  exit 1
fi

ENCLAVE_CID="$(cat $ENCLAVE_INFO | jq .EnclaveCID)"
exec /bin/svr2 --enclave_type nitro --nitro_cid "$ENCLAVE_CID" --nitro_port 27427 "$@"
