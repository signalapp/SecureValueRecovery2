#!/bin/bash
set -e
set -x
STDOUT=$(mktemp)
TMPDIR=$(mktemp -d)
nitro-cli build-enclave --docker-uri ${DOCKER_IMAGE} --output-file ${TMPDIR}/svr2.eif >$STDOUT
chown ${CHOWN_TO} ${TMPDIR}/svr2.eif
cp -vn ${TMPDIR}/svr2.eif ${OUTPUT_DIR}/nitro.$(cat $STDOUT | jq -r '.Measurements.PCR0[:8] + "." + .Measurements.PCR1[:8] + "." + .Measurements.PCR2[:8]').eif
