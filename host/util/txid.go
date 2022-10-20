// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

package util

import "sync/atomic"

// TxGenerator provides unique transaction ids for transactional request/responses
// to the enclave
type TxGenerator struct {
	txcounter uint64
}

// NextId returns a new unique transaction id
func (t *TxGenerator) NextID() uint64 {
	return atomic.AddUint64(&t.txcounter, 1)
}
