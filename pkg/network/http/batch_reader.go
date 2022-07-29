package http

import (
	"fmt"
	"unsafe"

	"github.com/DataDog/datadog-agent/pkg/util/log"
	"github.com/cilium/ebpf"
)

type batchReader struct {
	offsetManager *offsetManager
	batchMap      *ebpf.Map
}

func newBatchReader(offsetManager *offsetManager, batchMap *ebpf.Map) *batchReader {
	return &batchReader{
		offsetManager: offsetManager,
		batchMap:      batchMap,
	}
}

func (b *batchReader) Read(notification httpNotification, forcedRead bool) ([]httpTX, error) {
	key := new(httpBatchKey)
	key.Prepare(notification)
	batch := new(httpBatch)
	err := b.batchMap.Lookup(unsafe.Pointer(key), unsafe.Pointer(batch))
	if err != nil {
		return nil, fmt.Errorf("error retrieving http batch for cpu=%d", int(key.cpu))
	}

	if !forcedRead && batch.IsDirty(notification) {
		// This means the batch was overridden before we a got chance to read it
		log.Debugf("http: late read on get_transactions_from. cpu=%d", int(key.cpu))
		return nil, errLostBatch
	}

	i, j := b.offsetManager.Offsets(int(key.cpu), batch, forcedRead)
	return batch.Transactions()[i:j], nil
}
