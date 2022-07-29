package http

import "sync"

type offsetManager struct {
	mux        sync.Mutex
	stateByCPU []*cpuReadState
}

type cpuReadState struct {
	// this is the nextBatchID we're expecting for a particular CPU core. we use
	// this when we attempt to retrieve the latest HTTP transactions from kernel
	// space that haven't been sent to userspace yet because they're enqueued in
	// batch that isn't complete
	// we refer to this as a "forced read" elsewhere in the code
	nextBatchID int

	// information associated to partial batch reads
	partialBatchID int
	partialOffset  int
}

func newOffsetManager(numCPUS int) *offsetManager {
	stateByCPU := make([]*cpuReadState, numCPUS)
	for i := range stateByCPU {
		stateByCPU[i] = new(cpuReadState)
	}

	return &offsetManager{stateByCPU: stateByCPU}
}

func (o *offsetManager) Offsets(cpu int, batch *httpBatch, forcedRead bool) (i, j int) {
	o.mux.Lock()
	defer o.mux.Unlock()
	state := o.stateByCPU[cpu]

	if batch.IsComplete() {
		// update nextBatchID
		state.nextBatchID = max(int(batch.idx)+1, state.nextBatchID)
	}

	// determining the start offset
	// usually this is 0, but we've done a partial read of this batch
	// we need to take it into account
	if int(batch.idx) == state.partialBatchID {
		i = state.partialOffset
	}

	// determining the end offset
	// usually this is HTTP_BATCH_SIZE but it can be less
	// in the context of a forced (partial) read
	j = int(batch.pos)

	// if this is part of a forced read (that is, we're reading a batch before
	// it's complete) we need to keep track of which entries we're reading
	// so we avoid reading the same entries again
	if forcedRead {
		state.partialBatchID = int(batch.idx)
		state.partialOffset = j
	}

	return

}

func (o *offsetManager) NextBatchID(cpu int) int {
	o.mux.Lock()
	defer o.mux.Unlock()
	return o.stateByCPU[cpu].nextBatchID
}

func max(a, b int) int {
	if a >= b {
		return a
	}

	return b
}
