package tracer

import (
	"fmt"
	"math"
	"os"
	"reflect"
	"sync"
	"sync/atomic"
	"unsafe"

	ddebpf "github.com/DataDog/datadog-agent/pkg/ebpf"
	"github.com/DataDog/datadog-agent/pkg/util/kernel"
	"github.com/DataDog/datadog-agent/pkg/util/log"
	"github.com/DataDog/ebpf"
	"github.com/DataDog/ebpf/manager"
)

type batchCpu struct {
	offset uint64
	len    uint8
}

type batchNotification struct {
	offset uint64
	len    uint8
}

type BatchTelemetry struct {
	PerfReceived int64
	PerfLost     int64
}

type Batcher struct {
	typ           reflect.Type
	cName         string
	batchSize     uint32
	batchesPerCPU uint32
	cpuCount      int

	lastOffset map[int]uint64
	objChan    chan interface{}

	handler   *ddebpf.PerfHandler
	m         *manager.Manager
	objMap    *ebpf.Map
	offsetMap *ebpf.Map
	perfMap   *manager.PerfMap

	// lock protects lastOffset
	lock sync.Mutex

	telemetry BatchTelemetry
}

func NewBatcher(outType reflect.Type, cTypeName string, channelSize int, batchSize uint32, batchesPerCPU uint32) (*Batcher, error) {
	cpus, err := kernel.PossibleCPUs()
	if err != nil {
		return nil, err
	}

	offsets := make(map[int]uint64, cpus)
	for c := 0; c < cpus; c++ {
		offsets[c] = math.MaxUint64
	}

	return &Batcher{
		typ:           outType,
		cName:         cTypeName,
		batchSize:     batchSize,
		batchesPerCPU: batchesPerCPU,
		cpuCount:      cpus,
		objChan:       make(chan interface{}, channelSize),
		handler:       ddebpf.NewPerfHandler(channelSize),
		lastOffset:    offsets,
	}, nil
}

func (b *Batcher) Attach(m *manager.Manager, opts *manager.Options) error {
	m.Maps = append(m.Maps, &manager.Map{Name: b.offsetMapName()}, &manager.Map{Name: b.objMapName()})
	m.PerfMaps = append(m.PerfMaps, &manager.PerfMap{
		Map: manager.Map{Name: b.perfMapName()},
		PerfMapOptions: manager.PerfMapOptions{
			PerfRingBufferSize: 8 * os.Getpagesize(),
			Watermark:          1,
			DataHandler:        b.handler.DataHandler,
			LostHandler:        b.handler.LostHandler,
		},
	})

	if opts.MapSpecEditors == nil {
		opts.MapSpecEditors = make(map[string]manager.MapSpecEditor)
	}
	opts.MapSpecEditors[b.offsetMapName()] = manager.MapSpecEditor{
		Type:       ebpf.Array,
		MaxEntries: uint32(b.cpuCount),
		EditorFlag: manager.EditMaxEntries,
	}
	opts.MapSpecEditors[b.objMapName()] = manager.MapSpecEditor{
		Type:       ebpf.Hash,
		MaxEntries: uint32(b.cpuCount) * b.batchSize * b.batchesPerCPU,
		EditorFlag: manager.EditMaxEntries,
	}
	b.m = m
	return nil
}

func (b *Batcher) Start() error {
	var err error
	b.objMap, _, err = b.m.GetMap(b.objMapName())
	if err != nil {
		return err
	}

	b.offsetMap, _, err = b.m.GetMap(b.offsetMapName())
	if err != nil {
		return err
	}

	pm, found := b.m.GetPerfMap(b.perfMapName())
	if !found {
		return fmt.Errorf("unable to find perf map %s", b.perfMapName())
	}
	b.perfMap = pm

	// set initial offsets
	for cpu := 0; cpu < b.cpuCount; cpu++ {
		cb := new(batchCpu)
		cb.offset = uint64(cpu) * uint64(b.batchesPerCPU)
		if err := b.offsetMap.Put(unsafe.Pointer(&cpu), unsafe.Pointer(cb)); err != nil {
			return err
		}
	}

	err = b.perfMap.Start()
	if err != nil {
		return err
	}

	go b.reader()

	return nil
}

func (b *Batcher) Objects() <-chan interface{} {
	return b.objChan
}

func (b *Batcher) PendingObjects() <-chan interface{} {
	ch := make(chan interface{})

	go func() {
		defer close(ch)

		b.lock.Lock()
		defer b.lock.Unlock()

		cb := new(batchCpu)
		for cpu := 0; cpu < b.cpuCount; cpu++ {
			if err := b.offsetMap.Lookup(unsafe.Pointer(&cpu), unsafe.Pointer(cb)); err != nil {
				log.Errorf("[%s] error reading offset map for cpu %d: %s", b.cName, cpu, err)
				continue
			}
			if cb.len > 0 {
				//log.Debugf("[%s] reading pending objects for cpu %d, offset %d, len %d", b.cName, cpu, cb.offset, cb.len)
				for _, o := range b.readBatch(cb.offset, cb.len, cpu) {
					ch <- o
				}
			}
		}
	}()

	return ch
}

func (b *Batcher) Stop() {
	_ = b.perfMap.Stop(manager.CleanAll)
	b.handler.Stop()
	b.m = nil
}

func (b *Batcher) GetStats() BatchTelemetry {
	return BatchTelemetry{
		PerfReceived: atomic.LoadInt64(&b.telemetry.PerfReceived),
		PerfLost:     atomic.LoadInt64(&b.telemetry.PerfLost),
	}
}

func (b *Batcher) reader() {
	for {
		select {
		case batchData, ok := <-b.handler.DataChannel:
			if !ok {
				return
			}
			atomic.AddInt64(&b.telemetry.PerfReceived, 1)
			note := toBatchNotification(batchData.Data)
			b.readFromNotification(note, batchData.CPU)
		case lostCount, ok := <-b.handler.LostChannel:
			if !ok {
				return
			}
			atomic.AddInt64(&b.telemetry.PerfLost, int64(lostCount))
			log.Warnf("[%s] lost %d batch notification(s)", b.cName, lostCount)
		}
	}
}

func (b *Batcher) readFromNotification(note *batchNotification, cpu int) {
	b.lock.Lock()
	defer b.lock.Unlock()

	ex := b.expectedOffset(cpu)
	// if not what we expected and also not within the same batch, due to pending reads
	if note.offset != ex && !(ex > note.offset && ex < (note.offset+uint64(note.len))) {
		// skipped one or more objects?!
		// TODO read skipped objects from lastOffset[cpu]+1 to note.offset?
		log.Warnf("[%s] notification offset %d does not match expected offset %d for cpu %d", b.cName, note.offset, ex, cpu)
	}

	objs := b.readBatch(note.offset, note.len, cpu)
	for _, o := range objs {
		b.objChan <- o
	}
}

func (b *Batcher) readBatch(offset uint64, len uint8, cpu int) []interface{} {
	//log.Tracef("[%s] readBatch cpu=%d offset=%d len=%d lastOffset=%d", b.cName, cpu, offset, len, b.lastOffset[cpu])
	start := offset
	end := offset + uint64(len)
	if b.lastOffset[cpu] >= offset && b.lastOffset[cpu] < end {
		start = b.lastOffset[cpu] + 1
	}
	objs := make([]interface{}, 0, end-start)

	//log.Tracef("[%s] start=%d end=%d", b.cName, start, end)
	for i := start; i < end; i++ {
		o := reflect.New(b.typ)
		err := b.objMap.Lookup(unsafe.Pointer(&i), unsafe.Pointer(o.Pointer()))
		if err != nil {
			log.Warnf("[%s] unable to find batched object at offset %d: %s", b.cName, i, err)
			continue
		}
		b.lastOffset[cpu] = i
		objs = append(objs, o.Interface())
		if err := b.objMap.Delete(unsafe.Pointer(&i)); err != nil {
			log.Warnf("[%s] unable to delete batched object at offset %d: %s", b.cName, i, err)
		}
	}
	return objs
}

// expectedOffset returns what the next offset should be for a specific CPU based on previous batch reading
func (b *Batcher) expectedOffset(cpu int) uint64 {
	off := b.lastOffset[cpu]
	perCPU := uint64(b.batchesPerCPU) * uint64(b.batchSize)

	// nothing read yet, so return initial offset
	if off == math.MaxUint64 {
		return uint64(cpu) * perCPU
	}
	// (cpu*per_cpu) + ((cpu_batch->offset + batch_size) % per_cpu);
	return (uint64(cpu) * perCPU) + ((off + 1) % perCPU)
}

func (b *Batcher) perfMapName() string {
	return b.cName + "_batch_event"
}

func (b *Batcher) objMapName() string {
	return b.cName + "_batched"
}

func (b *Batcher) offsetMapName() string {
	return b.cName + "_batch_offsets"
}

func toBatchNotification(data []byte) *batchNotification {
	return (*batchNotification)(unsafe.Pointer(&data[0]))
}
