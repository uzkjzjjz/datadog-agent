package tracer

import (
	"fmt"
	"os"
	"reflect"
	"unsafe"

	ddebpf "github.com/DataDog/datadog-agent/pkg/ebpf"
	"github.com/DataDog/datadog-agent/pkg/util/kernel"
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
}

func NewBatcher(outType interface{}, cTypeName string, channelSize int, batchSize uint32, batchesPerCPU uint32) (*Batcher, error) {
	cpus, err := kernel.PossibleCPUs()
	if err != nil {
		return nil, err
	}

	return &Batcher{
		typ:           reflect.TypeOf(outType),
		cName:         cTypeName,
		batchSize:     batchSize,
		batchesPerCPU: batchesPerCPU,
		cpuCount:      cpus,
		objChan:       make(chan interface{}),
		handler:       ddebpf.NewPerfHandler(channelSize),
		lastOffset:    make(map[int]uint64, cpus),
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
		b.lastOffset[cpu] = cb.offset
	}

	err = b.perfMap.Start()
	if err != nil {
		return err
	}

	go b.reader()

	return nil
}

func (b *Batcher) reader() {
	for {
		select {
		case batchData, ok := <-b.handler.DataChannel:
			if !ok {
				return
			}
			note := toBatchNotification(batchData.Data)
			if note.offset != b.expectedOffset(batchData.CPU) {
				// skipped one or more objects?!
				// TODO read skipped batches
			}

			b.readBatch(note.offset, note.len, batchData.CPU)
		case _, ok := <-b.handler.LostChannel:
			if !ok {
				return
			}

			// TODO
		}
	}
}

func (b *Batcher) readBatch(offset uint64, len uint8, cpu int) {
	for i := offset; i < offset+uint64(len); i++ {
		o := reflect.New(b.typ)
		err := b.objMap.Lookup(unsafe.Pointer(&i), unsafe.Pointer(o.Pointer()))
		if err != nil {
			// TODO log?
			continue
		}
		b.lastOffset[cpu] = i
		b.objChan <- o
	}
}

func (b *Batcher) expectedOffset(cpu int) uint64 {
	off := b.lastOffset[cpu]
	// (cpu*per_cpu) + ((cpu_batch->offset + batch_size) % per_cpu);
	perCPU := uint64(b.batchesPerCPU) * uint64(b.batchSize)
	return (uint64(cpu) * perCPU) + ((off + 1) % perCPU)
}

func (b *Batcher) Objects() <-chan interface{} {
	return b.objChan
}

func (b *Batcher) Stop() {
	_ = b.perfMap.Stop(manager.CleanAll)
	b.handler.Stop()
	b.m = nil
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
