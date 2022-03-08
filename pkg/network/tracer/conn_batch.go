package tracer

import (
	"reflect"
	"sync"
)

var connPool = &sync.Pool{
	New: func() interface{} {
		return new(Conn)
	},
}

type ConnBatcher struct {
	*Batcher
	connChan chan *Conn
}

func NewConnBatcher() (*ConnBatcher, error) {
	b, err := NewBatcher(reflect.TypeOf(Conn{}), "conn_t", defaultClosedChannelSize, 5, 128)
	if err != nil {
		return nil, err
	}

	cb := &ConnBatcher{
		Batcher:  b,
		connChan: make(chan *Conn, defaultClosedChannelSize),
	}
	return cb, nil
}

func (cb *ConnBatcher) Start() error {
	go func() {
		defer close(cb.connChan)

		for o := range cb.Batcher.Objects() {
			cb.connChan <- o.(*Conn)
		}
	}()

	return cb.Batcher.Start()
}

func (cb *ConnBatcher) Objects() <-chan *Conn {
	return cb.connChan
}

func (cb *ConnBatcher) PendingObjects() <-chan *Conn {
	ch := make(chan *Conn)
	go func() {
		defer close(ch)

		for c := range cb.Batcher.PendingObjects() {
			ch <- c.(*Conn)
		}
	}()
	return ch
}
