// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package eval

import (
	"sync"
	"time"
	"unsafe"
)

// Context describes the context used during a rule evaluation
type Context struct {
	Event        interface{}
	ProbeContext interface{}

	// cache available across all the evaluations
	// TODO(safchain) change to interface{}
	Cache map[string]unsafe.Pointer

	now time.Time
}

// Now return and cache the `now` timestamp
func (c *Context) Now() time.Time {
	if c.now.IsZero() {
		c.now = time.Now()
	}
	return c.now
}

// SetEvent set the given event to the context
func (c *Context) SetEvent(event interface{}) {
	c.Event = event
}

// SetProbeContext set the given data to the context
func (c *Context) SetProbeContext(ctx interface{}) {
	c.ProbeContext = ctx
}

// Reset the context
func (c *Context) Reset() {
	c.Event = nil
	c.now = time.Time{}

	// as the cache should be low in entry, prefer to delete than re-alloc
	for key := range c.Cache {
		delete(c.Cache, key)
	}
}

// NewContext return a new Context
func NewContext(event interface{}, probeContext interface{}) *Context {
	return &Context{
		Event:        event,
		ProbeContext: probeContext,
		Cache:        make(map[string]unsafe.Pointer),
	}
}

// ContextPool defines a pool of context
type ContextPool struct {
	pool sync.Pool
}

// Get returns a context with the given object
func (cp *ContextPool) Get(event interface{}, probeContext interface{}) *Context {
	c := cp.pool.Get().(*Context)
	c.Event, c.ProbeContext = event, probeContext
	return c
}

// Put returns the context to the pool
func (cp *ContextPool) Put(ctx *Context) {
	ctx.Reset()
	cp.pool.Put(ctx)
}

// NewContextPool returns a new context pool
func NewContextPool() *ContextPool {
	return &ContextPool{
		pool: sync.Pool{
			New: func() interface{} { return NewContext(nil, nil) },
		},
	}
}
