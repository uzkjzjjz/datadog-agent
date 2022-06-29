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
	Event    unsafe.Pointer
	UserData unsafe.Pointer

	// cache available across all the evaluations
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
func (c *Context) SetEvent(event unsafe.Pointer) {
	c.Event = event
}

// SetUserData set the given data to the context
func (c *Context) SetUserData(data unsafe.Pointer) {
	c.UserData = data
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
func NewContext(event unsafe.Pointer) *Context {
	return &Context{
		Event: event,
		Cache: make(map[string]unsafe.Pointer),
	}
}

// ContextPool defines a pool of context
type ContextPool struct {
	pool sync.Pool
}

// Get returns a context with the given object
func (c *ContextPool) Get(event unsafe.Pointer, data unsafe.Pointer) *Context {
	ctx := c.pool.Get().(*Context)
	ctx.Event, ctx.UserData = event, data
	return ctx
}

// Put returns the context to the pool
func (c *ContextPool) Put(ctx *Context) {
	ctx.Reset()
	c.pool.Put(ctx)
}

// NewContextPool returns a new context pool
func NewContextPool() *ContextPool {
	return &ContextPool{
		pool: sync.Pool{
			New: func() interface{} { return NewContext(nil) },
		},
	}
}
