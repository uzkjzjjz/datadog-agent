// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux
// +build linux

package module

import (
	"fmt"
	"sync"

	"github.com/DataDog/datadog-go/v5/statsd"
	"golang.org/x/time/rate"

	"github.com/DataDog/datadog-agent/pkg/security/metrics"
)

const (
	// Arbitrary default limit to prevent flooding.
	defaultLimit = rate.Limit(10)
	// Default Token bucket size. 40 is meant to handle sudden burst of events while making sure that we prevent
	// flooding.
	defaultBurst int = 40
)

// Limit defines rate limiter limit
type Limit struct {
	Limit int
	Burst int
}

// LimiterOpts rate limiter options
type LimiterOpts struct {
	Limits map[string]map[string]Limit
}

// Limiter describes an object that applies limits on
// the rate of triggering something (rules, acvitity dumps events etc)
type Limiter struct {
	limiter *rate.Limiter

	// https://github.com/golang/go/issues/36606
	padding int32 //nolint:structcheck,unused
	dropped int64
	allowed int64
}

// NewLimiter returns a new rate limiter
func NewLimiter(limit rate.Limit, burst int) *Limiter {
	return &Limiter{
		limiter: rate.NewLimiter(limit, burst),
	}
}

// RateLimiter describes a set of rate limiters
type RateLimiter struct {
	sync.RWMutex
	opts         LimiterOpts
	limiters     map[string]map[string]*Limiter
	statsdClient statsd.ClientInterface
}

// NewRateLimiter initializes an empty rate limiter
func NewRateLimiter(client statsd.ClientInterface, opts LimiterOpts) *RateLimiter {
	return &RateLimiter{
		limiters:     make(map[string]map[string]*Limiter),
		statsdClient: client,
		opts:         opts,
	}
}

// Apply a set of rate limiters
func (rl *RateLimiter) Apply(group string, ids []string) {
	rl.Lock()
	defer rl.Unlock()

	newLimiters := make(map[string]*Limiter)
	for _, id := range ids {
		if limiter, found := rl.limiters[group][id]; found {
			newLimiters[id] = limiter
		} else {
			limit := defaultLimit
			burst := defaultBurst

			if l, exists := rl.opts.Limits[group][id]; exists {
				limit = rate.Limit(l.Limit)
				burst = l.Burst
			}
			newLimiters[id] = NewLimiter(limit, burst)
		}
	}
	rl.limiters[group] = newLimiters
}

// Allow returns true if a specific consumer shall be allowed take a token
func (rl *RateLimiter) Allow(group string, id string) bool {
	rl.RLock()
	defer rl.RUnlock()

	limiter, ok := rl.limiters[group][id]
	if !ok {
		return false
	}
	if limiter.limiter.Allow() {
		limiter.allowed++
		return true
	}
	limiter.dropped++
	return false
}

// RateLimiterStat represents the rate limiting statistics
type RateLimiterStat struct {
	dropped int64
	allowed int64
}

// GetGroupStats returns a map indexed by IDs of a specified group
// that describes the amount of allowed and dropped hits
func (rl *RateLimiter) GetGroupStats(group string) map[string]RateLimiterStat {
	rl.Lock()
	defer rl.Unlock()

	stats := make(map[string]RateLimiterStat)
	for id, limiter := range rl.limiters[group] {
		stats[id] = RateLimiterStat{
			dropped: limiter.dropped,
			allowed: limiter.allowed,
		}
		limiter.dropped = 0
		limiter.allowed = 0
	}
	return stats
}

// SendGroupStats sends statistics about the number of allowed and drops hits
// for the given group of rate limiters
func (rl *RateLimiter) SendGroupStats(group string) error {
	for id, counts := range rl.GetGroupStats(group) {
		tags := []string{fmt.Sprintf("%s:%s", group, id)}
		if counts.dropped > 0 {
			if err := rl.statsdClient.Count(metrics.MetricRateLimiterDrop, counts.dropped, tags, 1.0); err != nil {
				return err
			}
		}
		if counts.allowed > 0 {
			if err := rl.statsdClient.Count(metrics.MetricRateLimiterAllow, counts.allowed, tags, 1.0); err != nil {
				return err
			}
		}
	}
	return nil
}
