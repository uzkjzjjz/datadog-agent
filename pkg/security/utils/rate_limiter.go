// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux
// +build linux

package utils

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
	Limiter *rate.Limiter

	// https://github.com/golang/go/issues/36606
	padding int32 //nolint:structcheck,unused
	dropped int64
	allowed int64
}

// NewLimiter returns a new rate limiter
func NewLimiter(limit rate.Limit, burst int) *Limiter {
	return &Limiter{
		Limiter: rate.NewLimiter(limit, burst),
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
func NewRateLimiter(client statsd.ClientInterface) *RateLimiter {
	return &RateLimiter{
		limiters:     make(map[string]map[string]*Limiter),
		statsdClient: client,
		opts: LimiterOpts{
			Limits: make(map[string]map[string]Limit),
		},
	}
}

// SetGroupLimiters sets of rate limiters
func (rl *RateLimiter) SetGroupLimiters(group string, ids []string) {
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

// AddNewLimiter adds a new rate limiter with specified limit and burst
func (rl *RateLimiter) AddNewLimiter(group string, id string, limit rate.Limit, burst int) error {
	rl.RLock()
	defer rl.RUnlock()

	if burst <= 1 {
		return fmt.Errorf("EINVAL")
	}

	_, ok := rl.limiters[group][id]
	if ok {
		return fmt.Errorf("EEXIST")
	}

	rl.limiters[group][id] = NewLimiter(limit, burst)

	return nil
}

// RemoveLimiter remove a specified rate limiter
func (rl *RateLimiter) RemoveLimiter(group string, id string) error {
	rl.RLock()
	defer rl.RUnlock()

	_, ok := rl.limiters[group][id]
	if !ok {
		return fmt.Errorf("ENOENT")
	}

	delete(rl.limiters[group], id)

	return nil
}

// Allow returns true if a specific consumer shall be allowed take a token
func (rl *RateLimiter) Allow(group string, id string) bool {
	rl.RLock()
	defer rl.RUnlock()

	limiter, ok := rl.limiters[group][id]
	if !ok {
		return false
	}
	if limiter.Limiter.Allow() {
		limiter.allowed++
		return true
	}
	limiter.dropped++
	return false
}

// UpdateLimit update the limit of a given rate limiter
func (rl *RateLimiter) UpdateLimit(group string, id string, newLimit rate.Limit, newBurst int) error {
	rl.RLock()
	defer rl.RUnlock()

	if newBurst <= 1 {
		return fmt.Errorf("EINVAL")
	}

	limiter, ok := rl.limiters[group][id]
	if !ok {
		return fmt.Errorf("ENOENT")
	}

	limiter.Limiter.SetLimit(newLimit)
	limiter.Limiter.SetBurst(newBurst)

	return nil
}

// GetLimit gets the limit of a given rate limiter
func (rl *RateLimiter) GetLimit(group string, id string) (rate.Limit, int, error) {
	rl.RLock()
	defer rl.RUnlock()

	limiter, ok := rl.limiters[group][id]
	if !ok {
		return 0, 0, fmt.Errorf("ENOENT")
	}

	limit := limiter.Limiter.Limit()
	burst := limiter.Limiter.Burst()

	return limit, burst, nil
}

// RateLimiterStat represents the rate limiting statistics
type RateLimiterStat struct {
	Dropped int64
	Allowed int64
}

// GetStats gives you the current stats of a given rate limiter, and allow you to reset them
func (rl *RateLimiter) GetStats(group string, id string, reset bool) (RateLimiterStat, error) {
	rl.Lock()
	defer rl.Unlock()

	var stats RateLimiterStat
	limiter, ok := rl.limiters[group][id]
	if !ok {
		return RateLimiterStat{0, 0}, fmt.Errorf("ENOENT")
	}
	stats.Dropped = limiter.dropped
	stats.Allowed = limiter.allowed
	if reset {
		limiter.dropped = 0
		limiter.allowed = 0
	}
	return stats, nil
}

// GetGroupStats returns a map indexed by IDs of a specified group
// that describes the amount of allowed and dropped hits
func (rl *RateLimiter) GetGroupStats(group string) map[string]RateLimiterStat {
	rl.Lock()
	defer rl.Unlock()

	stats := make(map[string]RateLimiterStat)
	for id, limiter := range rl.limiters[group] {
		stats[id] = RateLimiterStat{
			Dropped: limiter.dropped,
			Allowed: limiter.allowed,
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
		if counts.Dropped > 0 {
			if err := rl.statsdClient.Count(metrics.MetricRateLimiterDrop, counts.Dropped, tags, 1.0); err != nil {
				return err
			}
		}
		if counts.Allowed > 0 {
			if err := rl.statsdClient.Count(metrics.MetricRateLimiterAllow, counts.Allowed, tags, 1.0); err != nil {
				return err
			}
		}
	}
	return nil
}
