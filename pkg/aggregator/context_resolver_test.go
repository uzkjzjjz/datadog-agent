// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

// +build test

package aggregator

import (
	// stdlib

	"testing"

	// 3p
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/DataDog/datadog-agent/pkg/aggregator/ckey"
	"github.com/DataDog/datadog-agent/pkg/metrics"
	"github.com/DataDog/datadog-agent/pkg/tagset"
)

func TestGenerateContextKey(t *testing.T) {
	mSample := metrics.MetricSample{
		Name:       "my.metric.name",
		Value:      1,
		Mtype:      metrics.GaugeType,
		Tags:       tagset.NewTags([]string{"foo", "bar"}),
		Host:       "metric-hostname",
		SampleRate: 1,
	}

	contextKey := generateContextKey(&mSample)
	assert.Equal(t, ckey.ContextKey(0x14298ff49d0c6bb9), contextKey)
}

func TestTrackContext(t *testing.T) {
	mSample1 := metrics.MetricSample{
		Name:       "my.metric.name",
		Value:      1,
		Mtype:      metrics.GaugeType,
		Tags:       tagset.NewTags([]string{"foo", "bar"}),
		SampleRate: 1,
	}
	mSample2 := metrics.MetricSample{
		Name:       "my.metric.name",
		Value:      1,
		Mtype:      metrics.GaugeType,
		Tags:       tagset.NewTags([]string{"foo", "bar", "baz"}),
		SampleRate: 1,
	}
	mSample3 := metrics.MetricSample{ // same as mSample2, with different Host
		Name:       "my.metric.name",
		Value:      1,
		Mtype:      metrics.GaugeType,
		Tags:       tagset.NewTags([]string{"foo", "bar", "baz"}),
		Host:       "metric-hostname",
		SampleRate: 1,
	}
	expectedContext1 := Context{
		Name: mSample1.Name,
		Tags: mSample1.Tags,
	}
	expectedContext2 := Context{
		Name: mSample2.Name,
		Tags: mSample2.Tags,
	}
	expectedContext3 := Context{
		Name: mSample3.Name,
		Tags: mSample3.Tags,
		Host: mSample3.Host,
	}
	contextResolver := newContextResolver()

	// Track the 2 contexts
	contextKey1 := contextResolver.trackContext(&mSample1)
	contextKey2 := contextResolver.trackContext(&mSample2)
	contextKey3 := contextResolver.trackContext(&mSample3)

	// When we look up the 2 keys, they return the correct contexts
	context1 := contextResolver.contextsByKey[contextKey1]
	assert.Equal(t, expectedContext1.Name, context1.Name)
	assert.Equal(t, expectedContext1.Tags, context1.Tags)

	context2 := contextResolver.contextsByKey[contextKey2]
	assert.Equal(t, expectedContext2.Name, context2.Name)
	assert.Equal(t, expectedContext2.Tags, context2.Tags)

	context3 := contextResolver.contextsByKey[contextKey3]
	assert.Equal(t, expectedContext3.Name, context3.Name)
	assert.Equal(t, expectedContext3.Tags, context3.Tags)

	unknownContextKey := ckey.ContextKey(0xffffffffffffffff)
	_, ok := contextResolver.contextsByKey[unknownContextKey]
	assert.False(t, ok)
}

func TestExpireContexts(t *testing.T) {
	mSample1 := metrics.MetricSample{
		Name:       "my.metric.name",
		Value:      1,
		Mtype:      metrics.GaugeType,
		Tags:       tagset.NewTags([]string{"foo", "bar"}),
		SampleRate: 1,
	}
	mSample2 := metrics.MetricSample{
		Name:       "my.metric.name",
		Value:      1,
		Mtype:      metrics.GaugeType,
		Tags:       tagset.NewTags([]string{"foo", "bar", "baz"}),
		SampleRate: 1,
	}
	contextResolver := newTimestampContextResolver()

	// Track the 2 contexts
	contextKey1 := contextResolver.trackContext(&mSample1, 4)
	contextKey2 := contextResolver.trackContext(&mSample2, 6)

	// With an expireTimestap of 3, both contexts are still valid
	assert.Len(t, contextResolver.expireContexts(3), 0)
	_, ok1 := contextResolver.resolver.contextsByKey[contextKey1]
	_, ok2 := contextResolver.resolver.contextsByKey[contextKey2]
	assert.True(t, ok1)
	assert.True(t, ok2)

	// With an expireTimestap of 5, context 1 is expired
	expiredContextKeys := contextResolver.expireContexts(5)
	if assert.Len(t, expiredContextKeys, 1) {
		assert.Equal(t, contextKey1, expiredContextKeys[0])
	}

	// context 1 is not tracked anymore, but context 2 still is
	_, ok := contextResolver.resolver.contextsByKey[contextKey1]
	assert.False(t, ok)
	_, ok = contextResolver.resolver.contextsByKey[contextKey2]
	assert.True(t, ok)
}

func TestCountBasedExpireContexts(t *testing.T) {
	mSample1 := metrics.MetricSample{Name: "my.metric.name1"}
	mSample2 := metrics.MetricSample{Name: "my.metric.name2"}
	mSample3 := metrics.MetricSample{Name: "my.metric.name3"}
	contextResolver := newCountBasedContextResolver(2)

	contextKey1 := contextResolver.trackContext(&mSample1)
	contextKey2 := contextResolver.trackContext(&mSample2)
	require.Len(t, contextResolver.expireContexts(), 0)

	contextKey3 := contextResolver.trackContext(&mSample3)
	contextResolver.trackContext(&mSample2)
	require.Len(t, contextResolver.expireContexts(), 0)

	expiredContextKeys := contextResolver.expireContexts()
	require.ElementsMatch(t, expiredContextKeys, []ckey.ContextKey{contextKey1})

	expiredContextKeys = contextResolver.expireContexts()
	require.ElementsMatch(t, expiredContextKeys, []ckey.ContextKey{contextKey2, contextKey3})

	require.Len(t, contextResolver.expireContexts(), 0)
	require.Len(t, contextResolver.resolver.contextsByKey, 0)
}

func TestTagDeduplication(t *testing.T) {
	// TODO: this is kind of silly now
	resolver := newContextResolver()

	ckey := resolver.trackContext(&metrics.MetricSample{
		Name: "foo",
		Tags: tagset.NewTags([]string{"bar", "bar"}),
	})

	assert.Equal(t, []string{"bar"}, resolver.contextsByKey[ckey].Tags.Sorted())
}
