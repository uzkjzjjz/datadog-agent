// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package scrubber

import (
	"io/ioutil"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRepl(t *testing.T) {
	scrubber := New()
	scrubber.AddReplacer(SingleLine, Replacer{
		Regex: regexp.MustCompile("foo"),
		Repl:  []byte("bar"),
	})
	res, err := scrubber.ScrubBytes([]byte("dog food"))
	require.NoError(t, err)
	require.Equal(t, "dog bard", string(res))
}

func TestReplFunc(t *testing.T) {
	scrubber := New()
	scrubber.AddReplacer(SingleLine, Replacer{
		Regex: regexp.MustCompile("foo"),
		ReplFunc: func(match []byte) []byte {
			return []byte(strings.ToUpper(string(match)))
		},
	})
	res, err := scrubber.ScrubBytes([]byte("dog food"))
	require.NoError(t, err)
	require.Equal(t, "dog FOOd", string(res))
}

func TestChainedReplaces(t *testing.T) {
	scrubber := New()
	scrubber.AddReplacer(SingleLine, Replacer{
		Regex: regexp.MustCompile("foo"),
		Repl:  []byte("bar"),
	})
	scrubber.AddReplacer(MultiLine, Replacer{
		Regex: regexp.MustCompile("with bar"),
		Repl:  []byte("..."),
	})
	res, err := scrubber.ScrubBytes([]byte("a line with foo"))
	require.NoError(t, err)
	require.Equal(t, "a line ...", string(res))
}

func TestCleanFile(t *testing.T) {
	dir := t.TempDir()
	filename := filepath.Join(dir, "test.yml")
	ioutil.WriteFile(filename, []byte("a line with foo\na line with bar"), 0666)

	scrubber := New()
	scrubber.AddReplacer(SingleLine, Replacer{
		Regex: regexp.MustCompile("foo"),
		Repl:  []byte("bar"),
	})
	res, err := scrubber.ScrubFile(filename)
	require.NoError(t, err)
	require.Equal(t, "a line with bar\na line with bar", string(res))
}

func TestScrubLine(t *testing.T) {
	scrubber := New()
	scrubber.AddReplacer(SingleLine, Replacer{
		Regex: regexp.MustCompile(`([A-Za-z][A-Za-z0-9+-.]+\:\/\/|\b)([^\:]+)\:([^\s]+)\@`),
		Repl:  []byte(`$1$2:********@`),
	})
	// this replacer should not be used on URLs!
	scrubber.AddReplacer(MultiLine, Replacer{
		Regex: regexp.MustCompile(".*"),
		Repl:  []byte("UHOH"),
	})
	res := scrubber.ScrubLine("https://foo:bar@example.com")
	require.Equal(t, "https://foo:********@example.com", res)
}

func TestSimpleComment(t *testing.T) {

	scrubber := New()
	cleaned, err := scrubber.ScrubBytes([]byte("hello\n#comment\nworld"))
	assert.Nil(t, err)
	cleanedString := string(cleaned)
	assert.Equal(t, "hello\nworld", cleanedString)
}

func TestNewlineBehavior(t *testing.T) {
	cases := []struct {
		input    string
		expected string
	}{
		{
			input:    "\nhelloworld\n",
			expected: "\nhelloworld\n",
		},
		{
			input:    "\nhelloworld",
			expected: "\nhelloworld",
		},
		{
			input:    "helloworld\n",
			expected: "helloworld\n",
		},
		{
			input:    "hello\nworld",
			expected: "hello\nworld",
		},
		{
			input:    "hello\nbig\nworld",
			expected: "hello\nbig\nworld",
		},
		{
			input:    "hello\n   \nworld",
			expected: "hello\n   \nworld",
		},
		{
			input:    "hello\n  \n \nworld",
			expected: "hello\n  \n \nworld",
		},
		{
			input:    "==\nComponentName\n==\n\nData About Component",
			expected: "==\nComponentName\n==\n\nData About Component",
		},
		{
			input:    "\n\n\nhelloworld",
			expected: "\n\n\nhelloworld",
		},
		{
			input:    "helloworld\n\n\n",
			expected: "helloworld\n\n\n",
		},
		{
			input:    "\n",
			expected: "\n",
		},
	}

	scrubber := New()
	for _, tc := range cases {
		cleaned, err := scrubber.ScrubBytes([]byte(tc.input))
		assert.Nil(t, err)
		cleanedString := string(cleaned)
		assert.Equal(t, tc.expected, cleanedString)
	}
}
