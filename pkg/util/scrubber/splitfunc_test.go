package scrubber

import (
	"bufio"
	"strings"
	"testing"
)

func TestScanLinesWithTrailingNewline(t *testing.T) {
	cases := []struct {
		input         string
		expectedLines []string
	}{
		{
			input:         "lineone\nlinetwo\nlinethree\n",
			expectedLines: []string{"lineone\n", "linetwo\n", "linethree\n"},
		},
		{
			input:         "lineone\n",
			expectedLines: []string{"lineone\n"},
		},
		{
			input:         "a\n\n\n",
			expectedLines: []string{"a\n", "\n", "\n"},
		},
		{
			input:         "",
			expectedLines: []string{""},
		},
		{
			input:         "\n\n\n\n",
			expectedLines: []string{"\n", "\n", "\n", "\n"},
		},
		{
			input:         "\n\n\r\n",
			expectedLines: []string{"\n", "\n", "\r\n"},
		},
		{
			input:         "\r\r\r\n",
			expectedLines: []string{"\r\r\r\n"},
		},
		{
			input:         "lineone",
			expectedLines: []string{"lineone"},
		},
		{
			input:         "lineone\n    ",
			expectedLines: []string{"lineone\n", "    "},
		},
	}

	for _, tc := range cases {
		buf := strings.NewReader(tc.input)

		s := bufio.NewScanner(buf)
		s.Split(ScanLinesWithTrailingNewline)
		for lineNum := 0; s.Scan(); lineNum++ {
			line := tc.expectedLines[lineNum]
			if s.Text() != line {
				t.Errorf("%d: bad line: %d %d\n%.100q\n%.100q\n", lineNum, len(s.Bytes()), len(line), s.Bytes(), line)
			}
		}
		err := s.Err()
		if err != nil {
			t.Fatal(err)
		}
	}
}
