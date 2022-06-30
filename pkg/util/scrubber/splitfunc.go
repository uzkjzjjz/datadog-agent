package scrubber

import "bytes"

// ScanLinesWithTrailingNewline is similar to the standard bufio.ScanLines
// with the key difference being that each token _includes_ the trailing \n
// character. Carriage returns get no special treatment and are included in
// the resulting tokens if they are present in the data.
//
// Based on https://github.com/golang/go/blob/e6c0546c54f6f3fa7c6cb5002ecc839bc89d5d20/src/bufio/scan.go#L344-L364
func ScanLinesWithTrailingNewline(data []byte, atEOF bool) (advance int, token []byte, err error) {
	if atEOF && len(data) == 0 {
		return 0, nil, nil
	}
	if i := bytes.IndexByte(data, '\n'); i >= 0 {
		// We have a full newline-terminated line.

		return i + 1, data[0 : i+1], nil
	}
	// If we're at EOF, we have a final, non-terminated line. Return it.
	if atEOF {
		return len(data), data, nil
	}
	// Request more data.
	return 0, nil, nil
}
