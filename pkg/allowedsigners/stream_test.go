// Copyright 2026 Philip Eklöf
//
// SPDX-License-Identifier: MIT

package allowedsigners

import (
	"errors"
	"testing"
)

func TestParseReturnsReaderErrorAfterCompleteLine(t *testing.T) {
	want := errors.New("reader failed")
	reader := &parseErrorReader{
		data: []byte("alice@example.com " + testKey + "\n"),
		err:  want,
	}
	if _, err := Parse(reader); !errors.Is(err, want) {
		t.Fatalf("Parse() error = %v, want reader error", err)
	}
}

type parseErrorReader struct {
	data []byte
	err  error
}

func (r *parseErrorReader) Read(p []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, r.err
	}
	n := copy(p, r.data)
	r.data = r.data[n:]
	return n, nil
}
