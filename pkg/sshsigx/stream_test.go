// Copyright 2026 Philip Eklöf
//
// SPDX-License-Identifier: MIT

package sshsigx

import (
	"errors"
	"io"
	"strings"
	"testing"
)

var errStream = errors.New("stream failed")

type errorAfterReader struct {
	data []byte
}

func (r *errorAfterReader) Read(p []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, errStream
	}
	n := copy(p, r.data)
	r.data = r.data[n:]
	return n, nil
}

func TestSignatureOperationsReturnReaderErrors(t *testing.T) {
	t.Run("create", func(t *testing.T) {
		_, err := SignatureCreate(newSigner(t), "file", &errorAfterReader{data: []byte("partial")})
		if !errors.Is(err, errStream) {
			t.Fatalf("SignatureCreate() error = %v, want stream error", err)
		}
	})

	t.Run("read", func(t *testing.T) {
		_, err := SignatureRead(&errorAfterReader{data: []byte("partial")})
		if !errors.Is(err, errStream) {
			t.Fatalf("SignatureRead() error = %v, want stream error", err)
		}
	})

	t.Run("verify", func(t *testing.T) {
		sig, err := SignatureCreate(newSigner(t), "file", strings.NewReader("data"))
		if err != nil {
			t.Fatalf("SignatureCreate() error = %v", err)
		}
		err = SignatureVerify(&errorAfterReader{data: []byte("partial")}, sig)
		if !errors.Is(err, errStream) {
			t.Fatalf("SignatureVerify() error = %v, want stream error", err)
		}
	})
}

var _ io.Reader = (*errorAfterReader)(nil)
