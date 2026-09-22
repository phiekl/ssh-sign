// Copyright 2026 Philip Eklöf
//
// SPDX-License-Identifier: MIT

package cmd

import (
	"bytes"
	"fmt"
	"io"

	"pxy.se/go/ssh-sign/pkg/sshsig"
)

// signatureStdinReader accepts whitespace-only lines before a pasted signature.
// SignatureRead handles trailing whitespace for both stdin and files.
type signatureStdinReader struct {
	source io.Reader
	data   *bytes.Reader
	err    error
}

func (r *signatureStdinReader) Read(p []byte) (int, error) {
	if r.data == nil && r.err == nil {
		const maxWhitespace = 1024
		data, err := io.ReadAll(io.LimitReader(r.source, sshsig.MaxSignatureArmorSize+1))
		if err != nil {
			r.err = err
			return 0, err
		}
		if len(data) > sshsig.MaxSignatureArmorSize {
			r.err = fmt.Errorf("read data exceeds %d bytes", sshsig.MaxSignatureArmorSize)
			return 0, r.err
		}

		start := len(data) - len(bytes.TrimLeft(data, " \t\r\n"))
		if start == len(data) {
			r.data = bytes.NewReader(nil)
			return r.data.Read(p)
		}
		if start > maxWhitespace {
			r.err = fmt.Errorf("unarmoring data failed: too much leading whitespace")
			return 0, r.err
		}
		// The header must still start at the beginning of a line.
		if start > 0 && data[start-1] != '\n' {
			r.err = fmt.Errorf("unarmoring data failed: signature header is not at the beginning of a line")
			return 0, r.err
		}
		r.data = bytes.NewReader(data[start:])
	}
	if r.err != nil {
		return 0, r.err
	}
	return r.data.Read(p)
}
