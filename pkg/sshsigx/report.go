// Copyright 2026 Philip Eklöf
//
// SPDX-License-Identifier: MIT

package sshsigx

import (
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Limits for untrusted data echoed in errors.
const (
	maxQuotedToken  = 256
	maxBoundedError = 512
)

// QuoteToken renders an untrusted token for a message.
func QuoteToken(s string) string {
	if len(s) <= maxQuotedToken {
		return strconv.Quote(s)
	}
	return fmt.Sprintf("%s... (%d bytes total)", strconv.Quote(s[:maxQuotedToken]), len(s))
}

// boundedError truncates a message while preserving its cause.
func boundedError(err error) error {
	msg := err.Error()
	if len(msg) <= maxBoundedError {
		return err
	}
	// Cutting by byte can split a multibyte rune, so drop a partial tail.
	cut := strings.TrimRightFunc(msg[:maxBoundedError], func(r rune) bool {
		return r == utf8.RuneError
	})
	return &truncatedError{
		err: err,
		msg: fmt.Sprintf("%s... (%d bytes total)", cut, len(msg)),
	}
}

type truncatedError struct {
	err error
	msg string
}

func (e *truncatedError) Error() string { return e.msg }

func (e *truncatedError) Unwrap() error { return e.err }
