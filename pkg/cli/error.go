// Copyright 2026 Philip Eklöf
//
// SPDX-License-Identifier: MIT

package cli

import "errors"

// UsageError marks an error caused by an invalid command invocation rather
// than a failure encountered while carrying out a valid invocation.
type UsageError struct {
	Err error
}

func (e *UsageError) Error() string {
	return e.Err.Error()
}

func (e *UsageError) Unwrap() error {
	return e.Err
}

// MarkUsage marks err as an invalid-invocation error.
func MarkUsage(err error) error {
	return &UsageError{Err: err}
}

// IsUsageError reports whether err or one of its causes is a UsageError.
func IsUsageError(err error) bool {
	var usageErr *UsageError
	return errors.As(err, &usageErr)
}
