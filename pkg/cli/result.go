// Copyright 2026 Philip Eklöf
//
// SPDX-License-Identifier: MIT

package cli

import (
	"encoding/json"
	"fmt"
	"reflect"
)

// Result holds a command's data and errors.
type Result struct {
	Data  fmt.Stringer
	Error []error
}

// NewResult drops nil errors and nil data, including typed nil pointers.
func NewResult(data fmt.Stringer, errs []error) Result {
	var res Result
	if !isNil(data) {
		res.Data = data
	}
	for _, err := range errs {
		if !isNil(err) {
			res.Error = append(res.Error, err)
		}
	}
	return res
}

// MarshalJSON puts error strings under "error" and data under "result".
func (r Result) MarshalJSON() ([]byte, error) {
	var errs []string
	for _, err := range r.Error {
		errs = append(errs, err.Error())
	}
	return json.Marshal(&struct {
		Error  []string     `json:"error,omitempty"`
		Result fmt.Stringer `json:"result,omitempty"`
	}{errs, r.Data})
}

func isNil(v any) bool {
	if v == nil {
		return true
	}
	rv := reflect.ValueOf(v)
	return rv.Kind() == reflect.Pointer && rv.IsNil()
}
