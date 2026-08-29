// Copyright 2026 Philip Eklöf
//
// SPDX-License-Identifier: MIT

package flow

import (
	"fmt"
	"io"
	"reflect"
)

func requireReader(r io.Reader, name string) error {
	if isNil(r) {
		return fmt.Errorf("%s is required", name)
	}
	return nil
}

func isNil(value any) bool {
	if value == nil {
		return true
	}
	switch v := reflect.ValueOf(value); v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Map, reflect.Pointer, reflect.Slice:
		return v.IsNil()
	}
	return false
}
