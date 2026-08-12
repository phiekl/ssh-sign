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
	missing := r == nil
	if !missing {
		switch v := reflect.ValueOf(r); v.Kind() {
		case reflect.Chan, reflect.Func, reflect.Map, reflect.Pointer, reflect.Slice:
			missing = v.IsNil()
		}
	}
	if missing {
		return fmt.Errorf("%s is required", name)
	}
	return nil
}
