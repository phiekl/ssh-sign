// Copyright 2026 Philip Eklöf
//
// SPDX-License-Identifier: MIT

package flow

import (
	"strings"
	"testing"
)

func TestFlowsRejectNilOptions(t *testing.T) {
	tests := map[string]func() (bool, []error){
		"sign": func() (bool, []error) {
			result, err := Sign(nil)
			return result == nil, []error{err}
		},
		"check": func() (bool, []error) {
			result, errs := Check(nil)
			return result == nil, errs
		},
		"verify": func() (bool, []error) {
			result, errs := Verify(nil)
			return result == nil, errs
		},
		"inspect": func() (bool, []error) {
			result, err := Inspect(nil)
			return result == nil, []error{err}
		},
	}

	for name, run := range tests {
		t.Run(name, func(t *testing.T) {
			resultNil, errs := run()
			if !resultNil {
				t.Error("result is non-nil, want nil")
			}
			if len(errs) != 1 || !strings.Contains(errs[0].Error(), "options are required") {
				t.Errorf("errors = %v, want an options-required error", errs)
			}
		})
	}
}
