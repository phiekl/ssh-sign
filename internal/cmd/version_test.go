// Copyright 2026 Philip Eklöf
//
// SPDX-License-Identifier: MIT

package cmd

import (
	"runtime/debug"
	"testing"
)

func TestResolveVersion(t *testing.T) {
	info := func(version string) *debug.BuildInfo {
		return &debug.BuildInfo{Main: debug.Module{Version: version}}
	}
	tests := []struct {
		name string
		set  string
		info *debug.BuildInfo
		ok   bool
		want string
	}{
		{"set at link time", "v0.2.0-41-gabcdef0", info("v0.2.1-0.20260925171037-f64cf8691b51"), true, "v0.2.0-41-gabcdef0"},
		{"module version", "", info("v0.2.1-0.20260925171037-f64cf8691b51+dirty"), true, "v0.2.1-0.20260925171037-f64cf8691b51+dirty"},
		{"devel", "", info("(devel)"), true, "unknown"},
		{"empty module version", "", info(""), true, "unknown"},
		{"no build info", "", nil, false, "unknown"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := resolveVersion(tt.set, tt.info, tt.ok); got != tt.want {
				t.Errorf("resolveVersion() = %q, want %q", got, tt.want)
			}
		})
	}
}
