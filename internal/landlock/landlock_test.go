// SPDX-FileCopyrightText: 2026 Philip Eklöf
//
// SPDX-License-Identifier: MIT

package landlock

import (
	"errors"
	"os"
	"testing"
)

// available reports whether Landlock can enforce a policy with this build
// and kernel.
func available() bool {
	status, err := detectedABI()
	return err == nil && status.effective > 0
}

func TestEffectiveABI(t *testing.T) {
	want := func(abi int) int {
		if abi < minimumRequiredABI {
			return 0
		}
		return abi
	}
	tests := map[string]struct {
		kernel    int
		errata    int
		errataErr error
		want      int
	}{
		"before scoped rights":    {kernel: 5, want: want(5)},
		"scope erratum unfixed":   {kernel: 6, want: want(5)},
		"new ABI erratum unfixed": {kernel: 9, want: want(5)},
		"errata query failed":     {kernel: 6, errataErr: errors.New("query failed"), want: want(5)},
		"scope erratum fixed":     {kernel: 6, errata: signalScopeErrata, want: want(6)},
		"policy cap":              {kernel: 11, errata: signalScopeErrata, want: targetABI},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if got := abiStatusFor(tt.kernel, tt.errata, tt.errataErr).effective; got != tt.want {
				t.Errorf("abiStatusFor().effective = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestRestrictWithoutKernelSupport(t *testing.T) {
	if available() {
		t.Skip("landlock is available here, so its absence cannot be observed")
	}

	// Unsupported Landlock is a no-op.
	if err := Restrict(nil); err != nil {
		t.Fatalf("Restrict() error = %v, want it waived", err)
	}
	if _, err := os.ReadFile("landlock.go"); err != nil {
		t.Errorf("reading a file after a waived Restrict(): %v", err)
	}
}
