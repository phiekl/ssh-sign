// SPDX-FileCopyrightText: 2026 Philip Eklöf
//
// SPDX-License-Identifier: MIT

//go:build linux && landlocktsync

package landlock

import "testing"

// TestTSyncMinimumMatchesGoLandlock pins our reporting mirror to go-landlock's
// best-effort behavior below the ABI required by the landlocktsync build tag.
func TestTSyncMinimumMatchesGoLandlock(t *testing.T) {
	status, err := detectedABI()
	if err != nil {
		t.Skipf("landlock is unavailable: %v", err)
	}
	if status.adjusted >= minimumRequiredABI {
		t.Skipf("adjusted ABI %d meets the tagged minimum", status.adjusted)
	}
	if status.effective != 0 {
		t.Fatalf("effective ABI = %d below tagged minimum ABI %d",
			status.effective, minimumRequiredABI,
		)
	}
	if got := runChild(t, "best-effort-open", targetFile(t)); got != "ok" {
		t.Errorf("best-effort access below tagged minimum = %q, want %q", got, "ok")
	}
}
