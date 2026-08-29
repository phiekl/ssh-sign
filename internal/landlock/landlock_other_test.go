// SPDX-FileCopyrightText: 2026 Philip Eklöf
//
// SPDX-License-Identifier: MIT

//go:build !linux

package landlock

import "testing"

func TestUnavailableWithoutLandlock(t *testing.T) {
	if Available() {
		t.Error("Available() = true on a platform without landlock")
	}
}
