// SPDX-FileCopyrightText: 2026 Philip Eklöf
//
// SPDX-License-Identifier: MIT

package allowedsigners

import (
	"fmt"
	"strings"
)

// validatePatternList checks the structure of an OpenSSH pattern-list.
func validatePatternList(list string) error {
	for _, pattern := range strings.Split(list, ",") {
		if pattern == "" || pattern == "!" {
			return fmt.Errorf("empty pattern")
		}
	}
	return nil
}

// patternListMatch reports whether value matches an OpenSSH pattern-list.
// A negated match takes precedence over any positive match.
func patternListMatch(list, value string) bool {
	matched := false
	for _, pattern := range strings.Split(list, ",") {
		negated := strings.HasPrefix(pattern, "!")
		if negated {
			pattern = strings.TrimPrefix(pattern, "!")
		}
		if !wildcardMatch(pattern, value) {
			continue
		}
		if negated {
			return false
		}
		matched = true
	}
	return matched
}

// wildcardMatch implements the '*' and '?' matching used by OpenSSH. Unlike
// filesystem globs, '*' also matches path separators.
func wildcardMatch(pattern, value string) bool {
	for {
		if pattern == "" {
			return value == ""
		}
		if pattern[0] == '*' {
			pattern = strings.TrimLeft(pattern, "*")
			if pattern == "" {
				return true
			}
			for i := 0; i <= len(value); i++ {
				if wildcardMatch(pattern, value[i:]) {
					return true
				}
			}
			return false
		}
		if value == "" {
			return false
		}
		if pattern[0] != '?' && pattern[0] != value[0] {
			return false
		}
		pattern = pattern[1:]
		value = value[1:]
	}
}
