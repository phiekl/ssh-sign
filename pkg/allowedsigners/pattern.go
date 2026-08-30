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
func patternListMatch(list, value string) bool {
	return patternsMatch(strings.Split(list, ","), value)
}

// patternsMatch reports whether value matches an already split pattern-list.
// A negated match takes precedence over any positive match.
func patternsMatch(patterns []string, value string) bool {
	matched := false
	for _, pattern := range patterns {
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

// wildcardMatch implements OpenSSH's '*' and '?' matching, including slashes.
// A single backtrack point avoids exponential recursion. Handle '*' before
// literal equality so "*blocked" matches "*xblocked" and exclusions hold.
func wildcardMatch(pattern, value string) bool {
	var p, v int
	// star is the pattern index of the most recent '*', and mark how much of
	// value it has been allowed to consume so far.
	star, mark := -1, 0

	for v < len(value) {
		switch {
		case p < len(pattern) && pattern[p] == '*':
			star = p
			p++
			mark = v
		case p < len(pattern) && (pattern[p] == '?' || pattern[p] == value[v]):
			p++
			v++
		case star >= 0:
			// Let the last '*' swallow one more byte and retry from there.
			p = star + 1
			mark++
			v = mark
		default:
			return false
		}
	}

	// Any trailing '*' can match the empty remainder.
	for p < len(pattern) && pattern[p] == '*' {
		p++
	}
	return p == len(pattern)
}
