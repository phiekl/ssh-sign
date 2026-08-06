// SPDX-FileCopyrightText: 2026 Philip Eklöf
//
// SPDX-License-Identifier: MIT

package allowedsigners

import (
	"bufio"
	"fmt"
	"io"
	"strings"

	"pxy.se/go/ssh-sign/pkg/sshsigx"
)

type ParseError struct {
	Line int
	Msg  string
}

func (e *ParseError) Error() string {
	return fmt.Sprintf("line: %d: %s", e.Line, e.Msg)
}

// Parse reads an allowed signers file from r.
func Parse(r io.Reader) (*File, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 2*1024*1024)

	var f File
	n := 0
	for sc.Scan() {
		n++
		line := sc.Text()
		trim := strings.TrimSpace(line)
		if trim == "" {
			continue
		}
		if strings.HasPrefix(trim, "#") {
			continue
		}
		entry, err := parseLine(n, trim)
		if err != nil {
			return nil, err
		}
		f.Entries = append(f.Entries, *entry)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return &f, nil
}

// parseLine parses a single line fed from an allowed signers file.
func parseLine(n int, line string) (*Entry, error) {
	fields, err := splitFields(line)
	if err != nil {
		return nil, &ParseError{Line: n, Msg: err.Error()}
	}
	if len(fields) < 3 {
		return nil, &ParseError{
			Line: n,
			Msg:  "expected at least 3 fields: principals [options] type key",
		}
	}

	e := &Entry{Line: n, Raw: line}

	e.Principal = strings.TrimSpace(fields[0])
	if e.Principal == "" {
		return nil, &ParseError{Line: n, Msg: "empty principal"}
	}
	if err := validatePatternList(e.Principal); err != nil {
		return nil, &ParseError{Line: n, Msg: fmt.Sprintf("invalid principal pattern-list: %v", err)}
	}

	keyTypeIdx := 1
	e.Options = Options{}

	// field[1] could be either options or a key type.
	if tokenIsOption(fields[1]) {
		opts, err := parseOptions(fields[1])
		if err != nil {
			return nil, &ParseError{Line: n, Msg: err.Error()}
		}
		e.Options = opts
		keyTypeIdx = 2
	}

	if len(fields) <= keyTypeIdx+1 {
		return nil, &ParseError{Line: n, Msg: "missing type/key fields"}
	}

	e.KeyType = fields[keyTypeIdx]
	e.KeyBase64 = fields[keyTypeIdx+1]

	// Validate/parse key.
	pk, err := sshsigx.PublicKeyParse(e.KeyBase64)
	if err != nil {
		return nil, &ParseError{Line: n, Msg: fmt.Sprintf("invalid ssh public key: %v", err)}
	}
	// Ensure that the defined keytype in the line matches.
	if pk.Type() != e.KeyType {
		return nil, &ParseError{
			Line: n,
			Msg:  fmt.Sprintf("key type mismatch: defined %q but parsed %q", e.KeyType, pk.Type()),
		}
	}
	e.PublicKey = pk

	if len(fields) > keyTypeIdx+2 {
		e.Comment = strings.Join(fields[keyTypeIdx+2:], " ")
	}
	return e, nil
}

// parseOptions parses the options fields in an allowed signers line.
func parseOptions(s string) (Options, error) {
	var o Options
	if strings.TrimSpace(s) == "" {
		return o, nil
	}

	parts, err := splitOptions(s)
	if err != nil {
		return o, err
	}

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if strings.EqualFold(part, "cert-authority") {
			return o, fmt.Errorf("%q option is not yet supported", part)
		}

		k, v, ok := strings.Cut(part, "=")
		if !ok {
			return o, fmt.Errorf("unknown option %q", part)
		}

		key := strings.ToLower(strings.TrimSpace(k))
		val := strings.TrimSpace(v)
		val, err = unquoteOptionValue(val)
		if err != nil {
			return o, fmt.Errorf("option %s: %w", key, err)
		}

		switch key {
		case "namespaces":
			if err := validatePatternList(val); err != nil {
				return o, fmt.Errorf("namespaces: invalid pattern-list: %v", err)
			}
			for _, ns := range strings.Split(val, ",") {
				o.Namespaces = append(o.Namespaces, ns)
			}
		case "valid-after":
			t, err := ParseTimestamp(val)
			if err != nil {
				return o, fmt.Errorf("valid-after: %w", err)
			}
			o.ValidAfter = &t
		case "valid-before":
			t, err := ParseTimestamp(val)
			if err != nil {
				return o, fmt.Errorf("valid-before: %w", err)
			}
			o.ValidBefore = &t
		default:
			return o, fmt.Errorf("unsupported option %q", k)
		}
	}
	return o, nil
}

// splitFields splits on spaces/tabs, but keeps quoted substrings together.
func splitFields(line string) ([]string, error) {
	var out []string
	var b strings.Builder

	flush := func() {
		if b.Len() > 0 {
			out = append(out, b.String())
			b.Reset()
		}
	}

	inQuote := false
	escaped := false
	for i := 0; i < len(line); i++ {
		ch := line[i]

		if escaped {
			b.WriteByte(ch)
			escaped = false
			continue
		}
		if inQuote && ch == '\\' {
			escaped = true
			continue
		}
		if ch == '"' {
			inQuote = !inQuote
			b.WriteByte(ch)
			continue
		}
		if !inQuote && (ch == ' ' || ch == '\t') {
			flush()
			// consume additional whitespace
			for i+1 < len(line) && (line[i+1] == ' ' || line[i+1] == '\t') {
				i++
			}
			continue
		}
		b.WriteByte(ch)
	}
	if inQuote {
		return nil, fmt.Errorf("unterminated quote")
	}
	flush()
	return out, nil
}

// splitOptions splits on comma, while ignoring quoted commas.
func splitOptions(s string) ([]string, error) {
	var out []string
	var b strings.Builder
	inQuote := false
	escaped := false

	flush := func() {
		out = append(out, b.String())
		b.Reset()
	}

	for i := 0; i < len(s); i++ {
		ch := s[i]
		if escaped {
			b.WriteByte(ch)
			escaped = false
			continue
		}
		if inQuote && ch == '\\' {
			escaped = true
			continue
		}
		if ch == '"' {
			inQuote = !inQuote
			b.WriteByte(ch)
			continue
		}
		if !inQuote && ch == ',' {
			flush()
			continue
		}
		b.WriteByte(ch)
	}
	if inQuote {
		return nil, fmt.Errorf("unterminated quote in options")
	}
	flush()
	return out, nil
}

// tokenIsOption checks if a token looks like an option.
func tokenIsOption(s string) bool {
	// This is the only standalone option not containing '='.
	if strings.EqualFold(s, "cert-authority") {
		return true
	}
	// A string that matches [",=] should be an option.
	if strings.ContainsAny(s, "\",=") {
		return true
	}
	return false
}

// unquoteOptionValue removes quoting and unescapes escaped characters in an option value.
func unquoteOptionValue(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", nil
	}
	if s[0] != '"' {
		return s, nil
	}
	if len(s) < 2 || s[len(s)-1] != '"' {
		return "", fmt.Errorf("unterminated quoted string")
	}
	inner := s[1 : len(s)-1]
	inner = strings.ReplaceAll(inner, `\"`, `"`)
	inner = strings.ReplaceAll(inner, `\\`, `\`)
	return inner, nil
}
