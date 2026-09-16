// SPDX-FileCopyrightText: 2026 Philip Eklöf
//
// SPDX-License-Identifier: MIT

// Package allowedsigners parses and matches OpenSSH allowed signers files.
// Some validation rules are stricter than ssh-keygen's.
package allowedsigners

import (
	"bufio"
	"fmt"
	"io"
	"strings"
	"unicode"
	"unicode/utf8"

	"pxy.se/go/ssh-sign/pkg/sshsig"
)

// maxLineSize limits memory use while allowing large certificates and comments.
const maxLineSize = 4 << 20

// maxSkippedRecorded caps retained diagnostics for malformed input.
const maxSkippedRecorded = 64

// whitespace lists field separators. Unicode spaces belong to identities.
// Tabs are allowed; other non-graphic characters are rejected before parsing.
const whitespace = " \t"

// trimSeparators removes leading and trailing spaces and tabs.
func trimSeparators(s string) string {
	return strings.Trim(s, whitespace)
}

// skip counts a malformed line and records its error up to the limit.
func (f *File) skip(perr ParseError) {
	f.SkippedCount++
	if len(f.Skipped) < maxSkippedRecorded {
		f.Skipped = append(f.Skipped, perr)
	}
}

// ParseError describes a malformed line that parsing skipped.
type ParseError struct {
	Line int
	Msg  string
}

func (e *ParseError) Error() string {
	return fmt.Sprintf("line=%d: %s", e.Line, e.Msg)
}

// Parse reads an allowed signers file from r.
func Parse(r io.Reader) (*File, error) {
	return parseWithMaxLineSize(r, maxLineSize)
}

func parseWithMaxLineSize(r io.Reader, maxLineSize int) (*File, error) {
	sc := bufio.NewScanner(r)
	// Scanner may need to buffer the line delimiter (or probe for EOF) in
	// addition to the token itself.
	bufferSize := min(64*1024, maxLineSize+1)
	sc.Buffer(make([]byte, 0, bufferSize), maxLineSize+1)

	var f File
	n := 0
	for sc.Scan() {
		n++
		line := sc.Text()
		if err := validateLineCharacters(line); err != nil {
			f.skip(ParseError{Line: n, Msg: err.Error()})
			continue
		}
		trim := trimSeparators(line)
		if trim == "" {
			continue
		}
		if strings.HasPrefix(trim, "#") {
			continue
		}
		entry, perr := parseLine(n, trim)
		if perr != nil {
			f.skip(*perr)
			continue
		}
		f.Entries = append(f.Entries, *entry)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return &f, nil
}

// validateLineCharacters checks the whole line, including comments.
// unicode.IsGraphic accepts Unicode spaces, letters, marks, numbers,
// punctuation and symbols.
func validateLineCharacters(line string) error {
	if !utf8.ValidString(line) {
		return fmt.Errorf("line contains invalid UTF-8")
	}
	for _, r := range line {
		switch {
		case r == '\t':
			continue
		case r == 0:
			return fmt.Errorf("line contains a NUL byte")
		case r == '\r':
			return fmt.Errorf("line contains a carriage return")
		case !unicode.IsGraphic(r):
			return fmt.Errorf("line contains a non-printable character U+%04X", r)
		}
	}
	return nil
}

// parseLine parses a single line fed from an allowed signers file.
func parseLine(n int, line string) (*Entry, *ParseError) {
	head, _, err := splitFields(line, 2)
	if err != nil {
		return nil, &ParseError{Line: n, Msg: err.Error()}
	}
	if len(head) < 2 {
		return nil, &ParseError{
			Line: n,
			Msg:  "expected at least 3 fields: principals [options] type key",
		}
	}
	fieldCount := 3
	if tokenIsOption(head[1]) {
		fieldCount = 4
	}
	fields, comment, err := splitFields(line, fieldCount)
	if err != nil {
		return nil, &ParseError{Line: n, Msg: err.Error()}
	}
	if len(fields) < fieldCount {
		return nil, &ParseError{Line: n, Msg: "missing type/key fields"}
	}

	e := &Entry{Line: n}

	e.Principal, err = unquotePrincipals(fields[0])
	if err != nil {
		return nil, &ParseError{Line: n, Msg: fmt.Sprintf("principals: %v", err)}
	}
	if e.Principal == "" {
		return nil, &ParseError{Line: n, Msg: "empty principal"}
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
	pk, err := sshsig.ParsePublicKey(e.KeyBase64)
	if err != nil {
		return nil, &ParseError{Line: n, Msg: fmt.Sprintf("invalid ssh public key: %v", err)}
	}
	// Ensure that the defined keytype in the line matches.
	if pk.Type() != e.KeyType {
		return nil, &ParseError{
			Line: n,
			Msg: fmt.Sprintf("key type mismatch: defined %s but parsed %q",
				sshsig.QuoteToken(e.KeyType), pk.Type()),
		}
	}
	e.PublicKey = pk

	e.Comment = comment
	return e, nil
}

// parseOptions parses the options fields in an allowed signers line.
func parseOptions(s string) (Options, error) {
	var o Options
	if trimSeparators(s) == "" {
		return o, nil
	}

	parts, err := splitOptions(s)
	if err != nil {
		return o, err
	}

	for _, part := range parts {
		part = trimSeparators(part)
		if part == "" {
			return o, fmt.Errorf("empty option")
		}
		if strings.EqualFold(part, "cert-authority") {
			return o, fmt.Errorf("%q option is not yet supported", part)
		}

		k, v, ok := strings.Cut(part, "=")
		if !ok {
			return o, fmt.Errorf("unknown option %s", sshsig.QuoteToken(part))
		}

		key := strings.ToLower(trimSeparators(k))
		val := trimSeparators(v)
		val, err = unquoteOptionValue(val)
		if err != nil {
			return o, fmt.Errorf("option %s: %w", sshsig.QuoteToken(key), err)
		}

		switch key {
		case "namespaces":
			if o.Namespaces != nil {
				return o, fmt.Errorf("multiple %q clauses", key)
			}
			o.Namespaces = append(o.Namespaces, strings.Split(val, ",")...)
		case "valid-after":
			if o.ValidAfter != nil {
				return o, fmt.Errorf("multiple %q clauses", key)
			}
			t, err := ParseKeygenTimestamp(val)
			if err != nil {
				return o, fmt.Errorf("valid-after: %w", err)
			}
			o.ValidAfter = &t
		case "valid-before":
			if o.ValidBefore != nil {
				return o, fmt.Errorf("multiple %q clauses", key)
			}
			t, err := ParseKeygenTimestamp(val)
			if err != nil {
				return o, fmt.Errorf("valid-before: %w", err)
			}
			o.ValidBefore = &t
		default:
			return o, fmt.Errorf("unsupported option %s", sshsig.QuoteToken(k))
		}
	}
	if o.ValidAfter != nil && o.ValidBefore != nil && !o.ValidBefore.After(*o.ValidAfter) {
		return o, fmt.Errorf("%q time is not after %q", "valid-before", "valid-after")
	}
	return o, nil
}

// splitFields returns at most limit whitespace-separated fields, keeping quoted
// substrings together. Once the limit is reached, the remainder is returned
// without interpreting it so an opaque key comment cannot affect parsing.
func splitFields(line string, limit int) ([]string, string, error) {
	var out []string
	var b strings.Builder

	flush := func() bool {
		if b.Len() > 0 {
			out = append(out, b.String())
			b.Reset()
		}
		return len(out) == limit
	}

	inQuote := false
	for i := 0; i < len(line); i++ {
		ch := line[i]

		if inQuote && isEscapedQuote(line, i) {
			b.WriteByte(ch)
			i++
			b.WriteByte(line[i])
			continue
		}
		if ch == '"' {
			inQuote = !inQuote
			b.WriteByte(ch)
			continue
		}
		if !inQuote && strings.IndexByte(whitespace, ch) >= 0 {
			complete := flush()
			// consume additional whitespace
			for i+1 < len(line) && strings.IndexByte(whitespace, line[i+1]) >= 0 {
				i++
			}
			if complete {
				return out, line[i+1:], nil
			}
			continue
		}
		b.WriteByte(ch)
	}
	if inQuote {
		return nil, "", fmt.Errorf("unterminated quote")
	}
	flush()
	return out, "", nil
}

// splitOptions splits on comma, while ignoring quoted commas.
func splitOptions(s string) ([]string, error) {
	var out []string
	var b strings.Builder
	inQuote := false

	flush := func() {
		out = append(out, b.String())
		b.Reset()
	}

	for i := 0; i < len(s); i++ {
		ch := s[i]
		if inQuote && isEscapedQuote(s, i) {
			b.WriteByte(ch)
			i++
			b.WriteByte(s[i])
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

// isEscapedQuote reports whether s[i] is a backslash escaping a quote.
func isEscapedQuote(s string, i int) bool {
	return s[i] == '\\' && i+1 < len(s) && s[i+1] == '"'
}

// unquoteOptionValue removes quoting and unescapes escaped characters in an option value.
func unquoteOptionValue(s string) (string, error) {
	s = trimSeparators(s)
	if s == "" {
		return "", nil
	}
	if s[0] != '"' {
		return "", fmt.Errorf("missing start quote")
	}
	return unquote(s)
}

// unquotePrincipals removes the first quote pair, as OpenSSH does.
// For example, !"alice" excludes alice. Reject text after the closing quote,
// since OpenSSH treats it as the next field and rejects the line.
func unquotePrincipals(s string) (string, error) {
	open := strings.IndexByte(s, '"')
	if open < 0 {
		return s, nil
	}
	rest := s[open+1:]
	closing := strings.IndexByte(rest, '"')
	if closing < 0 {
		return "", fmt.Errorf("unterminated quoted string")
	}
	if closing != len(rest)-1 {
		return "", fmt.Errorf("data follows the closing quote")
	}
	return s[:open] + rest[:closing], nil
}

// unquote removes surrounding quotes and unescapes quotes within them.
// Reject unescaped interior quotes: splicing `namespaces="a","b"` would
// authorise a namespace from a line ssh-keygen rejects.
func unquote(s string) (string, error) {
	if len(s) < 2 || s[len(s)-1] != '"' {
		return "", fmt.Errorf("unterminated quoted string")
	}

	inner := s[1 : len(s)-1]
	var b strings.Builder
	for i := 0; i < len(inner); i++ {
		if isEscapedQuote(inner, i) {
			i++
		} else if inner[i] == '"' {
			return "", fmt.Errorf("unescaped quote inside a quoted string")
		}
		b.WriteByte(inner[i])
	}
	return b.String(), nil
}
