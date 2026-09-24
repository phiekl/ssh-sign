// Copyright 2026 Philip Eklöf
//
// SPDX-License-Identifier: MIT

package args

import (
	"errors"
	"testing"
)

type testOpts struct {
	file    string
	ns      string
	key     string
	noNS    bool
	json    bool
	verbose int
}

func newTestSet(o *testOpts) *Set {
	s := NewSet("prog cmd")
	s.String(&o.file, "file", "f", "", "read from file")
	s.DenyEmpty("file")
	s.String(&o.ns, "namespace", "n", "file", "use namespace")
	s.Bool(&o.noNS, "no-namespace", "N", "ignore namespace")
	s.MutuallyExclusive("namespace", "no-namespace")
	s.String(&o.key, "key", "k", "", "use key")
	s.Required("key")
	s.Bool(&o.json, "json", "j", "enable JSON output")
	s.Count(&o.verbose, "verbose", "v", "be verbose")
	return s
}

func TestParseValues(t *testing.T) {
	tests := []struct {
		name string
		argv []string
		want testOpts
	}{
		{"long separate", []string{"--key", "k", "--file", "x"}, testOpts{key: "k", file: "x", ns: "file"}},
		{"long equals", []string{"--key=k", "--file=x"}, testOpts{key: "k", file: "x", ns: "file"}},
		{"long equals keeps later equals", []string{"--key=a=b"}, testOpts{key: "a=b", ns: "file"}},
		{"long takes dash value", []string{"--key", "-j"}, testOpts{key: "-j", ns: "file"}},
		{"short separate", []string{"-k", "k"}, testOpts{key: "k", ns: "file"}},
		{"short attached", []string{"-kk"}, testOpts{key: "k", ns: "file"}},
		{"short equals is literal", []string{"-k=k"}, testOpts{key: "=k", ns: "file"}},
		{"short takes dash value", []string{"-k", "-h"}, testOpts{key: "-h", ns: "file"}},
		{"cluster", []string{"-jNvvk", "k"}, testOpts{key: "k", ns: "file", noNS: true, json: true, verbose: 2}},
		{"cluster attached value", []string{"-jkk"}, testOpts{key: "k", ns: "file", json: true}},
		{"count", []string{"-k", "k", "-v", "--verbose", "-vv"}, testOpts{key: "k", ns: "file", verbose: 4}},
		{"last wins", []string{"-k", "a", "-k", "b"}, testOpts{key: "b", ns: "file"}},
		{"terminator", []string{"-k", "k", "--"}, testOpts{key: "k", ns: "file"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got testOpts
			if err := newTestSet(&got).Parse(tt.argv); err != nil {
				t.Fatalf("Parse(%q) error = %v", tt.argv, err)
			}
			if got != tt.want {
				t.Errorf("Parse(%q) = %+v, want %+v", tt.argv, got, tt.want)
			}
		})
	}
}

func TestParseShortInvalidUTF8(t *testing.T) {
	var value string
	s := NewSet("prog")
	s.String(&value, "value", "�", "", "")
	if err := s.Parse([]string{"-" + string([]byte{0xff}) + "x"}); err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if value != "x" {
		t.Errorf("value = %q, want %q", value, "x")
	}
}

func TestParseErrors(t *testing.T) {
	tests := []struct {
		name string
		argv []string
		want string
	}{
		{"unknown long", []string{"--bogus"}, "unknown flag: --bogus"},
		{"unknown long with value", []string{"--bogus=x"}, "unknown flag: --bogus"},
		{"unknown short", []string{"-x"}, "unknown shorthand flag: 'x' in -x"},
		{"unknown short in cluster", []string{"-jx"}, "unknown shorthand flag: 'x' in -jx"},
		{"long missing value", []string{"--key"}, "flag needs an argument: --key"},
		{"short missing value", []string{"-k"}, "flag needs an argument: 'k' in -k"},
		{"cluster missing value", []string{"-jk"}, "flag needs an argument: 'k' in -jk"},
		{"bool with value", []string{"--json=true"}, "flag does not take a value: --json"},
		{"count with value", []string{"--verbose=3"}, "flag does not take a value: --verbose"},
		{"triple dash", []string{"---foo"}, "bad flag syntax: ---foo"},
		{"empty long name", []string{"--=x"}, "bad flag syntax: --=x"},
		{"positional", []string{"foo"}, "no positional arguments expected"},
		{"dash positional", []string{"-"}, "no positional arguments expected"},
		{"after terminator", []string{"-k", "k", "--", "-j"}, "no positional arguments expected"},
		{"positional before required", []string{"foo"}, "no positional arguments expected"},
		{"parse error before positional", []string{"-x", "foo"}, "unknown shorthand flag: 'x' in -x"},
		{"positional stops parsing", []string{"foo", "--bogus"}, "no positional arguments expected"},
		{"required", []string{}, "missing required flag: key"},
		{"required before exclusive", []string{"-n", "a", "-N"}, "missing required flag: key"},
		{"exclusive", []string{"-k", "k", "-n", "a", "-N"}, "namespace and no-namespace are mutually exclusive flags"},
		{"exclusive with default value", []string{"-k", "k", "-n", "file", "-N"}, "namespace and no-namespace are mutually exclusive flags"},
		{"exclusive before empty", []string{"-k", "k", "-f", "", "-n", "a", "-N"}, "namespace and no-namespace are mutually exclusive flags"},
		{"empty", []string{"-k", "k", "-f", ""}, "flag/argument is empty: file"},
		{"empty long equals", []string{"-k", "k", "--file="}, "flag/argument is empty: file"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var o testOpts
			err := newTestSet(&o).Parse(tt.argv)
			if err == nil {
				t.Fatalf("Parse(%q) unexpectedly succeeded", tt.argv)
			}
			if errors.Is(err, ErrHelp) {
				t.Fatalf("Parse(%q) error = ErrHelp", tt.argv)
			}
			if err.Error() != tt.want {
				t.Errorf("Parse(%q) error = %q, want %q", tt.argv, err, tt.want)
			}
		})
	}
}

func TestParseReportsAllMissingAndEmpty(t *testing.T) {
	var a, b string
	s := NewSet("prog")
	s.String(&a, "aa", "a", "", "")
	s.String(&b, "bb", "b", "", "")
	s.Required("aa")
	s.Required("bb")
	if err := s.Parse(nil); err == nil || err.Error() != "missing required flags: aa, bb" {
		t.Errorf("Parse() error = %v", err)
	}

	s = NewSet("prog")
	s.String(&a, "aa", "a", "", "")
	s.String(&b, "bb", "b", "", "")
	s.DenyEmpty("aa")
	s.DenyEmpty("bb")
	if err := s.Parse([]string{"-a", "", "-b", ""}); err == nil ||
		err.Error() != "flags/arguments are empty: aa, bb" {
		t.Errorf("Parse() error = %v", err)
	}
}

func TestParseHelp(t *testing.T) {
	tests := [][]string{
		{"-h"},
		{"--help"},
		{"-jh"},
		{"-h", "foo"},
		{"-h", "-n", "a", "-N"},
		{"-f", "", "-h"},
	}
	for _, argv := range tests {
		var o testOpts
		if err := newTestSet(&o).Parse(argv); err != ErrHelp {
			t.Errorf("Parse(%q) error = %v, want ErrHelp", argv, err)
		}
	}

	notHelp := map[string][]string{
		"unknown flag: --bogus":            {"-h", "--bogus"},
		"no positional arguments expected": {"foo", "-h"},
	}
	for want, argv := range notHelp {
		var o testOpts
		if err := newTestSet(&o).Parse(argv); err == nil || err.Error() != want {
			t.Errorf("Parse(%q) error = %v, want %q", argv, err, want)
		}
	}
}

func TestHelp(t *testing.T) {
	var o testOpts
	want := `usage: prog cmd [option]..

options:
  -h, --help           display this help text and exit
  -f, --file           read from file
  -n, --namespace      use namespace (default "file")
  -N, --no-namespace   ignore namespace
  -k, --key            use key
  -j, --json           enable JSON output
  -v, --verbose        be verbose
`
	if got := newTestSet(&o).Help(); got != want {
		t.Errorf("Help() =\n%s\nwant\n%s", got, want)
	}
}

func TestLongOnlyHelp(t *testing.T) {
	var v string
	s := NewSet("prog")
	s.String(&v, "value", "", "", "set value")
	want := `usage: prog [option]..

options:
  -h, --help    display this help text and exit
      --value   set value
`
	if got := s.Help(); got != want {
		t.Errorf("Help() =\n%s\nwant\n%s", got, want)
	}
}

func newCommandSet() *Set {
	s := NewSet("prog")
	s.Command("inspect", "Show details")
	s.Command("sign", "Sign data")
	return s
}

func TestParseCommand(t *testing.T) {
	tests := []struct {
		argv     []string
		wantName string
		wantRest []string
	}{
		{[]string{"inspect"}, "inspect", []string{}},
		{[]string{"sign", "-k", "k", "--", "x"}, "sign", []string{"-k", "k", "--", "x"}},
		{[]string{"--", "sign", "-h"}, "sign", []string{"-h"}},
	}
	for _, tt := range tests {
		name, rest, err := newCommandSet().ParseCommand(tt.argv)
		if err != nil {
			t.Fatalf("ParseCommand(%q) error = %v", tt.argv, err)
		}
		if name != tt.wantName || len(rest) != len(tt.wantRest) {
			t.Fatalf("ParseCommand(%q) = %q, %q", tt.argv, name, rest)
		}
		for i := range rest {
			if rest[i] != tt.wantRest[i] {
				t.Errorf("ParseCommand(%q) rest = %q, want %q", tt.argv, rest, tt.wantRest)
			}
		}
	}
}

func TestParseCommandErrors(t *testing.T) {
	tests := []struct {
		argv []string
		want error
		msg  string
	}{
		{argv: nil, want: ErrUsage},
		{argv: []string{"-h"}, want: ErrHelp},
		{argv: []string{"-h", "inspect"}, want: ErrHelp},
		{argv: []string{"--"}, msg: "missing command"},
		{argv: []string{"bogus"}, msg: "invalid command: bogus"},
		{argv: []string{"--bogus"}, msg: "unknown flag: --bogus"},
		{argv: []string{"-j", "inspect"}, msg: "unknown shorthand flag: 'j' in -j"},
		{argv: []string{"-h", "--bogus"}, msg: "unknown flag: --bogus"},
	}
	for _, tt := range tests {
		_, _, err := newCommandSet().ParseCommand(tt.argv)
		if tt.want != nil {
			if err != tt.want {
				t.Errorf("ParseCommand(%q) error = %v, want %v", tt.argv, err, tt.want)
			}
			continue
		}
		if err == nil || err.Error() != tt.msg {
			t.Errorf("ParseCommand(%q) error = %v, want %q", tt.argv, err, tt.msg)
		}
	}
}

func TestCommandHelp(t *testing.T) {
	want := `usage: prog <command> [command option]..

commands:
  inspect   Show details
  sign      Sign data
`
	if got := newCommandSet().Help(); got != want {
		t.Errorf("Help() =\n%s\nwant\n%s", got, want)
	}
}

func TestDefinitionErrorsPanic(t *testing.T) {
	tests := map[string]func(s *Set){
		"duplicate long": func(s *Set) {
			var v bool
			s.Bool(&v, "help", "", "")
		},
		"duplicate short": func(s *Set) {
			var v bool
			s.Bool(&v, "other", "h", "")
		},
		"multi-rune short": func(s *Set) {
			var v bool
			s.Bool(&v, "other", "ab", "")
		},
		"undefined required":  func(s *Set) { s.Required("nope") },
		"undefined deny":      func(s *Set) { s.DenyEmpty("nope") },
		"deny on bool":        func(s *Set) { s.DenyEmpty("help") },
		"undefined exclusive": func(s *Set) { s.MutuallyExclusive("help", "nope") },
		"single exclusive":    func(s *Set) { s.MutuallyExclusive("help") },
	}
	for name, define := range tests {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Error("definition did not panic")
				}
			}()
			define(NewSet("prog"))
		})
	}
}
