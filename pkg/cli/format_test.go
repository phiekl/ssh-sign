// Copyright 2026 Philip Eklöf
//
// SPDX-License-Identifier: MIT

package cli

import (
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"
)

type sample struct {
	Name    string `json:"name"`
	Count   int    `json:"count"`
	Skipped string `json:"-"`
}

func TestResultFormatKV(t *testing.T) {
	got := ResultFormatKV(
		sample{Name: "alice", Count: 3, Skipped: "hidden"},
		-6, " ", "= ", "",
		"name", "count",
	)
	want := " name  = alice\n count = 3"
	if got != want {
		t.Errorf("ResultFormatKV() =\n%q\nwant\n%q", got, want)
	}
}

func TestResultFormatKVUsesTheKeyPrefixInOutputOnly(t *testing.T) {
	got := ResultFormatKV(sample{Name: "alice"}, -10, " ", "| ", "user_", "name")
	if want := " user_name | alice"; got != want {
		t.Errorf("ResultFormatKV() = %q, want %q", got, want)
	}
}

func TestResultFormatKVFlagsAnUnknownKey(t *testing.T) {
	got := ResultFormatKV(sample{Name: "alice"}, -6, " ", "= ", "", "nope")
	if !strings.Contains(got, "no such key: nope") {
		t.Errorf("ResultFormatKV() = %q, want it to flag the missing key", got)
	}
	// A field excluded from JSON is just as unreachable.
	got = ResultFormatKV(sample{Skipped: "hidden"}, -6, " ", "= ", "", "Skipped")
	if !strings.Contains(got, "no such key: Skipped") {
		t.Errorf("ResultFormatKV() = %q, want it to flag the missing key", got)
	}
}

func TestResultFormatKVEscapesControlCharacters(t *testing.T) {
	for _, name := range []string{
		"file" + string(rune(0x1b)) + "]0;PWNED" + string(rune(0x07)),
		"file" + string(rune(0x9b)) + "31m",
	} {
		got := ResultFormatKV(sample{Name: name}, -5, "", "= ", "", "name")
		if want := "name = " + strconv.Quote(name); got != want {
			t.Errorf("ResultFormatKV() = %q, want %q", got, want)
		}
		if strings.ContainsFunc(got, isControl) {
			t.Errorf("ResultFormatKV() = %q, want no raw control characters", got)
		}
	}

	got := ResultFormatKV(sample{Name: "signaturé"}, -5, "", "= ", "", "name")
	if want := "name = signaturé"; got != want {
		t.Errorf("ResultFormatKV() = %q, want %q", got, want)
	}
}

func TestEscapeControl(t *testing.T) {
	esc, bel := string(rune(0x1b)), string(rune(0x07))

	for name, tt := range map[string]struct{ in, want string }{
		"OSC sequence": {
			in:   "unknown key algorithm: ssh-x" + esc + "]0;PWNED" + bel,
			want: `unknown key algorithm: ssh-x\x1b]0;PWNED\a`,
		},
		"C1 introducer": {
			in:   "namespace " + string(rune(0x9b)) + "31m",
			want: "namespace \\u009b31m",
		},
		"lone invalid byte": {
			in:   "algorithm ssh-x" + string([]byte{0x9b}),
			want: "algorithm ssh-x" + string(utf8.RuneError),
		},
		"nothing to escape": {in: "no such file or directory", want: "no such file or directory"},
		"non-ASCII text":    {in: "signaturé", want: "signaturé"},
	} {
		t.Run(name, func(t *testing.T) {
			if got := EscapeControl(tt.in); got != tt.want {
				t.Errorf("EscapeControl() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestEscapeJSONControls(t *testing.T) {
	for name, tt := range map[string]struct{ in, want string }{
		"C1 introducer": {
			in:   `{"namespace":"file` + string(rune(0x9b)) + `31m"}`,
			want: `{"namespace":"file\u009b31m"}`,
		},
		"DEL": {
			in:   `{"namespace":"file` + string(rune(0x7f)) + `"}`,
			want: `{"namespace":"file\u007f"}`,
		},
		"printable two-byte rune": {
			in:   `{"comment":"caf` + "é ©" + `"}`,
			want: `{"comment":"caf` + "é ©" + `"}`,
		},
		"already escaped": {
			in:   `{"error":["a\u001bb"]}`,
			want: `{"error":["a\u001bb"]}`,
		},
	} {
		t.Run(name, func(t *testing.T) {
			if got := string(EscapeJSONControls([]byte(tt.in))); got != tt.want {
				t.Errorf("EscapeJSONControls() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestResultFormatKVRendersLargeNumbersLiterally(t *testing.T) {
	got := ResultFormatKV(
		struct {
			Big int64 `json:"big"`
		}{Big: 1000000},
		-4, "", "= ", "",
		"big",
	)
	if want := "big = 1000000"; got != want {
		t.Errorf("ResultFormatKV() = %q, want %q", got, want)
	}
}
