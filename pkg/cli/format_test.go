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

func TestResultFormatKV(t *testing.T) {
	got := ResultFormatKV(-6, " ", "= ", KV("name", "alice"), KV("count", 3))
	want := " name  = alice\n count = 3"
	if got != want {
		t.Errorf("ResultFormatKV() =\n%q\nwant\n%q", got, want)
	}
}

func TestResultFormatKVEscapesControlCharacters(t *testing.T) {
	for _, name := range []string{
		"file" + string(rune(0x1b)) + "]0;PWNED" + string(rune(0x07)),
		"file" + string(rune(0x9b)) + "31m",
	} {
		got := ResultFormatKV(-5, "", "= ", KV("name", name))
		if want := "name = " + strconv.Quote(name); got != want {
			t.Errorf("ResultFormatKV() = %q, want %q", got, want)
		}
		if strings.ContainsFunc(got, isControl) {
			t.Errorf("ResultFormatKV() = %q, want no raw control characters", got)
		}
	}

	got := ResultFormatKV(-5, "", "= ", KV("name", "signaturé"))
	if want := "name = signaturé"; got != want {
		t.Errorf("ResultFormatKV() = %q, want %q", got, want)
	}
}

// Invalid UTF-8 must be quoted even when no control rune is found.
func TestResultFormatKVQuotesInvalidUTF8(t *testing.T) {
	got := ResultFormatKV(-5, "", "= ", KV("name", "file"+string([]byte{0x9b})+"31m"))
	if want := `name = "file\x9b31m"`; got != want {
		t.Errorf("ResultFormatKV() = %q, want %q", got, want)
	}
	if !utf8.ValidString(got) {
		t.Errorf("ResultFormatKV() = %q, want valid UTF-8", got)
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
	got := ResultFormatKV(-4, "", "= ", KV("big", int64(1000000)))
	if want := "big = 1000000"; got != want {
		t.Errorf("ResultFormatKV() = %q, want %q", got, want)
	}
}

func TestResultFormatKVColor(t *testing.T) {
	fields := []Field{
		KV("name", "valid"),
		StatusKV("a", "valid"),
		StatusKV("b", "invalid"),
		StatusKV("c", "disabled"),
		StatusKV("d", "other"),
	}
	want := "name = valid\n" +
		"a    = \x1b[32mvalid\x1b[0m\n" +
		"b    = \x1b[31minvalid\x1b[0m\n" +
		"c    = \x1b[33mdisabled\x1b[0m\n" +
		"d    = other"
	if got := ResultFormatKVColor(-5, "", "= ", fields...); got != want {
		t.Errorf("ResultFormatKVColor() =\n%q\nwant\n%q", got, want)
	}
	want = "name = valid\na    = valid\nb    = invalid\nc    = disabled\nd    = other"
	if got := ResultFormatKV(-5, "", "= ", fields...); got != want {
		t.Errorf("ResultFormatKV() =\n%q\nwant\n%q", got, want)
	}
}

func TestResultFormatKVColorEscapesStatus(t *testing.T) {
	value := "valid" + string(rune(0x1b)) + "[0m"
	got := ResultFormatKVColor(-2, "", "= ", StatusKV("a", value))
	if want := "a = " + strconv.Quote(value); got != want {
		t.Errorf("ResultFormatKVColor() = %q, want %q", got, want)
	}
}

func TestColorError(t *testing.T) {
	if got, want := ColorError("error: x"), "\x1b[31merror: x\x1b[0m"; got != want {
		t.Errorf("ColorError() = %q, want %q", got, want)
	}
}
