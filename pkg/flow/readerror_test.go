// Copyright 2026 Philip Eklöf
//
// SPDX-License-Identifier: MIT

package flow

import (
	"errors"
	"io"
	"strings"
	"testing"

	"pxy.se/go/ssh-sign/pkg/sshsig"
)

// failingReader returns the supplied error on every read.
type failingReader struct {
	err error
}

func (r failingReader) Read([]byte) (int, error) {
	return 0, r.err
}

// A read failure, such as reading a directory, must not yield an invalid verdict.
func TestVerifyDoesNotCallAnUnreadableFileInvalid(t *testing.T) {
	s := sign(t, "git")
	wantErr := errors.New("is a directory")

	opts := s.verifyOpts("alice@example.com "+s.keyLine+"\n", "git")
	opts.VerifyFile = failingReader{err: wantErr}

	res, errs := Verify(opts)
	if res != nil {
		t.Errorf("Verify() = %+v, want no result when nothing could be read", res)
	}
	if !strings.Contains(errorText(errs), "failed reading data to verify") {
		t.Fatalf("Verify() errors = %v, want the read failure reported", errs)
	}
	if strings.Contains(errorText(errs), "unexpected verification failure") {
		t.Errorf("Verify() errors = %v, want it not framed as a verification failure", errs)
	}
}

func TestCheckDoesNotCallAnUnreadableFileInvalid(t *testing.T) {
	s := sign(t, "git")

	res, errs := Check(&CheckOpts{
		NoAuthKey:     true,
		Namespace:     "git",
		SignatureFile: strings.NewReader(s.armored),
		VerifyFile:    failingReader{err: errors.New("is a directory")},
	})
	if res != nil {
		t.Errorf("Check() = %+v, want no result when nothing could be read", res)
	}
	if !strings.Contains(errorText(errs), "failed reading data to verify") {
		t.Fatalf("Check() errors = %v, want the read failure reported", errs)
	}
}

// Readable but altered data must still yield an invalid verdict.
func TestVerifyStillCallsATamperedFileInvalid(t *testing.T) {
	s := sign(t, "git")

	opts := s.verifyOpts("alice@example.com "+s.keyLine+"\n", "git")
	opts.VerifyFile = strings.NewReader("tampered\n")

	res, errs := Verify(opts)
	if res == nil {
		t.Fatal("Verify() = nil, want a result for data that read cleanly")
	}
	if res.Verification != "invalid" {
		t.Errorf("Verification = %q, want %q", res.Verification, "invalid")
	}
	if len(errs) == 0 {
		t.Error("Verify() errors = none, want the mismatch reported")
	}
}

// io.EOF ends the message; it is not a read failure.
func TestVerifyReportsAnEmptyFileAsAVerdict(t *testing.T) {
	s := sign(t, "git")

	opts := s.verifyOpts("alice@example.com "+s.keyLine+"\n", "git")
	opts.VerifyFile = failingReader{err: io.EOF}

	res, errs := Verify(opts)
	if res == nil {
		t.Fatalf("Verify() = nil for an empty reader, errs = %v", errs)
	}
	if res.Verification != "invalid" {
		t.Errorf("Verification = %q, want %q", res.Verification, "invalid")
	}
}

// Callers must be able to inspect wrapped error types and causes.
func TestReadFailuresRemainInspectableByCallers(t *testing.T) {
	s := sign(t, "git")
	wantErr := errors.New("is a directory")

	opts := s.verifyOpts("alice@example.com "+s.keyLine+"\n", "git")
	opts.VerifyFile = failingReader{err: wantErr}
	_, verifyErrs := Verify(opts)

	_, checkErrs := Check(&CheckOpts{
		NoAuthKey:     true,
		Namespace:     "git",
		SignatureFile: strings.NewReader(s.armored),
		VerifyFile:    failingReader{err: wantErr},
	})

	for name, errs := range map[string][]error{"Verify": verifyErrs, "Check": checkErrs} {
		t.Run(name, func(t *testing.T) {
			err := errors.Join(errs...)
			if !sshsig.IsReadError(err) {
				t.Errorf("%s() errors = %v, want a reachable *sshsig.ReadError", name, errs)
			}
			if !errors.Is(err, wantErr) {
				t.Errorf("%s() errors = %v, want the underlying cause reachable", name, errs)
			}
		})
	}
}
