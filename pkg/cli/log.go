// Copyright 2026 Philip Eklöf
//
// SPDX-License-Identifier: MIT

package cli

import (
	"context"
	"io"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"unicode/utf8"
)

// Debug levels correspond to OpenSSH-style -v flags.
const (
	LevelDebug1 = slog.LevelDebug     // -v
	LevelDebug2 = slog.LevelDebug - 4 // -vv
	LevelDebug3 = slog.LevelDebug - 8 // -vvv
)

// MaxVerbosity is the maximum effective verbosity.
const MaxVerbosity = 3

// NewLogger writes the requested debug levels to w. Values below 1 disable logging.
func NewLogger(w io.Writer, verbosity int) *slog.Logger {
	if verbosity < 1 {
		return slog.New(slog.DiscardHandler)
	}
	level := LevelDebug1 - slog.Level(4*(min(verbosity, MaxVerbosity)-1))
	return slog.New(&debugHandler{mu: &sync.Mutex{}, w: w, level: level})
}

// Debug logs at level if log is non-nil.
func Debug(log *slog.Logger, level slog.Level, msg string, args ...any) {
	if log == nil {
		return
	}
	log.Log(context.Background(), level, msg, args...)
}

// debugHandler writes records as "debugN: message key=value" lines.
type debugHandler struct {
	mu    *sync.Mutex
	w     io.Writer
	level slog.Level
	// groups is the dot-terminated WithGroup prefix.
	groups string
	// attrs contains pre-rendered WithAttrs values.
	attrs string
}

func (h *debugHandler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= h.level
}

func (h *debugHandler) Handle(_ context.Context, r slog.Record) error {
	var b strings.Builder
	b.WriteString(levelName(r.Level))
	b.WriteString(": ")
	b.WriteString(EscapeControl(r.Message))
	b.WriteString(h.attrs)
	r.Attrs(func(a slog.Attr) bool {
		appendAttr(&b, h.groups, a)
		return true
	})
	b.WriteByte('\n')

	h.mu.Lock()
	defer h.mu.Unlock()
	_, err := io.WriteString(h.w, b.String())
	return err
}

func (h *debugHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	if len(attrs) == 0 {
		return h
	}
	var b strings.Builder
	b.WriteString(h.attrs)
	for _, a := range attrs {
		appendAttr(&b, h.groups, a)
	}
	clone := *h
	clone.attrs = b.String()
	return &clone
}

func (h *debugHandler) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}
	clone := *h
	clone.groups = h.groups + name + "."
	return &clone
}

func levelName(level slog.Level) string {
	switch level {
	case LevelDebug1:
		return "debug1"
	case LevelDebug2:
		return "debug2"
	case LevelDebug3:
		return "debug3"
	}
	return strings.ToLower(level.String())
}

func appendAttr(b *strings.Builder, groups string, a slog.Attr) {
	a.Value = a.Value.Resolve()
	if a.Equal(slog.Attr{}) {
		return
	}
	if a.Value.Kind() == slog.KindGroup {
		group := a.Value.Group()
		if len(group) == 0 {
			return
		}
		if a.Key != "" {
			groups += a.Key + "."
		}
		for _, ga := range group {
			appendAttr(b, groups, ga)
		}
		return
	}
	b.WriteByte(' ')
	b.WriteString(EscapeControl(groups + a.Key))
	b.WriteByte('=')
	b.WriteString(quoteValue(a.Value.String()))
}

// quoteValue quotes anything that is not a bare, printable token.
func quoteValue(s string) string {
	if s != "" && utf8.ValidString(s) && !strings.ContainsFunc(s, needsQuoting) {
		return s
	}
	return strconv.Quote(s)
}

func needsQuoting(r rune) bool {
	return isControl(r) || r == ' ' || r == '"' || r == '='
}
