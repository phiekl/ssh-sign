// Copyright 2026 Philip Eklöf
//
// SPDX-License-Identifier: MIT

// Package args parses command-line options and subcommands.
package args

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"unicode/utf8"
)

// ErrHelp means -h/--help was given. The caller writes Help.
var ErrHelp = errors.New("help requested")

// ErrUsage means no arguments were given. The caller writes Help.
var ErrUsage = errors.New("missing arguments")

type kind int

const (
	kindString kind = iota
	kindBool
	kindCount
)

type flag struct {
	long, short string
	usage       string
	def         string
	kind        kind
	str         *string
	boolean     *bool
	count       *int
	changed     bool
}

type command struct {
	name, description string
}

// Set holds flags and optional subcommands.
type Set struct {
	name      string
	flags     []*flag
	help      bool
	required  []string
	denyEmpty []string
	exclusive [][]string
	commands  []command
}

// NewSet returns a set named name, with -h/--help registered.
func NewSet(name string) *Set {
	s := &Set{name: name}
	s.Bool(&s.help, "help", "h", "display this help text and exit")
	return s
}

// String registers a string flag with default value def.
func (s *Set) String(p *string, long, short, def, usage string) {
	*p = def
	s.add(&flag{long: long, short: short, usage: usage, def: def, kind: kindString, str: p})
}

// Bool registers a flag that is set to true when given.
func (s *Set) Bool(p *bool, long, short, usage string) {
	*p = false
	s.add(&flag{long: long, short: short, usage: usage, kind: kindBool, boolean: p})
}

// Count registers a flag that counts how many times it is given.
func (s *Set) Count(p *int, long, short, usage string) {
	*p = 0
	s.add(&flag{long: long, short: short, usage: usage, kind: kindCount, count: p})
}

func (s *Set) add(f *flag) {
	if f.long == "" || strings.HasPrefix(f.long, "-") || strings.Contains(f.long, "=") {
		panic(fmt.Sprintf("args: invalid flag name %q", f.long))
	}
	if f.short != "" && (utf8.RuneCountInString(f.short) != 1 || f.short == "-") {
		panic(fmt.Sprintf("args: invalid shorthand %q for flag %q", f.short, f.long))
	}
	for _, other := range s.flags {
		if other.long == f.long || (f.short != "" && other.short == f.short) {
			panic(fmt.Sprintf("args: flag %q redefined", f.long))
		}
	}
	s.flags = append(s.flags, f)
}

// Required makes Parse reject a missing flag.
func (s *Set) Required(name string) {
	s.mustLookup(name)
	s.required = append(s.required, name)
}

// DenyEmpty makes Parse reject a string flag given an empty value.
func (s *Set) DenyEmpty(name string) {
	if s.mustLookup(name).kind != kindString {
		panic(fmt.Sprintf("args: flag %q is not a string", name))
	}
	s.denyEmpty = append(s.denyEmpty, name)
}

// MutuallyExclusive makes Parse reject more than one of the named flags.
func (s *Set) MutuallyExclusive(names ...string) {
	if len(names) < 2 {
		panic(fmt.Sprintf("args: mutually exclusive group %q has less than two flags", names))
	}
	for _, name := range names {
		s.mustLookup(name)
	}
	s.exclusive = append(s.exclusive, slices.Clone(names))
}

// Command registers a command for ParseCommand and Help.
func (s *Set) Command(name, description string) {
	s.commands = append(s.commands, command{name, description})
}

func (s *Set) mustLookup(name string) *flag {
	f := s.lookup(name)
	if f == nil {
		panic(fmt.Sprintf("args: undefined flag %q", name))
	}
	return f
}

func (s *Set) lookup(name string) *flag {
	for _, f := range s.flags {
		if f.long == name {
			return f
		}
	}
	return nil
}

func (s *Set) lookupShort(short string) *flag {
	for _, f := range s.flags {
		if f.short == short {
			return f
		}
	}
	return nil
}

// Parse parses flags and rejects positional arguments. Help takes precedence
// over validation errors, but not syntax errors.
func (s *Set) Parse(argv []string) error {
	rest, err := s.parseFlags(argv)
	if err != nil {
		return err
	}
	if s.help {
		return ErrHelp
	}
	if len(rest) > 0 {
		return errors.New("no positional arguments expected")
	}
	return s.validate()
}

// ParseCommand parses flags up to a command name and returns the name and the
// arguments following it.
func (s *Set) ParseCommand(argv []string) (string, []string, error) {
	if len(argv) == 0 {
		return "", nil, ErrUsage
	}
	rest, err := s.parseFlags(argv)
	if err != nil {
		return "", nil, err
	}
	if s.help {
		return "", nil, ErrHelp
	}
	if len(rest) == 0 {
		return "", nil, errors.New("missing command")
	}
	for _, c := range s.commands {
		if c.name == rest[0] {
			return c.name, slices.Clone(rest[1:]), s.validate()
		}
	}
	return "", nil, fmt.Errorf("invalid command: %s", rest[0])
}

// parseFlags stops at the first positional argument and returns it and all
// that follow.
func (s *Set) parseFlags(argv []string) ([]string, error) {
	for i := 0; i < len(argv); i++ {
		arg := argv[i]
		switch {
		case arg == "--":
			return argv[i+1:], nil
		case arg == "-" || !strings.HasPrefix(arg, "-"):
			return argv[i:], nil
		case strings.HasPrefix(arg, "--"):
			consumed, err := s.parseLong(arg, argv[i+1:])
			if err != nil {
				return nil, err
			}
			i += consumed
		default:
			consumed, err := s.parseShort(arg, argv[i+1:])
			if err != nil {
				return nil, err
			}
			i += consumed
		}
	}
	return nil, nil
}

func (s *Set) parseLong(arg string, next []string) (int, error) {
	name, value, hasValue := strings.Cut(arg[2:], "=")
	if name == "" || strings.HasPrefix(name, "-") {
		return 0, fmt.Errorf("bad flag syntax: %s", arg)
	}
	f := s.lookup(name)
	if f == nil {
		return 0, fmt.Errorf("unknown flag: --%s", name)
	}
	if f.kind != kindString {
		if hasValue {
			return 0, fmt.Errorf("flag does not take a value: --%s", name)
		}
		f.set("")
		return 0, nil
	}
	if hasValue {
		f.set(value)
		return 0, nil
	}
	if len(next) == 0 {
		return 0, fmt.Errorf("flag needs an argument: --%s", name)
	}
	f.set(next[0])
	return 1, nil
}

// parseShort handles clusters and values attached to short flags.
func (s *Set) parseShort(arg string, next []string) (int, error) {
	shorts := arg[1:]
	for j, r := range shorts {
		f := s.lookupShort(string(r))
		if f == nil {
			return 0, fmt.Errorf("unknown shorthand flag: %q in %s", r, arg)
		}
		if f.kind != kindString {
			f.set("")
			continue
		}
		_, size := utf8.DecodeRuneInString(shorts[j:])
		if value := shorts[j+size:]; value != "" {
			f.set(value)
			return 0, nil
		}
		if len(next) == 0 {
			return 0, fmt.Errorf("flag needs an argument: %q in %s", r, arg)
		}
		f.set(next[0])
		return 1, nil
	}
	return 0, nil
}

func (f *flag) set(value string) {
	f.changed = true
	switch f.kind {
	case kindString:
		*f.str = value
	case kindBool:
		*f.boolean = true
	case kindCount:
		*f.count++
	}
}

func (s *Set) validate() error {
	var missing []string
	for _, name := range s.required {
		if !s.lookup(name).changed {
			missing = append(missing, name)
		}
	}
	switch len(missing) {
	case 0:
	case 1:
		return fmt.Errorf("missing required flag: %s", missing[0])
	default:
		return fmt.Errorf("missing required flags: %s", strings.Join(missing, ", "))
	}

	for _, names := range s.exclusive {
		changed := ""
		for _, name := range names {
			if !s.lookup(name).changed {
				continue
			}
			if changed != "" {
				return fmt.Errorf("%s and %s are mutually exclusive flags", changed, name)
			}
			changed = name
		}
	}

	var empty []string
	for _, name := range s.denyEmpty {
		if f := s.lookup(name); f.changed && *f.str == "" {
			empty = append(empty, name)
		}
	}
	switch len(empty) {
	case 0:
	case 1:
		return fmt.Errorf("flag/argument is empty: %s", empty[0])
	default:
		return fmt.Errorf("flags/arguments are empty: %s", strings.Join(empty, ", "))
	}
	return nil
}

// Help returns the usage text.
func (s *Set) Help() string {
	var b strings.Builder
	if len(s.commands) > 0 {
		fmt.Fprintf(&b, "usage: %s <command> [command option]..\n\n", s.name)
		width := 0
		for _, c := range s.commands {
			width = max(width, len(c.name))
		}
		b.WriteString("commands:\n")
		for _, c := range s.commands {
			fmt.Fprintf(&b, "  %-*s   %s\n", width, c.name, c.description)
		}
		return b.String()
	}

	fmt.Fprintf(&b, "usage: %s [option]..\n\n", s.name)
	b.WriteString("options:\n")
	names := make([]string, len(s.flags))
	width := 0
	for i, f := range s.flags {
		names[i] = f.helpName()
		width = max(width, len(names[i]))
	}
	for i, f := range s.flags {
		usage := f.usage
		if f.kind == kindString && f.def != "" {
			usage += fmt.Sprintf(" (default %q)", f.def)
		}
		fmt.Fprintf(&b, "%-*s   %s\n", width, names[i], usage)
	}
	return b.String()
}

func (f *flag) helpName() string {
	if f.short != "" {
		return "  -" + f.short + ", --" + f.long
	}
	return "      --" + f.long
}
