# SPDX-FileCopyrightText: 2026 Philip Eklöf
#
# SPDX-License-Identifier: MIT

# Post-processes go-md2man's output (sed -E) so that what's typed, such as
# options, commands and dates, keeps ASCII hyphens in UTF-8 output, while
# hyphens of prose, such as "case-sensitive", stay breakable hyphens.

# Start from plain hyphens, since some go-md2man versions escape them.
s/\\-/-/g

# Don't hyphenate, which would split what's typed, such as options and
# paths, at line ends. go-md2man's .nh comes before .TH, which turns hyphenation back
# on. Setting HY (groff 1.23) also stops later macros, such as those for
# links, from turning it back on.
/^\.TH /{
	i\
.nr HY 0
	a\
.nh
}

# The separator of the NAME line, and hyphens in manual names.
s/^(ssh-sign(-[a-z]+)*) - /\1 \\- /
/^\.TH /s/-/\\-/g
/^ssh-sign.* \\- /{
	:name
	s/^(ssh(\\?-[a-z]+)*)-([a-z]+)/\1\\-\3/
	t name
}

# Code blocks are typed whole.
/^\.EX$/,/^\.EE$/{
	s/-/\\-/g
	s/'/\\(aq/g
	b
}

# Bold and italic spans, up to the next font change, one hyphen at a time.
:span
s/(\\f[BI](([^\\]|\\[^f])*([^\\]|\\-))?)-/\1\\-/
t span

# A tilde, as for home, stays ASCII: groff draws a plain ~ as a raised one.
s/~/\\(ti/g

# A caret stays ASCII too: groff draws a plain ^ as a modifier circumflex.
s/\^/\\(ha/g
