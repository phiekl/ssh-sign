# SPDX-FileCopyrightText: 2026 Philip Eklöf
#
# SPDX-License-Identifier: MIT

# Turns a Markdown document in doc/ into Markdown for go-md2man (sed -E).
# The Makefile adds the title line and starts NAME with the page's name,
# e.g. "# NAME\n\nssh-sign - ", for the summary to complete.
#
# A document starts with a level-1 title and a one-line summary, then, for
# a SYNOPSIS, optionally a code block of usage, and the description. Its
# sections are level-2 headings.
#
# The hold space keeps the state: "sum" until the summary, "syn" after it,
# "usage" within the usage block, "dl" within a definition, and empty
# otherwise.

# Everything before the title, such as the license comment, and the title.
1,/^# /{
	/^# /{
		x
		s/.*/sum/
		x
	}
	d
}

x
/^sum$/{
	x
	/^$/d
	# The summary completes the NAME line, e.g. "sign and verify data
	# using SSH keys".
	s/^(.)/\l\1/
	s/\.$//
	x
	s/.*/syn/
	x
	b
}
/^syn$/{
	x
	/^$/b
	/^```$/{
		x
		s/.*/usage/
		x
		s/.*/\n# SYNOPSIS\n/
		b
	}
	x
	s/.*//
	x
	s/^/# DESCRIPTION\n\n/
	x
}
/^usage$/{
	x
	/^```$/{
		x
		s/.*//
		x
		s/.*/\n# DESCRIPTION/
		b
	}
	# The command and its options in bold, and its operands in italics.
	# Each usage is a paragraph of its own.
	s/^([^ ]+)/**\1**/
	s/([ [(])(-[^]) ]+)/\1**\2**/g
	s/\[([a-z]+)\]/[*\1*]/g
	s/ ([a-z]+)( |$|[]\)])/ *\1*\2/g
	s/ ([a-z]+)( |$|[]\)])/ *\1*\2/g
	s/$/\n/
	b
}
x

# Links to sections and other documents keep only their text, e.g.
# **ssh-sign**(1) or OUTPUT.
s/\[([^]]*)\]\([^)#]*\.md(#[^)]*)?\)/\1/g
s/\[([^]]*)\]\(#[^)]*\)/\1/g

# Sections in capitals.
s/^## (.*)$/## \U\1/

# An entry of an option, key or variable, "- **term**: Text", becomes a
# definition list, as a tagged paragraph. Its following indented lines move
# along, until a line that is not indented.
/^- \*\*([^:]|:[^ ])*: [A-Z]/{
	s/^- (\*\*([^:]|:[^ ])*): /\n\1\n:   /
	x
	s/.*/dl/
	x
	b
}
/^[^ ]/{
	x
	s/.*//
	x
	b
}
/^  /{
	x
	/^dl$/{
		x
		s/^/  /
		b
	}
	x
}
