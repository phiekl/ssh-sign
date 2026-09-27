// Copyright 2026 Philip Eklöf
//
// SPDX-License-Identifier: MIT

package cli

const (
	colorRed    = "\x1b[31m"
	colorGreen  = "\x1b[32m"
	colorYellow = "\x1b[33m"
	colorReset  = "\x1b[0m"
)

// ColorStringer is implemented by results that can be rendered with colors.
type ColorStringer interface {
	ColorString() string
}

// ColorError colors an error line.
func ColorError(s string) string {
	return colorRed + s + colorReset
}

// colorStatus colors the known status values, leaving any other value as is.
func colorStatus(value any) any {
	var color string
	switch value {
	case "valid":
		color = colorGreen
	case "invalid":
		color = colorRed
	case "disabled":
		color = colorYellow
	default:
		return value
	}
	return color + value.(string) + colorReset
}
