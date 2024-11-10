// File: /tinytoml/src/pkg/tinytoml/tinytoml.go

/*
Package tinytoml provides a minimal TOML parser and encoder for configuration files.

Supported Features:
- Basic types: string, number (int/float), boolean
- Table/group nesting up to 3 levels
- Single-line string values with escape sequences (\, \", \', \t)
- Both inline (#) and full-line comments
- Flexible whitespace around equals sign and line start
- Quoted string values (must be used for strings containing whitespace)
- Strict whitespace handling (unquoted values cannot contain whitespace)
- Integer overflow detection and number format validation
- Duplicate key detection (first occurrence used)

Limitations:
- No array/slice support
- No multi-line string support
- Limited escape sequence support (only \, \", \', \t)
- Maximum 3 levels of table/group nesting
- No support for custom time formats
- No support for hex/octal/binary number formats
- No scientific notation support for numbers
- Unquoted strings cannot contain whitespace (use quotes)
*/

package tinytoml

import (
	"fmt"
	"strings"
	"unicode/utf8"
)

// TokenType represents the type of TOML value
type TokenType int

const (
	TokenInvalid TokenType = iota
	TokenString
	TokenNumber
	TokenBool
	TokenGroup
	TokenKey
)

// maxNestingLevel defines maximum allowed table/group nesting
const maxNestingLevel = 3

// Value represents a TOML value with type information
type Value struct {
	Type  TokenType // Type of the value
	Raw   string    // Raw string representation
	Group string    // Group this value belongs to
}

// ParseError represents a TOML parsing error with line information
type ParseError struct {
	Line    int    // Line number where error occurred
	Column  int    // Column number where error occurred
	Message string // Error message
	Context string // Context of the error (key/value/group)
	Err     error  // Original error if any
}

// Error implements error interface for ParseError
func (e *ParseError) Error() string {
	if e.Context != "" {
		if e.Err != nil {
			return fmt.Sprintf("line %d, col %d: %s in %s: %v", e.Line, e.Column, e.Message, e.Context, e.Err)
		}
		return fmt.Sprintf("line %d, col %d: %s in %s", e.Line, e.Column, e.Message, e.Context)
	}

	if e.Err != nil {
		return fmt.Sprintf("line %d: %s: %v", e.Line, e.Message, e.Err)
	}
	return fmt.Sprintf("line %d: %s", e.Line, e.Message)
}

// Unwrap implements error unwrapping
func (e *ParseError) Unwrap() error {
	return e.Err
}

// GetString returns string value with validation
func (v *Value) GetString() (string, error) {
	if v.Type != TokenString && v.Type != TokenKey {
		return "", fmt.Errorf("value is not a string")
	}
	return unescapeString(v.Raw)
}

// GetBool returns boolean value with validation
func (v *Value) GetBool() (bool, error) {
	if v.Type != TokenBool {
		return false, fmt.Errorf("value is not a boolean")
	}
	switch v.Raw {
	case "true":
		return true, nil
	case "false":
		return false, nil
	default:
		return false, fmt.Errorf("invalid boolean value: %s", v.Raw)
	}
}

// GetInt returns integer value with validation and overflow checking
func (v *Value) GetInt() (int64, error) {
	if v.Type != TokenNumber {
		return 0, fmt.Errorf("value is not a number")
	}
	return parseInt(v.Raw)
}

// GetFloat returns float value with validation
func (v *Value) GetFloat() (float64, error) {
	if v.Type != TokenNumber {
		return 0, fmt.Errorf("value is not a number")
	}
	return parseFloat(v.Raw)
}

// parseError creates a new ParseError
func parseError(line int, msg string, err error) error {
	return &ParseError{
		Line:    line,
		Message: msg,
		Err:     err,
	}
}

// isValidKey checks if a key name follows TOML specification
func isValidKey(key string) bool {
	if len(key) == 0 {
		return false
	}

	// Check first character
	if !isValidKeyStart(key[0]) {
		return false
	}

	// Check rest of the characters
	dots := 0
	for i := 1; i < len(key); i++ {
		if key[i] == '.' {
			if dots > 0 { // Check consecutive dots
				return false
			}
			dots++
			continue
		}
		if !isValidKeyChar(key[i]) {
			return false
		}
		dots = 0
	}

	return dots == 0 // Key can't end with a dot
}

// isValidKeyStart checks if a character is valid as first character of key
func isValidKeyStart(c byte) bool {
	return (c >= 'a' && c <= 'z') ||
		(c >= 'A' && c <= 'Z') ||
		c == '_'
}

// isValidKeyChar checks if a character is valid within a key
func isValidKeyChar(c byte) bool {
	return isValidKeyStart(c) ||
		(c >= '0' && c <= '9') ||
		c == '-'
}

// unescapeString handles basic string escape sequences
func unescapeString(s string) (string, error) {
	var result strings.Builder
	escaped := false
	isQuoted := false

	// Handle quoted strings
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		s = s[1 : len(s)-1]
		isQuoted = true
	}

	for i := 0; i < len(s); {
		r := rune(s[i])
		size := 1
		if r >= utf8.RuneSelf {
			r, size = utf8.DecodeRuneInString(s[i:])
			if r == utf8.RuneError {
				return "", fmt.Errorf("invalid UTF-8 encoding")
			}
		}

		if escaped {
			switch r {
			case '\\', '"', '\'', 't':
				if r == 't' {
					result.WriteRune('\t')
				} else {
					result.WriteRune(r)
				}
			default:
				return "", fmt.Errorf("invalid escape sequence: \\%c", r)
			}
			escaped = false
			i += size
			continue
		}

		if r == '\\' {
			escaped = true
			i++
			continue
		}

		if isQuoted || (r != ' ' && r != '\t') {
			result.WriteRune(r)
		}
		i += size
	}

	if escaped {
		return "", fmt.Errorf("unterminated escape sequence")
	}

	return result.String(), nil
}

// parseInt is a helper to parse integer values with overflow checking
func parseInt(s string) (int64, error) {
	var val int64
	var neg bool

	if len(s) == 0 {
		return 0, fmt.Errorf("empty number")
	}

	// Handle negative numbers
	if s[0] == '-' {
		neg = true
		s = s[1:]
	}

	// Parse digits
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("invalid integer: %s", s)
		}

		// Check for overflow
		if val > (1<<63-1)/10 {
			return 0, fmt.Errorf("integer overflow: %s", s)
		}

		digit := int64(c - '0')
		val = val*10 + digit

		// Check for overflow after addition
		if val < 0 {
			return 0, fmt.Errorf("integer overflow: %s", s)
		}
	}

	if neg {
		val = -val
		if val > 0 {
			return 0, fmt.Errorf("integer overflow: %s", s)
		}
	}

	return val, nil
}

// parseFloat is a helper to parse float values with format validation
func parseFloat(s string) (float64, error) {
	var intPart int64
	var fracPart int64
	var fracDiv float64 = 1
	var neg bool

	if len(s) == 0 {
		return 0, fmt.Errorf("empty number")
	}

	// Handle negative numbers
	if s[0] == '-' {
		neg = true
		s = s[1:]
	}

	// Split on decimal point
	parts := strings.Split(s, ".")
	if len(parts) > 2 {
		return 0, fmt.Errorf("invalid float: multiple decimal points in %s", s)
	}

	// Parse integer part
	var err error
	intPart, err = parseInt(parts[0])
	if err != nil {
		return 0, fmt.Errorf("invalid float: %w", err)
	}

	// Parse fractional part if exists
	if len(parts) == 2 {
		for _, c := range parts[1] {
			if c < '0' || c > '9' {
				return 0, fmt.Errorf("invalid float: non-digit in fractional part %s", s)
			}
			fracPart = fracPart*10 + int64(c-'0')
			fracDiv *= 10
		}
	}

	result := float64(intPart) + float64(fracPart)/fracDiv
	if neg {
		result = -result
	}

	return result, nil
}
