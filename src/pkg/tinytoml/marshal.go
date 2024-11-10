// File: /tinytoml/src/pkg/tinytoml/marshal.go

package tinytoml

import (
	"bufio"
	"bytes"
	"fmt"
	"math"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"unicode"
)

// Marshal converts a struct to TOML format
func Marshal(v interface{}) ([]byte, error) {
	val := reflect.ValueOf(v)
	if val.Kind() == reflect.Ptr {
		if val.IsNil() {
			return nil, fmt.Errorf("cannot marshal nil pointer")
		}
		val = val.Elem()
	}

	if val.Kind() != reflect.Struct {
		return nil, fmt.Errorf("marshal target must be a struct")
	}

	m := &marshaler{
		groups: make(map[string]map[string]string),
		depth:  0,
	}

	if err := m.marshalStruct(val); err != nil {
		return nil, err
	}

	return m.encode()
}

// marshaler holds marshaling state
type marshaler struct {
	groups map[string]map[string]string
	depth  int
}

// marshalStruct processes a struct value
func (m *marshaler) marshalStruct(val reflect.Value) error {
	typ := val.Type()
	for i := 0; i < val.NumField(); i++ {
		field := val.Field(i)
		fieldType := typ.Field(i)

		if !fieldType.IsExported() {
			continue
		}

		tag := fieldType.Tag.Get("toml")
		if tag == "-" {
			continue
		}

		group, key := "", tag
		if idx := strings.Index(tag, "."); idx >= 0 {
			group = tag[:idx]
			key = tag[idx+1:]
		}

		parts := strings.Split(group, ".")
		if len(parts) > maxNestingLevel {
			return fmt.Errorf("field %s: group nesting exceeds maximum depth of %d", fieldType.Name, maxNestingLevel)
		}
		for _, part := range parts {
			if part != "" && !isValidKey(part) {
				return fmt.Errorf("field %s: invalid group name: %s", fieldType.Name, part)
			}
		}
		if !isValidKey(key) {
			return fmt.Errorf("field %s: invalid key name: %s", fieldType.Name, key)
		}

		if m.groups[group] == nil {
			m.groups[group] = make(map[string]string)
		}

		str, err := m.marshalValue(field)
		if err != nil {
			return fmt.Errorf("field %s: %w", fieldType.Name, err)
		}

		m.groups[group][key] = str
	}

	return nil
}

// marshalValue converts a reflect.Value to a TOML-compatible string
func (m *marshaler) marshalValue(v reflect.Value) (string, error) {
	switch v.Kind() {
	case reflect.String:
		s := v.String()
		needsQuotes := strings.ContainsAny(s, "\"\\\n\t '") ||
			strings.Contains(s, "#") ||
			!isASCII(s) ||
			s == ""

		if needsQuotes {
			s = strings.ReplaceAll(s, "\\", "\\\\")
			s = strings.ReplaceAll(s, "\"", "\\\"")
			s = strings.ReplaceAll(s, "'", "\\'")
			s = strings.ReplaceAll(s, "\t", "\\t")
			return fmt.Sprintf("\"%s\"", s), nil
		}
		return s, nil

	case reflect.Bool:
		return strconv.FormatBool(v.Bool()), nil

	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		i := v.Int()
		if i > math.MaxInt64 || i < math.MinInt64 {
			return "", fmt.Errorf("integer overflow")
		}
		return strconv.FormatInt(i, 10), nil

	case reflect.Float32, reflect.Float64:
		f := v.Float()
		s := strconv.FormatFloat(f, 'f', -1, 64)
		if !strings.Contains(s, ".") {
			s += ".0"
		}
		return s, nil

	default:
		return "", fmt.Errorf("unsupported type: %v", v.Type())
	}
}

// isASCII checks if string contains non-ASCII characters
func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] > unicode.MaxASCII {
			return false
		}
	}
	return true
}

// encode produces the final TOML document
func (m *marshaler) encode() ([]byte, error) {
	var buf bytes.Buffer

	// Get all groups and sort
	var groups []string
	for group := range m.groups {
		groups = append(groups, group)
	}
	sort.Strings(groups)

	// Handle root group first
	if rootGroup, ok := m.groups[""]; ok && len(rootGroup) > 0 {
		if err := m.writeGroup(&buf, "", rootGroup); err != nil {
			return nil, err
		}
		buf.WriteByte('\n') // Add newline after root group
	}

	// Write each group with proper spacing
	isFirst := true
	for _, group := range groups {
		if group == "" {
			continue
		}

		if !isFirst {
			buf.WriteByte('\n')
		}
		isFirst = false

		parts := strings.Split(group, ".")
		if len(parts) > maxNestingLevel {
			return nil, fmt.Errorf("group nesting exceeds maximum depth of %d: %s", maxNestingLevel, group)
		}

		buf.WriteString(fmt.Sprintf("[%s]\n", group))
		if err := m.writeGroup(&buf, group, m.groups[group]); err != nil {
			return nil, err
		}
	}

	return buf.Bytes(), nil
}

// writeGroup writes a group of key-value pairs
func (m *marshaler) writeGroup(buf *bytes.Buffer, group string, values map[string]string) error {
	var keys []string
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	for _, key := range keys {
		value := values[key]
		if value == "" {
			return fmt.Errorf("empty value for key: %s", key)
		}
		if _, err := fmt.Fprintf(buf, "%s = %s\n", key, value); err != nil {
			return err
		}
	}

	return nil
}

// MarshalIndent is like Marshal but applies consistent formatting
func MarshalIndent(v interface{}) ([]byte, error) {
	data, err := Marshal(v)
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	scanner := bufio.NewScanner(bytes.NewReader(data))
	inGroup := false

	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		if strings.HasPrefix(trimmed, "[") {
			if inGroup {
				buf.WriteByte('\n')
			}
			inGroup = true
		}

		buf.WriteString(line)
		buf.WriteByte('\n')
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}
