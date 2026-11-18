// Package cli implements the command line interface of Agent Tool Policy.
// It wraps the policy library and adds no policy behaviour of its own.
package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"unicode/utf8"
)

// maxNesting is the deepest object or array nesting accepted in one input
// line.
const maxNesting = 64

// jsonWhitespace holds the only whitespace characters JSON allows around
// values.
const jsonWhitespace = " \t\r\n"

// checkJSONStructure validates one input line before it is decoded: valid
// UTF-8, exactly one JSON value, no duplicate object member at any depth,
// nesting within the limit, and no Unicode escape that is not valid UTF-16.
func checkJSONStructure(line []byte) error {
	if !utf8.Valid(line) {
		return errors.New("input is not valid UTF-8")
	}

	decoder := json.NewDecoder(bytes.NewReader(line))
	decoder.UseNumber()

	token, err := decoder.Token()
	if err != nil {
		return jsonError(err)
	}
	if err := walkValue(decoder, token, 1); err != nil {
		return err
	}

	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return errors.New("unexpected data after the first JSON value")
	}
	return checkUnicodeEscapes(line)
}

// checkUnicodeEscapes rejects \u escapes that do not form valid UTF-16 in
// any JSON string, object keys included: a high surrogate must be followed
// by a low surrogate, and a low surrogate must follow a high one.
// encoding/json would silently replace such escapes with U+FFFD, and
// json.Valid accepts them. The line must already be valid JSON.
func checkUnicodeEscapes(line []byte) error {
	inString := false
	for i := 0; i < len(line); i++ {
		if !inString {
			inString = line[i] == '"'
			continue
		}

		switch line[i] {
		case '"':
			inString = false
		case '\\':
			i++
			if line[i] != 'u' {
				continue
			}
			unit := utf16Unit(line[i+1 : i+5])
			i += 4
			switch {
			case isHighSurrogate(unit):
				if i+6 < len(line) && line[i+1] == '\\' && line[i+2] == 'u' &&
					isLowSurrogate(utf16Unit(line[i+3:i+7])) {
					i += 6
					continue
				}
				return errors.New("invalid Unicode escape: unpaired high surrogate")
			case isLowSurrogate(unit):
				return errors.New("invalid Unicode escape: unpaired low surrogate")
			}
		}
	}
	return nil
}

// utf16Unit decodes the four hexadecimal digits of a \u escape. It returns
// 0 for malformed digits, which valid JSON never contains.
func utf16Unit(digits []byte) uint64 {
	unit, err := strconv.ParseUint(string(digits), 16, 16)
	if err != nil {
		return 0
	}
	return unit
}

func isHighSurrogate(unit uint64) bool {
	return unit >= 0xD800 && unit <= 0xDBFF
}

func isLowSurrogate(unit uint64) bool {
	return unit >= 0xDC00 && unit <= 0xDFFF
}

func walkValue(decoder *json.Decoder, token json.Token, depth int) error {
	delimiter, isContainer := token.(json.Delim)
	if !isContainer {
		return nil
	}
	if depth > maxNesting {
		return fmt.Errorf("nesting exceeds %d levels", maxNesting)
	}

	if delimiter == '{' {
		seen := make(map[string]struct{})
		for {
			key, err := decoder.Token()
			if err != nil {
				return jsonError(err)
			}
			if end, ok := key.(json.Delim); ok && end == '}' {
				return nil
			}
			name, ok := key.(string)
			if !ok {
				return errors.New("malformed JSON object")
			}
			if _, duplicate := seen[name]; duplicate {
				return fmt.Errorf("duplicate object key %q", name)
			}
			seen[name] = struct{}{}

			value, err := decoder.Token()
			if err != nil {
				return jsonError(err)
			}
			if err := walkValue(decoder, value, depth+1); err != nil {
				return err
			}
		}
	}

	for {
		element, err := decoder.Token()
		if err != nil {
			return jsonError(err)
		}
		if end, ok := element.(json.Delim); ok && end == ']' {
			return nil
		}
		if err := walkValue(decoder, element, depth+1); err != nil {
			return err
		}
	}
}

// checkToolCallShape rejects well-formed JSON that is not a tool call: the
// top-level value must be an object, and a "tool" member, when present, must
// be a string. Without this check, null and {"tool":null} decode into an
// empty call and are denied as invalid_call instead of being reported as
// input errors. The line must already have passed checkJSONStructure.
func checkToolCallShape(line []byte) error {
	value := bytes.TrimLeft(line, jsonWhitespace)
	if len(value) == 0 || value[0] != '{' {
		return errors.New("top-level value must be a JSON object")
	}

	// A struct matches the member name the same way as decoding the call.
	var shape struct {
		Tool json.RawMessage `json:"tool"`
	}
	if err := json.Unmarshal(value, &shape); err != nil {
		return jsonError(err)
	}
	if shape.Tool != nil && shape.Tool[0] != '"' {
		return errors.New(`field "tool" must be a JSON string`)
	}
	return nil
}

func jsonError(err error) error {
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return errors.New("unexpected end of JSON input")
	}
	return err
}
