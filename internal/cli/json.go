// Package cli implements the command line interface of Agent Tool Policy.
// It wraps the policy library and adds no policy behaviour of its own.
package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// maxNesting is the deepest object or array nesting accepted in one input
// line.
const maxNesting = 64

// checkJSONStructure validates the token structure of one input line before
// it is decoded: exactly one JSON value, no duplicate object member at any
// depth, and nesting within the limit.
func checkJSONStructure(line []byte) error {
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
	return nil
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

func jsonError(err error) error {
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return errors.New("unexpected end of JSON input")
	}
	return err
}
