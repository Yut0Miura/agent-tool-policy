package cli

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/Yut0Miura/agent-tool-policy/policy"
)

// maxLineBytes is the largest accepted input line, 1 MiB.
const maxLineBytes = 1048576

// evaluateStream reads JSONL tool calls, evaluates each one against the same
// Run, and writes one compact decision per line. It stops at the first
// malformed line; decisions already written stay written.
func evaluateStream(run *policy.Run, stdin io.Reader, stdout, stderr io.Writer) int {
	scanner := bufio.NewScanner(stdin)
	scanner.Buffer(make([]byte, 64*1024), maxLineBytes+64*1024)
	encoder := json.NewEncoder(stdout)

	line := 0
	for scanner.Scan() {
		line++
		raw := scanner.Bytes()
		if len(raw) > maxLineBytes {
			return oversized(stderr, line)
		}
		if strings.TrimSpace(string(raw)) == "" {
			continue
		}

		call, err := decodeToolCall(raw)
		if err != nil {
			fmt.Fprintf(stderr, "line %d: invalid tool call: %v\n", line, err)
			return 2
		}
		if err := encoder.Encode(run.Evaluate(call)); err != nil {
			fmt.Fprintf(stderr, "output error: %v\n", err)
			return 1
		}
	}

	if err := scanner.Err(); err != nil {
		if errors.Is(err, bufio.ErrTooLong) {
			return oversized(stderr, line+1)
		}
		fmt.Fprintf(stderr, "input error: %v\n", err)
		return 2
	}
	return 0
}

func oversized(stderr io.Writer, line int) int {
	fmt.Fprintf(stderr, "line %d: input exceeds %d bytes\n", line, maxLineBytes)
	return 2
}

func decodeToolCall(raw []byte) (policy.ToolCall, error) {
	var call policy.ToolCall
	if err := checkJSONStructure(raw); err != nil {
		return call, err
	}

	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&call); err != nil {
		return policy.ToolCall{}, jsonError(err)
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return policy.ToolCall{}, errors.New("unexpected data after the first JSON value")
	}
	return call, nil
}
