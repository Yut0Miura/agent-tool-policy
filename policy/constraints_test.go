package policy

import (
	"encoding/json"
	"math"
	"testing"
)

const constraintPolicy = `version: 1
default: deny
budget:
  max_calls: 1000
tools:
  strings:
    effect: allow
    max_calls: 1000
    arguments:
      optional:
        type: string
        required: false
      limited:
        type: string
        required: false
        max_length: 5
      listed:
        type: string
        required: false
        enum:
          - api
          - worker
      prefixed:
        type: string
        required: false
        prefix: "docs:"
      combined:
        type: string
        required: false
        max_length: 10
        prefix: "docs:"
  numbers:
    effect: allow
    max_calls: 1000
    arguments:
      bounded:
        type: number
        required: false
        min: 1
        max: 10
      free:
        type: number
        required: false
  flags:
    effect: allow
    max_calls: 1000
    arguments:
      verbose:
        type: boolean
        required: false
`

func evaluateArgument(t *testing.T, tool, name string, value any) Decision {
	t.Helper()
	run := mustLoad(t, constraintPolicy).NewRun()
	return run.Evaluate(ToolCall{Tool: tool, Arguments: map[string]any{name: value}})
}

func assertCode(t *testing.T, decision Decision, want string) {
	t.Helper()
	if decision.Code != want {
		t.Fatalf("code = %q (%s), want %q", decision.Code, decision.Reason, want)
	}
}

func TestOptionalArgumentMayBeAbsent(t *testing.T) {
	run := mustLoad(t, constraintPolicy).NewRun()
	assertCode(t, run.Evaluate(ToolCall{Tool: "strings"}), codeAllowed)
}

func TestRuntimeNullIsATypeMismatch(t *testing.T) {
	assertCode(t, evaluateArgument(t, "strings", "optional", nil), codeArgumentTypeMismatch)
}

func TestStringConstraints(t *testing.T) {
	tests := []struct {
		name     string
		argument string
		value    any
		want     string
	}{
		{"wrong type", "optional", 42, codeArgumentTypeMismatch},
		{"within length", "limited", "12345", codeAllowed},
		{"too long", "limited", "123456", codeStringTooLong},
		{"unicode length counts runes", "limited", "ünïcödé", codeStringTooLong},
		{"unicode within length", "limited", "ünïcö", codeAllowed},
		{"enum member", "listed", "api", codeAllowed},
		{"enum case sensitive", "listed", "API", codeStringEnumMismatch},
		{"enum outsider", "listed", "database", codeStringEnumMismatch},
		{"prefix present", "prefixed", "docs:intro", codeAllowed},
		{"prefix missing", "prefixed", "notes:intro", codeStringPrefixMismatch},
		{"prefix case sensitive", "prefixed", "Docs:intro", codeStringPrefixMismatch},
		{"combined constraints pass", "combined", "docs:intro", codeAllowed},
		{"combined length wins", "combined", "docs:introduction", codeStringTooLong},
		{"combined prefix fails", "combined", "notes:one", codeStringPrefixMismatch},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assertCode(t, evaluateArgument(t, "strings", test.argument, test.value), test.want)
		})
	}
}

func TestNumericTypes(t *testing.T) {
	tests := []struct {
		name  string
		value any
		want  string
	}{
		{"int", int(5), codeAllowed},
		{"int8", int8(5), codeAllowed},
		{"int16", int16(5), codeAllowed},
		{"int32", int32(5), codeAllowed},
		{"int64", int64(5), codeAllowed},
		{"uint", uint(5), codeAllowed},
		{"uint8", uint8(5), codeAllowed},
		{"uint16", uint16(5), codeAllowed},
		{"uint32", uint32(5), codeAllowed},
		{"uint64", uint64(5), codeAllowed},
		{"float32", float32(5), codeAllowed},
		{"float64", float64(5), codeAllowed},
		{"json.Number", json.Number("5"), codeAllowed},
		{"json.Number fractional", json.Number("5.5"), codeAllowed},
		{"json.Number malformed", json.Number("five"), codeArgumentTypeMismatch},
		{"string", "5", codeArgumentTypeMismatch},
		{"boolean", true, codeArgumentTypeMismatch},
		{"NaN", math.NaN(), codeArgumentTypeMismatch},
		{"positive infinity", math.Inf(1), codeArgumentTypeMismatch},
		{"negative infinity", math.Inf(-1), codeArgumentTypeMismatch},
		{"safe integer limit", int64(safeInteger), codeAllowed},
		{"beyond safe integer", int64(safeInteger + 1), codeArgumentTypeMismatch},
		{"unsigned beyond safe integer", uint64(safeInteger + 1), codeArgumentTypeMismatch},
		{"negative beyond safe integer", int64(-safeInteger - 1), codeArgumentTypeMismatch},
		{"float beyond safe integer", float64(safeInteger) * 2, codeArgumentTypeMismatch},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assertCode(t, evaluateArgument(t, "numbers", "free", test.value), test.want)
		})
	}
}

func TestNumericBounds(t *testing.T) {
	tests := []struct {
		name  string
		value any
		want  string
	}{
		{"inclusive minimum", 1, codeAllowed},
		{"inclusive maximum", 10, codeAllowed},
		{"below minimum", 0, codeNumberBelowMin},
		{"above maximum", 11, codeNumberAboveMax},
		{"fractional below minimum", 0.99, codeNumberBelowMin},
		{"fractional above maximum", 10.01, codeNumberAboveMax},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assertCode(t, evaluateArgument(t, "numbers", "bounded", test.value), test.want)
		})
	}
}

func TestBooleanArgument(t *testing.T) {
	assertCode(t, evaluateArgument(t, "flags", "verbose", true), codeAllowed)
	assertCode(t, evaluateArgument(t, "flags", "verbose", false), codeAllowed)
	assertCode(t, evaluateArgument(t, "flags", "verbose", "true"), codeArgumentTypeMismatch)
	assertCode(t, evaluateArgument(t, "flags", "verbose", 1), codeArgumentTypeMismatch)
}

func TestTypeIsCheckedBeforeOtherConstraints(t *testing.T) {
	// A value of the wrong type never reaches the length or enum checks.
	assertCode(t, evaluateArgument(t, "strings", "limited", 123456789), codeArgumentTypeMismatch)
}
