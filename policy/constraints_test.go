package policy

import (
	"encoding/json"
	"fmt"
	"math"
	"strings"
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

// enumPolicy returns a policy whose pick tool takes one required string
// argument restricted to size enum values.
func enumPolicy(size int) string {
	var policy strings.Builder
	policy.WriteString("version: 1\ndefault: deny\nbudget:\n  max_calls: 1000\ntools:\n" +
		"  pick:\n    effect: allow\n    max_calls: 1000\n    arguments:\n" +
		"      choice:\n        type: string\n        required: true\n        enum:\n")
	for i := 0; i < size; i++ {
		fmt.Fprintf(&policy, "          - %s\n", enumValue(i))
	}
	return policy.String()
}

func enumValue(i int) string {
	return fmt.Sprintf("value_%04d", i)
}

func TestLargeEnum(t *testing.T) {
	run := mustLoad(t, enumPolicy(1000)).NewRun()
	tests := []struct {
		name  string
		value string
		want  string
	}{
		{"first member", enumValue(0), codeAllowed},
		{"middle member", enumValue(500), codeAllowed},
		{"last member", enumValue(999), codeAllowed},
		{"outsider", enumValue(1000), codeStringEnumMismatch},
		{"case sensitive", strings.ToUpper(enumValue(999)), codeStringEnumMismatch},
		{"prefix of a member", "value_", codeStringEnumMismatch},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			decision := run.Evaluate(ToolCall{Tool: "pick", Arguments: map[string]any{"choice": test.value}})
			assertCode(t, decision, test.want)
		})
	}
}

func TestEnumMismatchDecision(t *testing.T) {
	run := mustLoad(t, constraintPolicy).NewRun()
	decision := run.Evaluate(ToolCall{Tool: "strings", Arguments: map[string]any{"listed": "database"}})
	want := Decision{
		Effect: EffectDeny,
		Tool:   "strings",
		Code:   codeStringEnumMismatch,
		Reason: `argument "listed" is not an allowed value`,
	}
	if decision != want {
		t.Fatalf("decision = %+v, want %+v", decision, want)
	}
}

func BenchmarkEnumLookup(b *testing.B) {
	for _, size := range []int{10, 100, 1000} {
		b.Run(fmt.Sprintf("size=%d", size), func(b *testing.B) {
			engine, err := Load([]byte(enumPolicy(size)))
			if err != nil {
				b.Fatalf("Load() error = %v", err)
			}
			argument := engine.tools["pick"].arguments["choice"]
			// The last member is the worst case for a linear search.
			value := enumValue(size - 1)

			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if code, _ := checkArgument("choice", argument, value); code != "" {
					b.Fatalf("code = %q, want accepted", code)
				}
			}
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

const decimalBoundPolicy = `version: 1
default: deny
budget:
  max_calls: 1000
tools:
  numbers:
    effect: allow
    max_calls: 1000
    arguments:
      ratio:
        type: number
        required: false
        min: 0.1
      ceiling:
        type: number
        required: false
        max: 0
`

func TestJSONNumbersAreComparedWithoutRounding(t *testing.T) {
	tests := []struct {
		name     string
		argument string
		value    any
		want     string
	}{
		{"decimal equal to minimum", "ratio", json.Number("0.1"), codeAllowed},
		{"decimal just below minimum", "ratio", json.Number("0.09999999999999999999999"), codeNumberBelowMin},
		{"decimal above minimum", "ratio", json.Number("0.11"), codeAllowed},
		{"exponent equal to minimum", "ratio", json.Number("1E-1"), codeAllowed},
		{"zero at maximum", "ceiling", json.Number("0"), codeAllowed},
		{"negative zero at maximum", "ceiling", json.Number("-0.0"), codeAllowed},
		{"zero with large exponent", "ceiling", json.Number("0e999999999"), codeAllowed},
		{"tiny value above maximum", "ceiling", json.Number("1e-400"), codeNumberAboveMax},
		{"tiny negative value", "ceiling", json.Number("-1e-400"), codeAllowed},
		{"float64 equal to minimum", "ratio", 0.1, codeAllowed},
		{"float64 below minimum", "ratio", 0.09, codeNumberBelowMin},
		{"integer at maximum", "ceiling", 0, codeAllowed},
		{"integer above maximum", "ceiling", int64(1), codeNumberAboveMax},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			run := mustLoad(t, decimalBoundPolicy).NewRun()
			decision := run.Evaluate(ToolCall{Tool: "numbers", Arguments: map[string]any{test.argument: test.value}})
			assertCode(t, decision, test.want)
		})
	}
}

func TestJSONNumberGrammarAndDomain(t *testing.T) {
	tests := []struct {
		name  string
		value json.Number
		want  string
	}{
		{"safe integer limit", "9007199254740991", codeAllowed},
		{"negative safe integer limit", "-9007199254740991", codeAllowed},
		{"exponent within domain", "9.007199254740991e15", codeAllowed},
		{"leading zero", "01", codeArgumentTypeMismatch},
		{"plus sign", "+1", codeArgumentTypeMismatch},
		{"missing integer part", ".5", codeArgumentTypeMismatch},
		{"missing fraction digits", "1.", codeArgumentTypeMismatch},
		{"missing exponent digits", "1e+", codeArgumentTypeMismatch},
		{"surrounding space", " 1", codeArgumentTypeMismatch},
		{"beyond safe integer", "9007199254740992", codeArgumentTypeMismatch},
		{"negative beyond safe integer", "-9007199254740992", codeArgumentTypeMismatch},
		{"fraction beyond safe integer", "9007199254740991.5", codeArgumentTypeMismatch},
		{"exponent beyond safe integer", "1e16", codeArgumentTypeMismatch},
		{"NaN", "NaN", codeArgumentTypeMismatch},
		{"infinity", "Infinity", codeArgumentTypeMismatch},
		{"negative infinity", "-Infinity", codeArgumentTypeMismatch},
		{"huge exponent", "1e999999999", codeArgumentTypeMismatch},
		{"huge negative exponent", "1e-999999999", codeArgumentTypeMismatch},
		{"long exponent", json.Number("1e" + strings.Repeat("9", 1000)), codeArgumentTypeMismatch},
		{"long significand", json.Number("0." + strings.Repeat("1", 2000)), codeArgumentTypeMismatch},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assertCode(t, evaluateArgument(t, "numbers", "free", test.value), test.want)
		})
	}
}

func TestBooleanArgument(t *testing.T) {
	assertCode(t, evaluateArgument(t, "flags", "verbose", true), codeAllowed)
	assertCode(t, evaluateArgument(t, "flags", "verbose", false), codeAllowed)
	assertCode(t, evaluateArgument(t, "flags", "verbose", "true"), codeArgumentTypeMismatch)
	assertCode(t, evaluateArgument(t, "flags", "verbose", 1), codeArgumentTypeMismatch)
}

func TestInvalidUTF8StringIsATypeMismatch(t *testing.T) {
	for _, value := range []string{"\xff", "a\xc3", "\xed\xa0\x80"} {
		decision := evaluateArgument(t, "strings", "optional", value)
		if decision.Effect != EffectDeny {
			t.Errorf("value %q: effect = %q, want %q", value, decision.Effect, EffectDeny)
		}
		assertCode(t, decision, codeArgumentTypeMismatch)
		if want := `argument "optional" has invalid type`; decision.Reason != want {
			t.Errorf("value %q: reason = %q, want %q", value, decision.Reason, want)
		}
	}
}

const unicodePolicy = `version: 1
default: deny
budget:
  max_calls: 100
tools:
  menu:
    effect: allow
    max_calls: 100
    arguments:
      section:
        type: string
        required: false
        prefix: "caf\u00e9:"
      word:
        type: string
        required: false
        enum:
          - "\u00fcber"
          - "\U0001F600"
`

func TestUnicodePrefixAndEnumAreExact(t *testing.T) {
	tests := []struct {
		name     string
		argument string
		value    string
		want     string
	}{
		{"precomposed prefix", "section", "caf\u00e9:drinks", codeAllowed},
		{"decomposed prefix is not normalized", "section", "cafe\u0301:drinks", codeStringPrefixMismatch},
		{"precomposed enum value", "word", "\u00fcber", codeAllowed},
		{"decomposed enum value is not normalized", "word", "u\u0308ber", codeStringEnumMismatch},
		{"supplementary plane enum value", "word", "\U0001F600", codeAllowed},
		{"replacement character", "word", "\ufffd", codeStringEnumMismatch},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			run := mustLoad(t, unicodePolicy).NewRun()
			decision := run.Evaluate(ToolCall{Tool: "menu", Arguments: map[string]any{test.argument: test.value}})
			assertCode(t, decision, test.want)
		})
	}
}

func TestTypeIsCheckedBeforeOtherConstraints(t *testing.T) {
	// A value of the wrong type never reaches the length or enum checks.
	assertCode(t, evaluateArgument(t, "strings", "limited", 123456789), codeArgumentTypeMismatch)
}
