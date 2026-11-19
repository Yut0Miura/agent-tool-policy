package policy

import (
	"encoding/json"
	"math"
	"math/big"
	"reflect"
	"strings"

	yaml "go.yaml.in/yaml/v3"
)

// safeInteger is 2^53-1, the largest integer a float64 represents exactly.
// Comparisons are only defined inside this domain.
const safeInteger = 9007199254740991

// Decimal text is converted to an exact value only within fixed limits, so
// that the cost of a comparison stays bounded however a number is written.
const (
	// maxDecimalLength is the longest decimal text accepted.
	maxDecimalLength = 1024
	// maxExponentDigits bounds the exponent of a decimal, leading zeros
	// excluded.
	maxExponentDigits = 6
	// minDecimalExponent is the smallest power of ten of the leading digit
	// of a non-zero decimal.
	minDecimalExponent = -1024
	// maxDecimalExponent is the largest power of ten of the leading digit
	// of a decimal inside the safe integer domain.
	maxDecimalExponent = 15
)

// numberBound is a min or max bound of a number argument. value is the
// float64 decoded from YAML, compared with Go numeric values. exact is the
// decimal written in the policy, compared with JSON numbers; it is nil when
// the bound has no supported exact value.
type numberBound struct {
	value float64
	exact *big.Rat
}

// UnmarshalYAML decodes a bound and keeps the exact decimal it is written as.
func (bound *numberBound) UnmarshalYAML(node *yaml.Node) error {
	var value float64
	if err := node.Decode(&value); err != nil {
		return err
	}
	bound.value = value
	bound.exact = nil

	if text, ok := splitDecimal(node.Value, false); ok {
		exact, ok := text.rat()
		if !ok {
			return nil
		}
		// The decimal is kept only when it is the number YAML decoded.
		if rounded, _ := exact.Float64(); rounded == value {
			bound.exact = exact
			return nil
		}
	}
	// Other notations, such as hexadecimal integers, carry no decimal text.
	// SetFloat64 returns nil for NaN and infinities.
	bound.exact = new(big.Rat).SetFloat64(value)
	return nil
}

// supported reports whether the bound is finite and inside the exact
// comparison domain.
func (bound *numberBound) supported() bool {
	return bound.exact != nil && inSafeDomain(bound.value) && inSafeRange(bound.exact)
}

// numericValue is a supported runtime numeric value. A json.Number keeps
// the exact decimal it is written as. Go numeric values keep their float64
// value: their decimal source text is no longer available.
type numericValue struct {
	value float64
	exact *big.Rat
}

// compare returns -1, 0 or +1 as the value is below, equal to or above the
// bound.
func (number numericValue) compare(bound *numberBound) int {
	if number.exact != nil {
		return number.exact.Cmp(bound.exact)
	}
	switch {
	case number.value < bound.value:
		return -1
	case number.value > bound.value:
		return 1
	default:
		return 0
	}
}

// normalizeNumber converts a supported runtime numeric value for comparison
// with policy bounds. Built-in numeric types and json.Number are matched
// directly; named numeric types fall back to their reflect.Kind. It reports
// false for unsupported types, for NaN and infinities, for malformed JSON
// numbers and for values outside the exact comparison domain.
func normalizeNumber(v any) (numericValue, bool) {
	switch n := v.(type) {
	case json.Number:
		return checkJSONNumber(n)
	case float32:
		return checkFloat(float64(n))
	case float64:
		return checkFloat(n)
	case int:
		return checkInt(int64(n))
	case int8:
		return checkInt(int64(n))
	case int16:
		return checkInt(int64(n))
	case int32:
		return checkInt(int64(n))
	case int64:
		return checkInt(n)
	case uint:
		return checkUint(uint64(n))
	case uint8:
		return checkUint(uint64(n))
	case uint16:
		return checkUint(uint64(n))
	case uint32:
		return checkUint(uint64(n))
	case uint64:
		return checkUint(n)
	default:
		return normalizeNamedNumber(v)
	}
}

// normalizeNamedNumber accepts a named type whose underlying type is a Go
// integer or floating-point type, such as type TokenCount int64, and checks
// it with the same rules as the built-in types. Pointers, complex numbers,
// strings, booleans, structs and every other kind are not numbers. A
// json.Number is handled before this fallback, so a string kind is never
// read as a number here.
func normalizeNamedNumber(v any) (numericValue, bool) {
	value := reflect.ValueOf(v)
	switch value.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return checkInt(value.Int())
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return checkUint(value.Uint())
	case reflect.Float32, reflect.Float64:
		return checkFloat(value.Float())
	default:
		return numericValue{}, false
	}
}

// checkJSONNumber converts a JSON number to its exact decimal value without
// rounding it to a float64 first.
func checkJSONNumber(n json.Number) (numericValue, bool) {
	text, ok := splitDecimal(string(n), true)
	if !ok {
		return numericValue{}, false
	}
	exact, ok := text.rat()
	if !ok || !inSafeRange(exact) {
		return numericValue{}, false
	}
	return numericValue{exact: exact}, true
}

func checkFloat(f float64) (numericValue, bool) {
	if math.IsNaN(f) || math.IsInf(f, 0) || f < -safeInteger || f > safeInteger {
		return numericValue{}, false
	}
	return numericValue{value: f}, true
}

func checkInt(i int64) (numericValue, bool) {
	if i < -safeInteger || i > safeInteger {
		return numericValue{}, false
	}
	return numericValue{value: float64(i)}, true
}

func checkUint(u uint64) (numericValue, bool) {
	if u > safeInteger {
		return numericValue{}, false
	}
	return numericValue{value: float64(u)}, true
}

// inSafeRange reports whether an exact value lies within the safe integer
// domain.
func inSafeRange(value *big.Rat) bool {
	limit := new(big.Rat).SetInt64(safeInteger)
	return new(big.Rat).Abs(value).Cmp(limit) <= 0
}

// decimalText is the text of a decimal number split into its parts.
type decimalText struct {
	negative         bool
	integer          string
	fraction         string
	exponent         string
	negativeExponent bool
}

// splitDecimal splits decimal text. With strict set it accepts the JSON
// number grammar only; otherwise it accepts the YAML 1.2 decimal notation,
// which also allows a leading plus sign, leading zeros and an empty integer
// or fraction part.
func splitDecimal(text string, strict bool) (decimalText, bool) {
	var parts decimalText
	if text == "" || len(text) > maxDecimalLength {
		return parts, false
	}

	i := 0
	switch text[0] {
	case '-':
		parts.negative = true
		i++
	case '+':
		if strict {
			return parts, false
		}
		i++
	}

	parts.integer, i = scanDigits(text, i)
	if i < len(text) && text[i] == '.' {
		parts.fraction, i = scanDigits(text, i+1)
		if strict && parts.fraction == "" {
			return parts, false
		}
	}
	if parts.integer == "" && (strict || parts.fraction == "") {
		return parts, false
	}
	if strict && len(parts.integer) > 1 && parts.integer[0] == '0' {
		return parts, false
	}

	if i < len(text) && (text[i] == 'e' || text[i] == 'E') {
		i++
		if i < len(text) && (text[i] == '+' || text[i] == '-') {
			parts.negativeExponent = text[i] == '-'
			i++
		}
		parts.exponent, i = scanDigits(text, i)
		if parts.exponent == "" {
			return parts, false
		}
	}
	return parts, i == len(text)
}

func scanDigits(text string, i int) (string, int) {
	start := i
	for i < len(text) && text[i] >= '0' && text[i] <= '9' {
		i++
	}
	return text[start:i], i
}

// rat returns the exact value of the decimal. It reports false when the
// decimal lies outside the limits, so that no input builds an unbounded
// value.
func (parts decimalText) rat() (*big.Rat, bool) {
	significand := strings.TrimLeft(parts.integer+parts.fraction, "0")
	if significand == "" {
		return new(big.Rat), true
	}

	digits := strings.TrimLeft(parts.exponent, "0")
	if len(digits) > maxExponentDigits {
		return nil, false
	}
	scale := 0
	for _, digit := range digits {
		scale = scale*10 + int(digit-'0')
	}
	if parts.negativeExponent {
		scale = -scale
	}
	scale -= len(parts.fraction)

	// The value is significand * 10^scale.
	leading := scale + len(significand) - 1
	if leading < minDecimalExponent || leading > maxDecimalExponent {
		return nil, false
	}

	mantissa, _ := new(big.Int).SetString(significand, 10)
	power := scale
	if power < 0 {
		power = -power
	}
	factor := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(power)), nil)

	exact := new(big.Rat)
	if scale >= 0 {
		exact.SetInt(mantissa.Mul(mantissa, factor))
	} else {
		exact.SetFrac(mantissa, factor)
	}
	if parts.negative {
		exact.Neg(exact)
	}
	return exact, true
}
