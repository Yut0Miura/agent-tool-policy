package policy

import (
	"encoding/json"
	"math"
)

// safeInteger is 2^53-1, the largest integer a float64 represents exactly.
// Comparisons are only defined inside this domain.
const safeInteger = 9007199254740991

// normalizeNumber converts a supported runtime numeric value to float64. It
// reports false for unsupported types, for NaN and infinities, and for values
// outside the exact comparison domain.
func normalizeNumber(v any) (float64, bool) {
	switch n := v.(type) {
	case json.Number:
		f, err := n.Float64()
		if err != nil {
			return 0, false
		}
		return checkFloat(f)
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
		return 0, false
	}
}

func checkFloat(f float64) (float64, bool) {
	if math.IsNaN(f) || math.IsInf(f, 0) || f < -safeInteger || f > safeInteger {
		return 0, false
	}
	return f, true
}

func checkInt(i int64) (float64, bool) {
	if i < -safeInteger || i > safeInteger {
		return 0, false
	}
	return float64(i), true
}

func checkUint(u uint64) (float64, bool) {
	if u > safeInteger {
		return 0, false
	}
	return float64(u), true
}
