package ledger

import (
	"errors"
	"math"
	"testing"
)

// TestSizeToIntEnLosValoresLimite: el mayor valor que cabe pasa tal cual, y el
// siguiente —y el máximo de uint64— fallan con ErrSizeRange en vez de volverse
// negativos. Los límites son las constantes de math, no un cálculo de esta función.
func TestSizeToIntEnLosValoresLimite(t *testing.T) {
	if n, err := SizeToInt(math.MaxInt); err != nil || n != math.MaxInt {
		t.Errorf("SizeToInt(MaxInt) = %d, %v", n, err)
	}
	for _, n := range []uint64{math.MaxInt + 1, math.MaxUint64} {
		if got, err := SizeToInt(n); !errors.Is(err, ErrSizeRange) {
			t.Errorf("SizeToInt(%d) = %d, %v; want ErrSizeRange", n, got, err)
		}
	}
	if n, err := SizeToInt64(math.MaxInt64); err != nil || n != math.MaxInt64 {
		t.Errorf("SizeToInt64(MaxInt64) = %d, %v", n, err)
	}
	for _, n := range []uint64{math.MaxInt64 + 1, math.MaxUint64} {
		if got, err := SizeToInt64(n); !errors.Is(err, ErrSizeRange) {
			t.Errorf("SizeToInt64(%d) = %d, %v; want ErrSizeRange", n, got, err)
		}
	}
	if n, err := SizeToInt(0); err != nil || n != 0 {
		t.Errorf("SizeToInt(0) = %d, %v", n, err)
	}
}
