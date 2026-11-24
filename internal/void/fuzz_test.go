package void

import (
	"math/big"
	"regexp"
	"testing"
)

// La referencia independiente de R1: una expresión regular y la cota, con math/big para
// que la cota no dependa del mismo ParseUint que usa el parser.
var formaCID = regexp.MustCompile(`^nucleo-void@v1:(0|[1-9][0-9]*)$`)

var cotaCID = new(big.Int).SetUint64(1<<53 - 1)

func referenciaCID(s string) (uint64, bool) {
	m := formaCID.FindStringSubmatch(s)
	if m == nil {
		return 0, false
	}
	n, ok := new(big.Int).SetString(m[1], 10)
	if !ok || n.Cmp(cotaCID) > 0 {
		return 0, false
	}
	return n.Uint64(), true
}

// FuzzCidAnulacion: ParseCID acepta exactamente lo que acepta la referencia, con el mismo
// índice, y lo que acepta vuelve a escribirse igual con CID.
func FuzzCidAnulacion(f *testing.F) {
	for _, s := range []string{
		"nucleo-void@v1:0", "nucleo-void@v1:3", "nucleo-void@v1:9007199254740991",
		"nucleo-void@v1:9007199254740992", "nucleo-void@v1:03", "nucleo-void@v1:-1",
		"nucleo-void@v1:", "nucleo-void@v2:3", "nucleo-void@v1:3 ", "none://",
		"nucleo-void@v1:+3", "nucleo-void@v1:18446744073709551616", "nucleo-void@v1:٣",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		got, err := ParseCID(s)
		want, ok := referenciaCID(s)
		if (err == nil) != ok {
			t.Fatalf("ParseCID(%q): err = %v; la referencia dice válido = %v", s, err, ok)
		}
		if !ok {
			return
		}
		if got != want {
			t.Fatalf("ParseCID(%q) = %d, want %d", s, got, want)
		}
		if CID(got) != s {
			t.Fatalf("CID(%d) = %q, want %q", got, CID(got), s)
		}
	})
}
