package policy

import (
	"strings"
	"testing"
)

const (
	tLog     = "5e423033044f56a13a686799487bcbfa63dd1e39204cec27dd39a26daa615628"
	tTestigo = "dd7e84d010aed28a416e928f50c4c09ac0f94a8f5b346548168bddb61cdb7263"
	tA       = "03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8"
	tB       = "29acbae141bccaf0b22e1a94d34d0bc7361e526d0bfe12c89794bc9322966dd7"
	tC       = "2543b92ff1095511476adc8369db6ddc933665a11978dda1404ee1066ca9559d"
)

func politica(extra string) string {
	return `{"origin":"nucleoledger.com/mi-empresa","logKey":"` + tLog + `",` + extra +
		`"witnesses":{"w1":"` + tTestigo + `"},"quorum":1}`
}

// TestCorte (ADR-033 §A): el corte es 0|[1-9][0-9]* y ≤ 2^53 − 1. La gramática de quorum
// admite signo; la del corte, no: «-0» y «-1» son inválidos.
func TestCorte(t *testing.T) {
	for s, want := range map[string]bool{
		"0": true, "41": true, "9007199254740991": true,
		"9007199254740992": false, "-0": false, "-1": false, "01": false, "1e0": false,
		"1.0": false, "": false, "18446744073709551616": false,
	} {
		if _, ok := corte(s); ok != want {
			t.Errorf("corte(%q) = %v, want %v", s, ok, want)
		}
	}
}

// TestRetiradasSeGuardan: las claves retiradas se leen con su corte, la clave ML-DSA se
// guarda tal cual, y ErasureAuthority las entrega, con erasureKey y sin ella.
func TestRetiradasSeGuardan(t *testing.T) {
	mldsa := strings.Repeat("ab", 1312)
	f, err := Parse([]byte(politica(`"erasureKey":"` + tB + `","retiredErasureKeys":{"` + tC + `":7,"` + tA + `":41},"logMLDSAKey":"` + mldsa + `",`)))
	if err != nil {
		t.Fatal(err)
	}
	if f.RetiredErasureKeys[tA] != 41 || f.RetiredErasureKeys[tC] != 7 || len(f.RetiredErasureKeys) != 2 {
		t.Errorf("retiradas = %v", f.RetiredErasureKeys)
	}
	if got := f.RetiredKeys(); len(got) != 2 || got[0] != tA || got[1] != tC {
		t.Errorf("RetiredKeys = %v, want en orden", got)
	}
	if f.LogMLDSAKey != mldsa {
		t.Error("logMLDSAKey no se guardó")
	}
	a := f.ErasureAuthority()
	if a.Origin != f.Origin || len(a.Key) != 32 || a.Retired[tA] != 41 || a.Retired[tC] != 7 {
		t.Errorf("ErasureAuthority = %+v", a)
	}
	if wp := f.WitnessPolicy(); len(wp.RetiredErasureKeys) != 2 {
		t.Errorf("la política de apertura no lleva las retiradas: %v", wp.RetiredErasureKeys)
	}

	sin, err := Parse([]byte(politica(`"retiredErasureKeys":{"` + tA + `":41},`)))
	if err != nil {
		t.Fatal(err)
	}
	a = sin.ErasureAuthority()
	if a.Key != nil || a.Retired[tA] != 41 || a.Origin == "" {
		t.Errorf("sin erasureKey: ErasureAuthority = %+v", a)
	}

	// Sin ninguna de las dos, la autoridad está vacía, como en 0.7-draft.
	nada, err := Parse([]byte(politica("")))
	if err != nil {
		t.Fatal(err)
	}
	if a := nada.ErasureAuthority(); a.Key != nil || a.Retired != nil || nada.RetiredErasureKeys != nil {
		t.Errorf("sin claves: %+v", a)
	}
}
