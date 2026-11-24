package reconcile

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/nucleoledger/nucleo/internal/erasure"
	"github.com/nucleoledger/nucleo/internal/ledger"
)

// vectorAnulacion es testdata/vectors/void/reconcile.json (PROTOCOL 0.9-draft §5.2,
// ADR-035): cadenas completas, el sistema vivo descrito por índices, y el veredicto
// escrito a mano por void/generar.py, fuera de este código.
type vectorAnulacion struct {
	Origin string
	Policy struct {
		ErasureKey string `json:"erasureKey"`
	}
	Scenarios []struct {
		Name   string
		Blocks []*ledger.Block
		Live   struct {
			Present []uint64
			Changed []uint64
		}
		Expected struct {
			Voided []Voided
			Erased []struct {
				Index    uint64
				ErasedBy uint64 `json:"erased_by"`
			}
			Findings []struct {
				Status    Status
				Index     uint64
				Rule      string
				Reason    string
				FirstVoid *uint64 `json:"first_void"`
			}
			ExitCode int `json:"exit_code"`
		}
	}
}

func leeVectorAnulacion(t *testing.T) vectorAnulacion {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "vectors", "void", "reconcile.json"))
	if err != nil {
		t.Fatal(err)
	}
	var v vectorAnulacion
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	if len(v.Scenarios) != 23 {
		t.Fatalf("reconcile.json trae %d escenarios, want 23", len(v.Scenarios))
	}
	return v
}

// TestAnulacionVector recorre los 23 escenarios y exige voided, erased, findings (estado,
// índice, regla, motivo y, en R6, first_void) y el código de salida exactos. El código es
// el de la CLI: 2 si hay algún hallazgo (cmd/nucleo/reconcile.go).
func TestAnulacionVector(t *testing.T) {
	v := leeVectorAnulacion(t)
	k, err := hex.DecodeString(v.Policy.ErasureKey)
	if err != nil {
		t.Fatal(err)
	}
	auth := erasure.Authority{Origin: v.Origin, Key: k}
	for _, sc := range v.Scenarios {
		t.Run(sc.Name, func(t *testing.T) {
			var vivos []Record
			for _, i := range sc.Live.Present {
				vivos = append(vivos, Record{Index: i, hashActual: sc.Blocks[i].Header.PayloadHash})
			}
			for _, i := range sc.Live.Changed {
				vivos = append(vivos, Record{Index: i, Payload: []byte(`{"estado":"anulada"}`)})
			}
			rep, err := Reconcile(ledgerEnMemoria(sc.Blocks), FromSlice(vivos), Options{Erasure: auth})
			if err != nil {
				t.Fatal(err)
			}
			want := sc.Expected
			if want.Voided == nil {
				want.Voided = []Voided{}
			}
			if !slices.Equal(rep.Voided, want.Voided) {
				t.Errorf("voided = %+v\nwant     %+v", rep.Voided, want.Voided)
			}
			var gotE, wantE []string
			for _, x := range rep.Erased {
				gotE = append(gotE, fmt.Sprintf("%d por %d", x.Index, x.ErasedBy))
			}
			for _, x := range want.Erased {
				wantE = append(wantE, fmt.Sprintf("%d por %d", x.Index, x.ErasedBy))
			}
			if !slices.Equal(gotE, wantE) {
				t.Errorf("erased = %v, want %v", gotE, wantE)
			}
			linea := func(st Status, i uint64, regla, motivo string, primera *uint64) string {
				s := fmt.Sprintf("%s %d %s %q", st, i, regla, motivo)
				if primera != nil {
					s += fmt.Sprintf(" primera %d", *primera)
				}
				return s
			}
			var gotF, wantF []string
			for _, f := range rep.Findings {
				motivo := f.Reason
				// El motivo de R6 no está en el vector, que fija first_void.
				if f.Status == StatusRepeatedVoid {
					motivo = ""
				}
				gotF = append(gotF, linea(f.Status, f.Index, f.Rule, motivo, f.FirstVoid))
			}
			for _, f := range want.Findings {
				wantF = append(wantF, linea(f.Status, f.Index, f.Rule, f.Reason, f.FirstVoid))
			}
			slices.Sort(gotF)
			slices.Sort(wantF)
			if !slices.Equal(gotF, wantF) {
				t.Errorf("findings:\n got  %q\n want %q", gotF, wantF)
			}
			codigo := 0
			if len(rep.Findings) > 0 {
				codigo = 2
			}
			if codigo != want.ExitCode {
				t.Errorf("código de salida = %d, want %d", codigo, want.ExitCode)
			}
		})
	}
}

// TestVoidedSiempreEsArray: sin anulaciones, voided sale como [] y no como null ni
// ausente (ajuste A1 de ADR-035).
func TestVoidedSiempreEsArray(t *testing.T) {
	rep, err := Reconcile(ledgerEnMemoria{}, FromSlice(nil), Options{})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := rep.JSON()
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	if string(m["voided"]) != "[]" {
		t.Errorf("voided = %s, want []", m["voided"])
	}
}
