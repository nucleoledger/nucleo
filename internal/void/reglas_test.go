package void

import (
	"fmt"
	"slices"
	"testing"

	"github.com/nucleoledger/nucleo/internal/ledger"
)

// escenarioVoid es lo que este paquete necesita de un escenario de reconcile.json: la
// cadena y, del veredicto escrito a mano, las anulaciones válidas y los hallazgos.
type escenarioVoid struct {
	Name     string
	Blocks   []*ledger.Block
	Expected struct {
		Voided []struct {
			Index    uint64
			VoidedBy uint64 `json:"voided_by"`
		}
		Findings []struct {
			Status    string
			Index     uint64
			Rule      string
			Reason    string
			FirstVoid *uint64 `json:"first_void"`
		}
	}
}

// TestLasReglasCoincidenConLosEscenarios: Evaluate da, en cada escenario de
// reconcile.json, exactamente las anulaciones válidas y los hallazgos de anulación del
// veredicto escrito a mano (la regla, el motivo y, en R6, la primera anulación).
func TestLasReglasCoincidenConLosEscenarios(t *testing.T) {
	var v struct {
		Statuses  map[string]string
		Scenarios []escenarioVoid
	}
	leeVector(t, "reconcile.json", &v)
	if len(v.Scenarios) != 23 {
		t.Fatalf("reconcile.json: %d escenarios, want 23", len(v.Scenarios))
	}
	for _, sc := range v.Scenarios {
		t.Run(sc.Name, func(t *testing.T) {
			res := Evaluate(sc.Blocks)
			var got, want []string
			for _, x := range res.Valid {
				got = append(got, fmt.Sprintf("válida %d→%d", x.Event.Header.Index, x.Target.Header.Index))
			}
			for _, x := range res.Invalid {
				s := fmt.Sprintf("%d %s %q", x.Event.Header.Index, x.Rule, x.Reason)
				if x.Rule == "R6" {
					s += fmt.Sprintf(" primera %d", x.FirstVoid)
				}
				got = append(got, s)
			}
			for _, x := range sc.Expected.Voided {
				want = append(want, fmt.Sprintf("válida %d→%d", x.VoidedBy, x.Index))
			}
			for _, f := range sc.Expected.Findings {
				switch f.Status {
				case v.Statuses["invalid"]:
					want = append(want, fmt.Sprintf("%d %s %q", f.Index, f.Rule, f.Reason))
				case v.Statuses["repeated"]:
					if f.FirstVoid == nil {
						t.Fatal("el vector de R6 no trae first_void")
					}
					// El motivo de R6 no está en el vector: lo que fija es first_void.
					var motivo string
					for _, x := range res.Invalid {
						if x.Event.Header.Index == f.Index {
							motivo = x.Reason
						}
					}
					want = append(want, fmt.Sprintf("%d R6 %q primera %d", f.Index, motivo, *f.FirstVoid))
				}
			}
			slices.Sort(got)
			slices.Sort(want)
			if !slices.Equal(got, want) {
				t.Errorf("Evaluate:\n got  %q\n want %q", got, want)
			}
		})
	}
}

func TestVoidOf(t *testing.T) {
	a := &ledger.Block{Header: ledger.Header{Index: 3}}
	r := Result{Valid: []Valid{{Event: &ledger.Block{Header: ledger.Header{Index: 4}}, Target: a}}}
	if x := r.VoidOf(3); x == nil || x.Event.Header.Index != 4 {
		t.Errorf("VoidOf(3) = %v", x)
	}
	if r.VoidOf(2) != nil {
		t.Error("VoidOf(2) no es nil")
	}
}
