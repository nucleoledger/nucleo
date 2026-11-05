package erasure

import (
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"

	"github.com/nucleoledger/nucleo/internal/ledger"
)

// VectorRotacion es testdata/vectors/erasure/rotacion.json: la política de cada caso, una
// cadena dispersa y el veredicto de cada evento escrito a mano desde PROTOCOL 0.8-draft
// §5.1 (ADR-033). Las firmas son de `cryptography`, no de este paquete.
type VectorRotacion struct {
	Origin string `json:"origin"`
	Cases  []struct {
		Name   string `json:"name"`
		Policy struct {
			ErasureKey         string            `json:"erasureKey"`
			RetiredErasureKeys map[string]uint64 `json:"retiredErasureKeys"`
		} `json:"policy"`
		Blocks []struct {
			Index       uint64 `json:"index"`
			Type        string `json:"type"`
			PayloadHash string `json:"payload_hash"`
			PayloadCID  string `json:"payload_cid"`
		} `json:"blocks"`
		Expected struct {
			Events []struct {
				Index        uint64  `json:"index"`
				Authorized   bool    `json:"authorized"`
				AuthorizedBy *string `json:"authorized_by"`
				Key          *string `json:"key"`
				Reason       string  `json:"reason"`
			} `json:"events"`
		} `json:"expected"`
	} `json:"cases"`
}

// TestRotacionVector: cada evento de rotacion.json, con Check. El contenido que suprime lo
// busca el test entre los bloques anteriores del caso (la condición 2 de §5.1, que en la
// cadena aplica internal/reconcile); los casos sin contenido anterior tienen que declarar
// el motivo no_erased_block.
func TestRotacionVector(t *testing.T) {
	var v VectorRotacion
	leeVector(t, "rotacion.json", &v)
	if len(v.Cases) < 10 {
		t.Fatalf("rotacion.json trae %d casos", len(v.Cases))
	}
	for _, c := range v.Cases {
		t.Run(c.Name, func(t *testing.T) {
			auth := Authority{Origin: v.Origin, Retired: c.Policy.RetiredErasureKeys}
			if c.Policy.ErasureKey != "" {
				auth.Key = clavePublica(t, c.Policy.ErasureKey)
			}
			eventos := map[uint64]int{}
			for i, b := range c.Blocks {
				if b.Type == Type {
					eventos[b.Index] = i
				}
			}
			if len(eventos) != len(c.Expected.Events) {
				t.Fatalf("%d eventos y %d veredictos", len(eventos), len(c.Expected.Events))
			}
			for _, want := range c.Expected.Events {
				b := c.Blocks[eventos[want.Index]]
				h := ""
				for _, prev := range c.Blocks {
					eph, err := EventPayloadHash(prev.PayloadHash)
					if prev.Index < b.Index && prev.Type != Type && err == nil && eph == b.PayloadHash {
						h = prev.PayloadHash
					}
				}
				if h == "" {
					if want.Reason != "no_erased_block" || want.Authorized {
						t.Errorf("evento %d: no suprime ningún contenido anterior y el vector dice %+v", want.Index, want)
					}
					continue
				}
				ev := &ledger.Block{Header: ledger.Header{Index: b.Index, Type: b.Type, PayloadHash: b.PayloadHash, PayloadCID: b.PayloadCID}}
				got, err := auth.Check(ev, h)
				if want.Authorized {
					if err != nil {
						t.Errorf("evento %d: debía estar autorizado: %v", want.Index, err)
						continue
					}
					porRetirada := *want.AuthorizedBy == "retiredErasureKeys"
					if got.Key != *want.Key || got.Retired != porRetirada {
						t.Errorf("evento %d: autorizado por %s (retirada %v), want %s por %s", want.Index, got.Key, got.Retired, *want.Key, *want.AuthorizedBy)
					}
					if porRetirada && got.Cutoff != c.Policy.RetiredErasureKeys[got.Key] {
						t.Errorf("evento %d: corte %d", want.Index, got.Cutoff)
					}
					continue
				}
				if err == nil {
					t.Errorf("evento %d: autorizado por %s, y el vector dice %s", want.Index, got.Key, want.Reason)
					continue
				}
				var ce *CutoffError
				switch want.Reason {
				case "retired_after_cutoff":
					if !errors.As(err, &ce) || ce.Index != want.Index {
						t.Errorf("evento %d: %v, want una clave retirada después de su corte", want.Index, err)
					}
				case "unknown_key":
					if errors.As(err, &ce) || !errors.Is(err, ErrNotAuthorized) {
						t.Errorf("evento %d: %v, want una clave que la política no lista", want.Index, err)
					}
				default:
					t.Errorf("evento %d: motivo %q que este test no conoce", want.Index, want.Reason)
				}
			}
		})
	}
}

// TestSegundaClaveVector: la autorización de la clave nueva de una rotación, sobre el
// mismo texto del vector de PROTOCOL §5.1.
func TestSegundaClaveVector(t *testing.T) {
	var v struct {
		PublicKey         string `json:"public_key"`
		Origin            string `json:"origin"`
		ErasedPayloadHash string `json:"erased_payload_hash"`
		Through           uint64 `json:"through"`
		PayloadCID        string `json:"payload_cid"`
	}
	leeVector(t, "autorizacion-segunda-clave.json", &v)
	through, err := VerifyCID(clavePublica(t, v.PublicKey), v.Origin, v.ErasedPayloadHash, v.PayloadCID)
	if err != nil || through != v.Through {
		t.Errorf("VerifyCID = %d, %v", through, err)
	}
}

// TestCheckEsDeterminista: si la misma clave verifica como actual y como retirada (una
// Authority que la política no permite construir, pero Check no lo sabe), se nombra la
// actual; y el error de una retirada fuera de su corte dice el corte y el índice.
func TestCheckEsDeterminista(t *testing.T) {
	var v VectorRotacion
	leeVector(t, "rotacion.json", &v)
	c := v.Cases[0] // a-40: el evento 40, firmado con A, suprime el bloque 10
	ev := &ledger.Block{Header: ledger.Header{Index: 40, Type: Type, PayloadHash: c.Blocks[1].PayloadHash, PayloadCID: c.Blocks[1].PayloadCID}}
	h := c.Blocks[0].PayloadHash
	const a = "03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8"
	got, err := Authority{Origin: v.Origin, Key: clavePublica(t, a), Retired: map[string]uint64{a: 41}}.Check(ev, h)
	if err != nil || got.Retired || got.Key != a {
		t.Errorf("la actual primero: %+v, %v", got, err)
	}
	_, err = Authority{Origin: v.Origin, Retired: map[string]uint64{a: 39}}.Check(ev, h)
	if err == nil || !strings.Contains(err.Error(), "después de su corte 39") || !strings.Contains(err.Error(), "este es el 40") {
		t.Errorf("motivo: %v", err)
	}
	// Sin ninguna clave, nada; con una clave que no es, el mensaje de siempre.
	if _, err := (Authority{Origin: v.Origin}).Check(ev, h); err == nil {
		t.Error("sin claves, autorizado")
	}
	otra := ed25519.NewKeyFromSeed(make([]byte, 32)).Public().(ed25519.PublicKey)
	if _, err := (Authority{Origin: v.Origin, Key: otra}).Check(ev, h); err == nil || !strings.Contains(err.Error(), "no verifica con la erasureKey") {
		t.Errorf("otra clave: %v", err)
	}
}
