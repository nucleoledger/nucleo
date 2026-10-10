package reconcile

import (
	"crypto/ed25519"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nucleoledger/nucleo/internal/erasure"
	"github.com/nucleoledger/nucleo/internal/ledger"
	"github.com/nucleoledger/nucleo/internal/store"
)

// TestUnRegistroSuprimidoNoEsUnFaltante (ADR-031): el sistema vivo borra un registro
// porque su titular lo pidió y Núcleo suprime su contenido. La reconciliación lo
// informa como suprimido —hay un evento sellado que lo dice— y no como un registro
// que desapareció; el evento mismo no le falta al sistema vivo, porque es de Núcleo.
//
// Y un evento solo vale hacia delante: si el mismo contenido se vuelve a sellar
// DESPUÉS de suprimirse, esa copia nueva no está suprimida y su ausencia sí es un
// hallazgo.
func TestUnRegistroSuprimidoNoEsUnFaltante(t *testing.T) {
	s, err := openLedger(t)
	if err != nil {
		t.Fatal(err)
	}
	a := []byte(`{"factura":"001","cliente":"Ana"}`)
	b := []byte(`{"factura":"002","cliente":"María Pérez"}`)
	c := []byte(`{"factura":"003","cliente":"Luis"}`)
	hb := hashOf(string(b))
	evento, err := erasure.Payload(hb)
	if err != nil {
		t.Fatal(err)
	}
	apila(t, s,
		sellado{"sri.factura.v1", a},  // 0
		sellado{"sri.factura.v1", b},  // 1: se suprime
		sellado{"sri.factura.v1", c},  // 2
		sellado{erasure.Type, evento}, // 3: el evento
		sellado{"sri.factura.v1", b},  // 4: el mismo contenido, sellado otra vez después
	)

	vivos := []Record{{Index: 0, Payload: a}, {Index: 2, Payload: c}}
	rep, err := Reconcile(s, FromSlice(vivos), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Erased) != 1 || rep.Erased[0].Index != 1 || rep.Erased[0].ErasedBy != 3 || rep.Erased[0].SealedHash != hb {
		t.Errorf("suprimidos = %+v, want el bloque 1, suprimido por el 3", rep.Erased)
	}
	if len(rep.Findings) != 1 || rep.Findings[0].Index != 4 || rep.Findings[0].Status != StatusMissing {
		t.Errorf("hallazgos = %+v, want solo el bloque 4 como faltante", rep.Findings)
	}

	// El JSON lleva el array siempre, también vacío.
	limpio, err := Reconcile(s, FromSlice([]Record{{Index: 0, Payload: a}, {Index: 1, Payload: b}, {Index: 2, Payload: c}, {Index: 4, Payload: b}}), Options{})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := limpio.JSON()
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	if _, ok := m["erased"].([]any); !ok || len(limpio.Findings) != 0 {
		t.Errorf("cotejo limpio: erased = %#v, hallazgos %+v\n%s", m["erased"], limpio.Findings, raw)
	}
}

// TestSinEventoUnRegistroBorradoEsUnFaltante: lo mismo sin el evento. Es lo que hace
// que la supresión no sirva para esconder un borrado: si no deja evento sellado, la
// reconciliación lo señala.
func TestSinEventoUnRegistroBorradoEsUnFaltante(t *testing.T) {
	s, err := openLedger(t)
	if err != nil {
		t.Fatal(err)
	}
	a := []byte(`{"factura":"001"}`)
	b := []byte(`{"factura":"002"}`)
	// Un evento de supresión de OTRO contenido no cubre a b.
	otro, err := erasure.Payload(hashOf("otro contenido"))
	if err != nil {
		t.Fatal(err)
	}
	apila(t, s, sellado{"sri.factura.v1", a}, sellado{"sri.factura.v1", b}, sellado{erasure.Type, otro})

	rep, err := Reconcile(s, FromSlice([]Record{{Index: 0, Payload: a}}), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Erased) != 0 {
		t.Errorf("suprimidos = %+v, want ninguno", rep.Erased)
	}
	if len(rep.Findings) != 1 || rep.Findings[0].Index != 1 || rep.Findings[0].Status != StatusMissing {
		t.Errorf("hallazgos = %+v, want el bloque 1 como faltante", rep.Findings)
	}
	if strings.Contains(string(mustJSON(t, rep)), `"erased": null`) {
		t.Error("erased sale como null")
	}
}

type sellado struct {
	typ     string
	payload []byte
}

func openLedger(t *testing.T) (*store.Store, error) {
	t.Helper()
	s, _, err := store.Open(filepath.Join(t.TempDir(), "nucleo.db"))
	if err == nil {
		t.Cleanup(func() { s.Close() })
	}
	return s, err
}

// apila sella los registros en orden, un minuto entre cada uno.
func apila(t *testing.T, s *store.Store, regs ...sellado) {
	t.Helper()
	priv := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	pub := priv.Public().(ed25519.PublicKey)
	var prev *ledger.Block
	for i, r := range regs {
		h, err := ledger.NewHeader(prev, testTenant, r.typ, r.payload, "none://", pub,
			testBase.Add(time.Duration(i)*time.Minute))
		if err != nil {
			t.Fatal(err)
		}
		b, err := ledger.Seal(h, priv)
		if err != nil {
			t.Fatal(err)
		}
		if err := s.AppendBlock(b); err != nil {
			t.Fatal(err)
		}
		prev = b
	}
}

func mustJSON(t *testing.T, r *Report) []byte {
	t.Helper()
	raw, err := r.JSON()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
