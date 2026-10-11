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

// La clave de supresión de los tests (ADR-032): otra semilla que la del tenant, que es
// la de ceros. En un despliegue no está en el servidor; aquí, en el test.
var (
	claveSupresion = ed25519.NewKeyFromSeed([]byte("clave de supresion de los tests."))
	autoridad      = erasure.Authority{Origin: testOrigin, Key: claveSupresion.Public().(ed25519.PublicKey)}
)

const testOrigin = "nucleoledger.com/prueba"

// autoriza firma con la clave de supresión la supresión del contenido h hasta through.
func autoriza(t *testing.T, key ed25519.PrivateKey, origin, h string, through uint64) string {
	t.Helper()
	cid, err := erasure.Authorize(key, origin, h, through)
	if err != nil {
		t.Fatal(err)
	}
	return cid
}

// evento es el bloque de supresión del contenido h, con el payload_cid dado.
func evento(t *testing.T, h, cid string) sellado {
	t.Helper()
	p, err := erasure.Payload(h)
	if err != nil {
		t.Fatal(err)
	}
	return sellado{typ: erasure.Type, payload: p, cid: cid}
}

func factura(p []byte) sellado { return sellado{typ: "sri.factura.v1", payload: p} }

// TestSupresionSinAutorizacionNoCuenta (ADR-032): el hallazgo del Sprint 19. Con las
// piezas internas —sin pasar por `erase` ni por `seal`— se sella un evento de supresión
// firmado SOLO con la clave del tenant, que es la que abre la passphrase del servidor,
// para un registro que el sistema vivo ya no tiene. Con ADR-031 la reconciliación lo
// daba por suprimido y salía con 0 (se comprobó antes del cambio). Ahora el registro
// sigue faltando, y el evento es un hallazgo: tenga la política clave de supresión o no.
func TestSupresionSinAutorizacionNoCuenta(t *testing.T) {
	a := []byte(`{"venta":"001","importe":"10000.00"}`)
	b := []byte(`{"venta":"002","importe":"75.00"}`)
	ha := hashOf(string(a))
	for nombre, opts := range map[string]Options{
		"con la clave de supresión en la política": {Erasure: autoridad},
		"sin clave de supresión":                   {},
	} {
		t.Run(nombre, func(t *testing.T) {
			s, err := openLedger(t)
			if err != nil {
				t.Fatal(err)
			}
			// El evento tal como lo sellaba ADR-031: payload_cid "none://".
			apila(t, s, factura(a), factura(b), evento(t, ha, "none://"))
			rep, err := Reconcile(s, FromSlice([]Record{{Index: 1, Payload: b}}), opts)
			if err != nil {
				t.Fatal(err)
			}
			if len(rep.Erased) != 0 {
				t.Errorf("suprimidos = %+v: un evento sin autorización contó", rep.Erased)
			}
			faltante, noAutorizado := hallazgo(rep, 0), hallazgo(rep, 2)
			if faltante == nil || faltante.Status != StatusMissing {
				t.Errorf("el bloque 0 no sale como faltante: %+v", rep.Findings)
			}
			if noAutorizado == nil || noAutorizado.Status != StatusUnauthorizedErasure || noAutorizado.Reason == "" {
				t.Errorf("el evento no sale como supresión no autorizada, con su motivo: %+v", rep.Findings)
			}
		})
	}
}

// TestUnRegistroSuprimidoNoEsUnFaltante (ADR-031, ADR-032): el sistema vivo borra un
// registro porque su titular lo pidió y Núcleo suprime su contenido con la autorización
// de la clave de supresión. La reconciliación lo informa como suprimido y no como un
// registro que desapareció; el evento mismo no le falta al sistema vivo, porque es de
// Núcleo.
//
// Y una autorización solo llega hasta su through: si el mismo contenido se vuelve a
// sellar DESPUÉS de suprimirse, esa copia nueva no está suprimida y su ausencia sí es
// un hallazgo.
func TestUnRegistroSuprimidoNoEsUnFaltante(t *testing.T) {
	s, err := openLedger(t)
	if err != nil {
		t.Fatal(err)
	}
	a := []byte(`{"factura":"001","cliente":"Ana"}`)
	b := []byte(`{"factura":"002","cliente":"María Pérez"}`)
	c := []byte(`{"factura":"003","cliente":"Luis"}`)
	hb := hashOf(string(b))
	apila(t, s,
		factura(a), // 0
		factura(b), // 1: se suprime
		factura(c), // 2
		evento(t, hb, autoriza(t, claveSupresion, testOrigin, hb, 1)), // 3: el evento, autorizado hasta el 1
		factura(b), // 4: el mismo contenido, sellado otra vez después
	)

	vivos := []Record{{Index: 0, Payload: a}, {Index: 2, Payload: c}}
	rep, err := Reconcile(s, FromSlice(vivos), Options{Erasure: autoridad})
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
	limpio, err := Reconcile(s, FromSlice([]Record{{Index: 0, Payload: a}, {Index: 1, Payload: b}, {Index: 2, Payload: c}, {Index: 4, Payload: b}}), Options{Erasure: autoridad})
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

// TestAutorizacionAjenaNoCuenta (ADR-032 §D): una autorización de otra clave, sobre otro
// contenido, de otro log, o que no llega hasta el bloque, no cuenta. Cada caso deja el
// registro como faltante y el evento como hallazgo, salvo el último: una autorización
// válida que no llega hasta la copia que falta es una supresión legítima de OTRA copia.
func TestAutorizacionAjenaNoCuenta(t *testing.T) {
	a := []byte(`{"venta":"001","importe":"10000.00"}`)
	b := []byte(`{"venta":"002","importe":"75.00"}`)
	ha, hb := hashOf(string(a)), hashOf(string(b))
	otraClave := ed25519.NewKeyFromSeed([]byte("otra clave que no es la politica"))
	for _, c := range []struct {
		nombre string
		cid    string
	}{
		{"de otra clave", autoriza(t, otraClave, testOrigin, ha, 0)},
		{"sobre otro hash", autoriza(t, claveSupresion, testOrigin, hb, 0)},
		{"de otro log", autoriza(t, claveSupresion, "nucleoledger.com/otro", ha, 0)},
		{"con through igual al evento", autoriza(t, claveSupresion, testOrigin, ha, 2)},
		{"con la clave del tenant", autoriza(t, ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)), testOrigin, ha, 0)},
	} {
		t.Run(c.nombre, func(t *testing.T) {
			s, err := openLedger(t)
			if err != nil {
				t.Fatal(err)
			}
			apila(t, s, factura(a), factura(b), evento(t, ha, c.cid))
			rep, err := Reconcile(s, FromSlice([]Record{{Index: 1, Payload: b}}), Options{Erasure: autoridad})
			if err != nil {
				t.Fatal(err)
			}
			if len(rep.Erased) != 0 {
				t.Errorf("suprimidos = %+v", rep.Erased)
			}
			if f := hallazgo(rep, 0); f == nil || f.Status != StatusMissing {
				t.Errorf("el bloque 0 no sale como faltante: %+v", rep.Findings)
			}
			if f := hallazgo(rep, 2); f == nil || f.Status != StatusUnauthorizedErasure {
				t.Errorf("el evento no sale como no autorizado: %+v", rep.Findings)
			}
		})
	}

	t.Run("que no llega hasta la copia que falta", func(t *testing.T) {
		s, err := openLedger(t)
		if err != nil {
			t.Fatal(err)
		}
		// Dos copias del mismo contenido, y una autorización solo hasta la primera.
		apila(t, s, factura(a), factura(a), evento(t, ha, autoriza(t, claveSupresion, testOrigin, ha, 0)))
		rep, err := Reconcile(s, FromSlice(nil), Options{Erasure: autoridad})
		if err != nil {
			t.Fatal(err)
		}
		if len(rep.Erased) != 1 || rep.Erased[0].Index != 0 {
			t.Errorf("suprimidos = %+v, want solo el bloque 0", rep.Erased)
		}
		if len(rep.Findings) != 1 || rep.Findings[0].Index != 1 || rep.Findings[0].Status != StatusMissing {
			t.Errorf("hallazgos = %+v, want el bloque 1 como faltante", rep.Findings)
		}
	})
}

// TestSinEventoUnRegistroBorradoEsUnFaltante: sin evento de su contenido, un registro
// borrado es un faltante. Un evento autorizado de OTRO contenido no lo cubre.
func TestSinEventoUnRegistroBorradoEsUnFaltante(t *testing.T) {
	s, err := openLedger(t)
	if err != nil {
		t.Fatal(err)
	}
	a := []byte(`{"factura":"001"}`)
	b := []byte(`{"factura":"002"}`)
	c := []byte(`{"factura":"003"}`)
	hc := hashOf(string(c))
	apila(t, s, factura(a), factura(b), factura(c), evento(t, hc, autoriza(t, claveSupresion, testOrigin, hc, 2)))

	rep, err := Reconcile(s, FromSlice([]Record{{Index: 0, Payload: a}}), Options{Erasure: autoridad})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Erased) != 1 || rep.Erased[0].Index != 2 {
		t.Errorf("suprimidos = %+v, want solo el bloque 2", rep.Erased)
	}
	if len(rep.Findings) != 1 || rep.Findings[0].Index != 1 || rep.Findings[0].Status != StatusMissing {
		t.Errorf("hallazgos = %+v, want el bloque 1 como faltante", rep.Findings)
	}
	if strings.Contains(string(mustJSON(t, rep)), `"erased": null`) {
		t.Error("erased sale como null")
	}
}

// hallazgo devuelve el hallazgo del bloque idx, o nil.
func hallazgo(rep *Report, idx uint64) *Finding {
	for i := range rep.Findings {
		if rep.Findings[i].Index == idx {
			return &rep.Findings[i]
		}
	}
	return nil
}

type sellado struct {
	typ     string
	payload []byte
	cid     string // "" es "none://"
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
		cid := r.cid
		if cid == "" {
			cid = "none://"
		}
		h, err := ledger.NewHeader(prev, testTenant, r.typ, r.payload, cid, pub,
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
