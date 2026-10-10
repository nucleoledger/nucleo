package witness

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nucleoledger/nucleo/internal/checkpoint"
	"github.com/nucleoledger/nucleo/internal/ledger"
)

// unLog es un log de prueba con su clave y sus hojas, para los tests de varios logs.
type unLog struct {
	t      *testing.T
	origin string
	priv   ed25519.PrivateKey
	hojas  [][]byte
}

func nuevoLog(t *testing.T, origin string, semilla byte) *unLog {
	t.Helper()
	hojas := make([][]byte, 32)
	for i := range hojas {
		// La semilla entra en las hojas: dos logs con el mismo origin y otra clave
		// son dos historias distintas, no la misma firmada por otro.
		hojas[i] = []byte(fmt.Sprintf("%s/%d/bloque-%d", origin, semilla, i))
	}
	return &unLog{t: t, origin: origin, priv: ed25519.NewKeyFromSeed(seed(semilla)), hojas: hojas}
}

func (l *unLog) pub() ed25519.PublicKey { return l.priv.Public().(ed25519.PublicKey) }

// firma emite el checkpoint de las primeras n hojas, firmado con la clave de este log
// y con el origin que se le diga (normalmente el suyo).
func (l *unLog) firmaComo(origin string, n int) []byte {
	l.t.Helper()
	s, err := checkpoint.NewSigner(origin, l.priv)
	if err != nil {
		l.t.Fatal(err)
	}
	msg, err := checkpoint.Sign(checkpoint.Checkpoint{Origin: origin, Size: uint64(n), RootHash: ledger.Root(l.hojas[:n])}, s)
	if err != nil {
		l.t.Fatal(err)
	}
	return msg
}

func (l *unLog) firma(n int) []byte { return l.firmaComo(l.origin, n) }

func (l *unLog) prueba(viejo, nuevo int) [][]byte {
	l.t.Helper()
	if viejo == 0 {
		return nil
	}
	p, err := ledger.ConsistencyProof(l.hojas[:nuevo], viejo)
	if err != nil {
		l.t.Fatal(err)
	}
	return p
}

// testigoSobre crea un testigo con la memoria persistente dada.
func testigoSobre(t *testing.T, st State) *Witness {
	t.Helper()
	clk := &clock{t: 1_800_000_000}
	w, err := NewWithState(witnessName, ed25519.NewKeyFromSeed(seed(100)), clk.now, st)
	if err != nil {
		t.Fatal(err)
	}
	return w
}

func tamanoRecordado(t *testing.T, w *Witness, origin string) uint64 {
	t.Helper()
	c, ok := w.Last(origin)
	if !ok {
		return 0
	}
	return c.Size
}

// TestVariosLogsNoSePisanLaMemoria (ADR-030 §D): tres logs en un testigo, uno cuyo
// origin es prefijo del de otro, avanzando intercalados. Cada uno recuerda lo suyo, y
// un checkpoint con el origin de un log firmado por la clave de otro se rechaza sin
// tocar la memoria de ninguno.
func TestVariosLogsNoSePisanLaMemoria(t *testing.T) {
	st, err := OpenState(filepath.Join(t.TempDir(), "testigo.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	w := testigoSobre(t, st)
	a := nuevoLog(t, "ejemplo.ec/a", 1)
	ab := nuevoLog(t, "ejemplo.ec/ab", 2) // "ejemplo.ec/a" es prefijo de este origin
	b := nuevoLog(t, "ejemplo.ec/b", 3)
	for _, l := range []*unLog{a, ab, b} {
		if err := w.AddLog(l.origin, l.pub()); err != nil {
			t.Fatal(err)
		}
	}

	// Avances intercalados, con tamaños distintos para cada uno.
	pasos := []struct {
		l          *unLog
		viejo, sig int
	}{
		{a, 0, 3}, {ab, 0, 5}, {b, 0, 1}, {a, 3, 7}, {b, 1, 9}, {ab, 5, 6}, {a, 7, 8},
	}
	for _, p := range pasos {
		if _, err := w.CosignAt(uint64(p.viejo), p.l.firma(p.sig), p.l.prueba(p.viejo, p.sig)); err != nil {
			t.Fatalf("%s de %d a %d: %v", p.l.origin, p.viejo, p.sig, err)
		}
	}
	for l, quiere := range map[*unLog]uint64{a: 8, ab: 6, b: 9} {
		if got := tamanoRecordado(t, w, l.origin); got != quiere {
			t.Errorf("%s recuerda %d; want %d", l.origin, got, quiere)
		}
		c, _ := w.Last(l.origin)
		if string(c.RootHash) != string(ledger.Root(l.hojas[:quiere])) {
			t.Errorf("%s recuerda una raíz que no es la suya", l.origin)
		}
	}

	// El origin de b, firmado con la clave de a: el origin solo elige la clave, y
	// esta nota no está firmada por la de b.
	if _, err := w.CosignAt(9, a.firmaComo(b.origin, 10), nil); !errors.Is(err, ErrBadSignature) {
		t.Errorf("checkpoint de b firmado por a = %v; want ErrBadSignature", err)
	}
	// Y el de ab con la clave de a, aunque compartan prefijo.
	if _, err := w.CosignAt(6, a.firmaComo(ab.origin, 7), nil); !errors.Is(err, ErrBadSignature) {
		t.Errorf("checkpoint de ab firmado por a = %v; want ErrBadSignature", err)
	}
	for l, quiere := range map[*unLog]uint64{a: 8, ab: 6, b: 9} {
		if got := tamanoRecordado(t, w, l.origin); got != quiere {
			t.Errorf("tras los rechazos, %s recuerda %d; want %d", l.origin, got, quiere)
		}
	}
	origins, err := st.Origins()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(origins, ",") != "ejemplo.ec/a,ejemplo.ec/ab,ejemplo.ec/b" {
		t.Errorf("Origins = %v", origins)
	}
}

// TestLogRetiradoNoSeCosignaYConservaSuMemoria (ADR-030 §C): retirado, un log deja
// de cosignarse —404 «log retirado» por HTTP— pero su memoria sigue, se sigue
// publicando en la ruta de monitorización, y al reactivarlo continúa desde ella.
func TestLogRetiradoNoSeCosignaYConservaSuMemoria(t *testing.T) {
	st, err := OpenState(filepath.Join(t.TempDir(), "testigo.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	a := nuevoLog(t, "ejemplo.ec/robado", 1)
	b := nuevoLog(t, "ejemplo.ec/sigue", 2)

	// Primer arranque: los dos activos.
	w := testigoSobre(t, st)
	_ = w.AddLog(a.origin, a.pub())
	_ = w.AddLog(b.origin, b.pub())
	if _, err := w.CosignAt(0, a.firma(5), nil); err != nil {
		t.Fatal(err)
	}
	if _, err := w.CosignAt(0, b.firma(2), nil); err != nil {
		t.Fatal(err)
	}

	// Segundo arranque, sobre la MISMA memoria: a retirado.
	w = testigoSobre(t, st)
	if err := w.RetireLog(a.origin, a.pub()); err != nil {
		t.Fatal(err)
	}
	_ = w.AddLog(b.origin, b.pub())
	if _, err := w.CosignAt(5, a.firma(6), a.prueba(5, 6)); !errors.Is(err, ErrRetiredLog) {
		t.Fatalf("cosignar un log retirado = %v; want ErrRetiredLog", err)
	}
	if got := tamanoRecordado(t, w, a.origin); got != 5 {
		t.Errorf("el retirado recuerda %d; want 5", got)
	}
	if _, err := w.CosignAt(2, b.firma(3), b.prueba(2, 3)); err != nil {
		t.Errorf("el otro log dejó de cosignarse: %v", err)
	}

	// Por HTTP: 404 con el cuerpo «log retirado», y la ruta de monitorización sigue
	// publicando su último checkpoint.
	srv := httptest.NewServer(NewServer(w).Handler())
	defer srv.Close()
	cli, err := NewClient(srv.URL, witnessName, ed25519.NewKeyFromSeed(seed(100)).Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	_, err = cli.AddCheckpoint(context.Background(), 5, a.prueba(5, 6), a.firma(6))
	var he *HTTPError
	if !errors.As(err, &he) || he.Status != 404 || !strings.Contains(he.Body, RetiredBody) {
		t.Fatalf("por HTTP = %v; want 404 con %q", err, RetiredBody)
	}
	nota, err := cli.Checkpoint(context.Background(), a.origin)
	if err != nil {
		t.Fatalf("la ruta de monitorización ya no publica el retirado: %v", err)
	}
	if c, _ := checkpoint.ParseNote(nota); c.Size != 5 {
		t.Errorf("publica el tamaño %d; want 5", c.Size)
	}

	// Tercer arranque: a reactivado. Continúa desde 5, no desde cero.
	w = testigoSobre(t, st)
	_ = w.AddLog(a.origin, a.pub())
	if _, err := w.CosignAt(0, a.firma(2), nil); err == nil {
		t.Fatal("reactivado, aceptó empezar de cero: eso es un rollback")
	}
	if _, err := w.CosignAt(5, a.firma(6), a.prueba(5, 6)); err != nil {
		t.Errorf("reactivado, no continúa desde su memoria: %v", err)
	}
}

// TestReanadirConOtraClaveNoReiniciaLaHistoria (ADR-030 §C): un origin que se quitó de
// la configuración y vuelve con OTRA clave se encuentra su memoria; no puede volver a
// empezar desde un tamaño menor.
func TestReanadirConOtraClaveNoReiniciaLaHistoria(t *testing.T) {
	st, err := OpenState(filepath.Join(t.TempDir(), "testigo.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	viejo := nuevoLog(t, "ejemplo.ec/empresa", 1)
	w := testigoSobre(t, st)
	_ = w.AddLog(viejo.origin, viejo.pub())
	if _, err := w.CosignAt(0, viejo.firma(9), nil); err != nil {
		t.Fatal(err)
	}

	otro := nuevoLog(t, "ejemplo.ec/empresa", 7) // mismo origin, otra clave, otro árbol
	w = testigoSobre(t, st)
	_ = w.AddLog(otro.origin, otro.pub())
	var conflicto *ConflictError
	if _, err := w.CosignAt(0, otro.firma(3), nil); !errors.As(err, &conflicto) || conflicto.LastSize != 9 {
		t.Fatalf("con otra clave, empezar de cero = %v; want conflicto con el tamaño recordado 9", err)
	}
	if _, err := w.CosignAt(9, otro.firma(12), otro.prueba(9, 12)); err == nil {
		t.Fatal("con otra clave, extendió una historia que no es la que el testigo recuerda")
	}
	if got := tamanoRecordado(t, w, viejo.origin); got != 9 {
		t.Errorf("recuerda %d; want 9", got)
	}
}

// TestActivoYRetiradoALaVezEsError: un origin no puede estar en los dos sitios.
func TestActivoYRetiradoALaVezEsError(t *testing.T) {
	w := testigoSobre(t, NewMemState())
	l := nuevoLog(t, "ejemplo.ec/x", 1)
	if err := w.AddLog(l.origin, l.pub()); err != nil {
		t.Fatal(err)
	}
	if err := w.RetireLog(l.origin, l.pub()); err == nil {
		t.Error("retiró un log activo")
	}
	w = testigoSobre(t, NewMemState())
	_ = w.RetireLog(l.origin, l.pub())
	if err := w.AddLog(l.origin, l.pub()); err == nil {
		t.Error("activó un log retirado")
	}
	if strings.Join(w.RetiredLogs(), ",") != l.origin || len(w.Logs()) != 0 {
		t.Errorf("Logs=%v RetiredLogs=%v", w.Logs(), w.RetiredLogs())
	}
}
