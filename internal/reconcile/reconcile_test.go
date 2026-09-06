package reconcile

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nucleoledger/nucleo/internal/ledger"
	"github.com/nucleoledger/nucleo/internal/store"
)

const testTenant = "1790012345001"

var testBase = time.Date(2026, 3, 14, 10, 0, 0, 0, time.UTC)

// LA FACTURA. Es el ejemplo que da sentido al proyecto entero: se sella por
// 10.000 y meses después el sistema vivo la enseña por 1.000.
const (
	facturaOriginal = `{"factura":"001-001-000012345","cliente":"Constructora del Litoral S.A.","importe":"10000.00"}`
	facturaAlterada = `{"factura":"001-001-000012345","cliente":"Constructora del Litoral S.A.","importe":"1000.00"}`
)

func hashOf(b string) string {
	sum := sha256.Sum256([]byte(b))
	return hex.EncodeToString(sum[:])
}

// sealed monta un ledger con cinco registros, el tercero de los cuales es LA
// factura.
func sealed(t *testing.T) (*store.Store, [][]byte) {
	t.Helper()
	s, _, err := store.Open(filepath.Join(t.TempDir(), "nucleo.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })

	payloads := [][]byte{
		[]byte(`{"tipo":"apertura","periodo":"2026-03"}`),
		[]byte(`{"factura":"001-001-000012344","importe":"320.50"}`),
		[]byte(facturaOriginal),
		[]byte(`{"factura":"001-001-000012346","importe":"75.00"}`),
		[]byte(`{"tipo":"cierre","periodo":"2026-03"}`),
	}
	priv := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	pub := priv.Public().(ed25519.PublicKey)
	var prev *ledger.Block
	for i, p := range payloads {
		h, err := ledger.NewHeader(prev, testTenant, "sri.factura.v1", p, "blob://x", pub,
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
	return s, payloads
}

// live devuelve los registros "vivos" a partir de los sellados, con las
// modificaciones que se le pidan.
func live(payloads [][]byte, mutate func(i int, p []byte) []byte) []Record {
	var out []Record
	for i, p := range payloads {
		np := mutate(i, p)
		if np == nil {
			continue // el sistema vivo ya no lo tiene
		}
		out = append(out, Record{Index: uint64(i), Payload: np})
	}
	return out
}

// TestReconcileDetectsTheAlteredInvoice es LA historia del proyecto.
//
// La factura se selló por 10.000. Meses después, el sistema vivo la enseña por
// 1.000: alguien hizo un UPDATE y la base operativa no guarda memoria de ello.
// El ledger no impidió el cambio —no puede— pero sí sabe qué se selló, y la
// reconciliación señala el registro exacto, el hash original y desde cuándo
// estaba sellado.
func TestReconcileDetectsTheAlteredInvoice(t *testing.T) {
	s, payloads := sealed(t)

	records := live(payloads, func(i int, p []byte) []byte {
		if i == 2 {
			return []byte(facturaAlterada)
		}
		return p
	})

	rep, err := Reconcile(s, FromSlice(records), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Checked != 5 {
		t.Errorf("Checked = %d, want 5", rep.Checked)
	}
	if rep.Verified != 4 {
		t.Errorf("Verified = %d, want 4", rep.Verified)
	}

	altered := rep.Altered()
	if len(altered) != 1 {
		t.Fatalf("%d discrepancias, want 1: %+v", len(altered), rep.Findings)
	}
	f := altered[0]
	if f.Index != 2 {
		t.Errorf("índice = %d, want 2", f.Index)
	}
	// El hash sellado es el de la factura ORIGINAL: es la prueba de qué decía.
	if f.SealedHash != hashOf(facturaOriginal) {
		t.Errorf("SealedHash = %s, want %s", f.SealedHash, hashOf(facturaOriginal))
	}
	if f.CurrentHash != hashOf(facturaAlterada) {
		t.Errorf("CurrentHash = %s, want %s", f.CurrentHash, hashOf(facturaAlterada))
	}
	if f.SealedHash == f.CurrentHash {
		t.Fatal("los dos hashes coinciden: el test no distingue nada")
	}
	sealedAt, err := f.SealedTime()
	if err != nil {
		t.Fatal(err)
	}
	if want := testBase.Add(2 * time.Minute); !sealedAt.Equal(want) {
		t.Errorf("SealedAt = %v, want %v", sealedAt, want)
	}
	if f.Tenant != testTenant {
		t.Errorf("Tenant = %q", f.Tenant)
	}

	// Y el reporte es serializable, que es lo que permite archivarlo.
	raw, err := rep.JSON()
	if err != nil {
		t.Fatal(err)
	}
	var back Report
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	if len(back.Altered()) != 1 || back.Altered()[0].SealedHash != f.SealedHash {
		t.Error("el reporte no sobrevive al round-trip JSON")
	}
}

// TestReconcileCleanRun es el control negativo: sin alteraciones no hay
// hallazgos. Sin él, una reconciliación que gritara siempre pasaría por
// vigilante.
func TestReconcileCleanRun(t *testing.T) {
	s, payloads := sealed(t)
	rep, err := Reconcile(s, FromSlice(live(payloads, func(i int, p []byte) []byte { return p })), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Findings) != 0 {
		t.Errorf("%d hallazgos sobre una base intacta: %+v", len(rep.Findings), rep.Findings)
	}
	if rep.Verified != 5 || rep.TreeSize != 5 {
		t.Errorf("Verified = %d, TreeSize = %d, want 5 y 5", rep.Verified, rep.TreeSize)
	}
}

// TestReconcileDetectsMissingAndExtra cubre las otras dos formas de divergir: lo
// que el sistema vivo perdió y lo que tiene sin haberlo sellado.
func TestReconcileDetectsMissingAndExtra(t *testing.T) {
	s, payloads := sealed(t)

	records := live(payloads, func(i int, p []byte) []byte {
		if i == 1 {
			return nil // desaparecido del sistema vivo
		}
		return p
	})
	records = append(records, Record{Index: 99, Payload: []byte(`{"factura":"fantasma"}`), Extra: true})

	rep, err := Reconcile(s, FromSlice(records), Options{})
	if err != nil {
		t.Fatal(err)
	}

	byStatus := map[Status][]Finding{}
	for _, f := range rep.Findings {
		byStatus[f.Status] = append(byStatus[f.Status], f)
	}
	if got := byStatus[StatusMissing]; len(got) != 1 || got[0].Index != 1 {
		t.Errorf("faltantes = %+v, want el bloque 1", got)
	}
	if got := byStatus[StatusExtra]; len(got) != 1 || got[0].Index != 99 {
		t.Errorf("no sellados = %+v, want el 99", got)
	}
	// Un faltante conserva el hash sellado: es lo que permite buscarlo en una
	// copia de seguridad y comprobar que es el que era.
	if byStatus[StatusMissing][0].SealedHash != hashOf(string(payloads[1])) {
		t.Error("el faltante no conserva el hash sellado")
	}
}

// TestReconcileRunsFullVerify comprueba la ejecución programada que prometió la
// enmienda de ADR-009: la verificación exhaustiva deja de depender de que a
// alguien le entren sospechas.
func TestReconcileRunsFullVerify(t *testing.T) {
	s, payloads := sealed(t)
	rep, err := Reconcile(s, FromSlice(live(payloads, func(i int, p []byte) []byte { return p })),
		Options{IncludeFullVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	if rep.FullVerify == nil || !rep.FullVerify.Run {
		t.Fatal("no se ejecutó la verificación exhaustiva")
	}
	if !rep.FullVerify.OK {
		t.Errorf("VerifyFull falló sobre una base sana: %s", rep.FullVerify.Err)
	}

	// Sin ella, el reporte no la menciona: no se afirma lo que no se hizo.
	rep2, err := Reconcile(s, FromSlice(nil), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if rep2.FullVerify != nil {
		t.Error("el reporte menciona una verificación que no se pidió")
	}
}

// TestSourceErrorAbortsRun comprueba que un fallo de la fuente no produzca un
// reporte a medias con aspecto de completo, que sería lo peligroso.
func TestSourceErrorAbortsRun(t *testing.T) {
	s, _ := sealed(t)
	boom := errors.New("la base operativa no responde")
	src := func(yield func(Record) error) error {
		if err := yield(Record{Index: 0, Payload: []byte("x")}); err != nil {
			return err
		}
		return boom
	}
	rep, err := Reconcile(s, src, Options{})
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want %v", err, boom)
	}
	if rep != nil {
		t.Error("se devolvió un reporte pese al fallo de la fuente")
	}
}

// TestFindingsAreOrdered: dos ejecuciones del mismo cotejo dan el mismo reporte,
// que es lo que permite compararlos entre sí.
func TestFindingsAreOrdered(t *testing.T) {
	s, payloads := sealed(t)
	records := live(payloads, func(i int, p []byte) []byte {
		if i == 0 || i == 3 {
			return []byte(fmt.Sprintf(`{"alterado":%d}`, i))
		}
		if i == 4 {
			return nil
		}
		return p
	})
	// Se entregan en orden inverso para forzar el ordenamiento.
	for i, j := 0, len(records)-1; i < j; i, j = i+1, j-1 {
		records[i], records[j] = records[j], records[i]
	}
	rep, err := Reconcile(s, FromSlice(records), Options{})
	if err != nil {
		t.Fatal(err)
	}
	var idx []uint64
	for _, f := range rep.Findings {
		idx = append(idx, f.Index)
	}
	want := []uint64{0, 3, 4}
	if fmt.Sprint(idx) != fmt.Sprint(want) {
		t.Errorf("índices = %v, want %v", idx, want)
	}
	if !strings.Contains(string(rep.Findings[2].Status), "faltante") {
		t.Errorf("el último hallazgo debería ser el faltante: %+v", rep.Findings[2])
	}
}
