//go:build testhooks

package main

import (
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	_ "github.com/nucleoledger/nucleo/internal/store" // registra el driver "sqlite"
)

// El hallazgo del Sprint 18 sobre ADR-031: quien compromete el servidor del ERP tiene el
// fichero de la passphrase (ADR-029 acepta 0640 root:www-data). Borraba una venta del
// sistema vivo, la suprimía con ese fichero —`erase --passphrase-file … --json
// --assume-confirmed`— y la reconciliación pasaba de «faltante» (2) a «suprimido» (0).
// Reproducido con este mismo flujo antes de la enmienda: el test salía en verde con el
// ataque funcionando.
//
// Ahora el flujo está invertido: con el fichero de la passphrase, erase falla y
// reconcile sigue en 2. Y sin consola tampoco: las tarjetas no se aceptan de un fichero.
func TestElFicheroDeLaPassphraseNoSuprime(t *testing.T) {
	c := newCLI(t)
	c.initLedger()
	c.sealFile(`{"venta":"001","importe":"10000.00"}`)
	c.sealFile(`{"venta":"002","importe":"75.00"}`)
	pass := filepath.Join(c.dir, "passphrase.txt")
	if err := os.WriteFile(pass, []byte(testPassphrase+"\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	vivos := ficheroVivo(t, c.dir, 1, `{"venta":"002","importe":"75.00"}`)
	c.runWant(t, exitVerify, "reconcile", "--source", vivos)

	// El ataque tal cual.
	out, _ := c.runWant(t, exitUsage, "--json", "erase", "--block", "0", "--passphrase-file", pass, "--assume-confirmed")
	if !strings.Contains(out, "DOS TARJETAS") {
		t.Errorf("no dice qué hace falta:\n%s", out)
	}
	// Sin la bandera, y sin consola —un test, como un cron o un proceso web—, tampoco.
	_, errOut := c.runWant(t, exitUsage, "erase", "--block", "0", "--assume-confirmed")
	if !strings.Contains(errOut, "consola") {
		t.Errorf("sin consola no lo dice:\n%s", errOut)
	}

	c.runWant(t, exitVerify, "reconcile", "--source", vivos)
	if n := bloques(t, c.dir); n != 2 {
		t.Errorf("hay %d bloques: se selló algo", n)
	}
	if _, ct := contenidoDe(t, c.dir, 0); ct == nil {
		t.Error("el contenido se borró")
	}
}

// TestCadaSupresionAbreUnaAlarma: cada supresión abre una alarma durable, que viaja en
// el JSON de cada comando y solo se cierra con `alert ack`. Y como se deduce de la
// cadena, borrar su reconocimiento la vuelve a abrir en vez de esconderla.
func TestCadaSupresionAbreUnaAlarma(t *testing.T) {
	c := newCLI(t)
	c.initConTarjetas(t)
	c.sealFile(`{"venta":"001","cliente":"María Pérez"}`)
	c.mustRun("--json", "erase", "--block", "0", "--assume-confirmed")

	type alarma struct {
		ErasureAlert struct {
			State string `json:"state"`
			Open  []struct {
				Index             uint64   `json:"index"`
				ErasedPayloadHash string   `json:"erased_payload_hash"`
				Blocks            []uint64 `json:"blocks"`
			} `json:"open"`
		} `json:"erasure_alert"`
	}
	lee := func(args ...string) alarma {
		t.Helper()
		out := c.mustRun(append([]string{"--json"}, args...)...)
		var a alarma
		if err := json.Unmarshal([]byte(out), &a); err != nil {
			t.Fatalf("%v\n%s", err, out)
		}
		return a
	}
	h0, _ := contenidoDe(t, c.dir, 0)
	for _, cmd := range [][]string{
		{"status"},
		{"verify"},
		{"alert", "status"},
		{"seal", "--tenant", testTenant, "--type", "sri.factura.v1", "--payload", c.writeTemp(t, `{"venta":"002"}`)},
	} {
		a := lee(cmd...)
		if a.ErasureAlert.State != "open" || len(a.ErasureAlert.Open) != 1 || a.ErasureAlert.Open[0].Index != 1 ||
			a.ErasureAlert.Open[0].ErasedPayloadHash != h0 {
			t.Errorf("%v: erasure_alert = %+v", cmd, a.ErasureAlert)
		}
	}
	_, errOut := c.runWant(t, exitSyncFail, "alert", "status", "--exit-code")
	if !strings.Contains(errOut, "sin reconocer") {
		t.Errorf("alert status no avisa por stderr:\n%s", errOut)
	}

	ack := c.mustRun("--json", "alert", "ack", "--by", "auditoría")
	if !strings.Contains(ack, `"erasures_acked": 1`) {
		t.Errorf("alert ack:\n%s", ack)
	}
	if a := lee("status"); a.ErasureAlert.State != "none" || len(a.ErasureAlert.Open) != 0 {
		t.Errorf("tras ack: %+v", a.ErasureAlert)
	}
	c.mustRun("alert", "status", "--exit-code")

	// Borrar el reconocimiento no esconde la supresión: la reabre. Y borrar el detalle
	// tampoco: se abre igual, sin él.
	ev := bloqueDeCLI(t, c.dir, 1)
	for _, k := range []string{metaSupresionAck + ev.Hash, metaSupresionDetalle + ev.Hash} {
		if n := borraEstado(t, c.dir, k); n != 1 {
			t.Fatalf("log_state[%s]: borradas %d filas, want 1", k, n)
		}
	}
	if a := lee("status"); a.ErasureAlert.State != "open" || len(a.ErasureAlert.Open) != 1 {
		t.Errorf("con el reconocimiento borrado: %+v", a.ErasureAlert)
	}
}

// borraEstado quita una fila de log_state con SQL, como haría quien escribe el fichero,
// y devuelve cuántas borró.
func borraEstado(t *testing.T, dir, k string) int64 {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(dir, "nucleo.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	r, err := db.Exec(`DELETE FROM log_state WHERE k = ?`, k)
	if err != nil {
		t.Fatal(err)
	}
	n, _ := r.RowsAffected()
	return n
}
