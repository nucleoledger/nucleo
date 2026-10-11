//go:build testhooks

package main

import (
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nucleoledger/nucleo/internal/erasure"
	"github.com/nucleoledger/nucleo/internal/identity"
	"github.com/nucleoledger/nucleo/internal/ledger"
	"github.com/nucleoledger/nucleo/internal/store" // registra además el driver "sqlite"
	"github.com/nucleoledger/nucleo/internal/vault"
)

// El hallazgo del Sprint 18 sobre ADR-031: quien compromete el servidor del ERP tiene el
// fichero de la passphrase (ADR-029 acepta 0640 root:www-data). Borraba una venta del
// sistema vivo, la suprimía con ese fichero —`erase --passphrase-file … --json
// --assume-confirmed`— y la reconciliación pasaba de «faltante» (2) a «suprimido» (0).
//
// La enmienda del Sprint 18 lo cerró en el comando exigiendo dos tarjetas del vault, y
// no bastaba: las tarjetas reconstruyen la misma clave que la passphrase, y la
// reconciliación aceptaba cualquier evento firmado con ella (ADR-032, el test de abajo).
// Ahora erase vuelve a aceptar la passphrase, porque no es eso lo que decide: sin la
// autorización de la clave de supresión no borra nada, y reconcile sigue en 2.
func TestElFicheroDeLaPassphraseNoSuprime(t *testing.T) {
	c := newCLI(t)
	sp := c.initConSupresion(t)
	c.sealFile(`{"venta":"001","importe":"10000.00"}`)
	c.sealFile(`{"venta":"002","importe":"75.00"}`)
	pass := filepath.Join(c.dir, "passphrase.txt")
	if err := os.WriteFile(pass, []byte(testPassphrase+"\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	vivos := ficheroVivo(t, c.dir, 1, `{"venta":"002","importe":"75.00"}`)
	c.runWant(t, exitVerify, "reconcile", "--source", vivos, "--policy-file", sp.politica)

	// El ataque tal cual, con la política del despliegue: sin autorización.
	out, _ := c.runWant(t, exitUsage, "--json", "erase", "--block", "0", "--policy-file", sp.politica,
		"--passphrase-file", pass, "--assume-confirmed")
	if !strings.Contains(out, "nucleo erasure-key authorize") {
		t.Errorf("no dice qué hace falta:\n%s", out)
	}
	// Con la autorización de OTRO contenido —la de la venta 002, que el atacante consiguió
	// por una supresión legítima—, tampoco.
	h1, _ := contenidoDe(t, c.dir, 1)
	otra := c.autoriza(t, sp, h1, 1)
	c.runWant(t, exitUsage, "--json", "erase", "--block", "0", "--policy-file", sp.politica,
		"--passphrase-file", pass, "--authorization", otra, "--assume-confirmed")
	// Y sin política con erasureKey no empieza: con las banderas sueltas del testigo.
	c.runWant(t, exitUsage, "--json", "erase", "--block", "0", "--witness-name", sp.name, "--witness-key", sp.key,
		"--passphrase-file", pass, "--assume-confirmed")

	c.runWant(t, exitVerify, "reconcile", "--source", vivos, "--policy-file", sp.politica)
	if n := bloques(t, c.dir); n != 2 {
		t.Errorf("hay %d bloques: se selló algo", n)
	}
	if _, ct := contenidoDe(t, c.dir, 0); ct == nil {
		t.Error("el contenido se borró")
	}
}

// TestLaClaveDelServidorNoSuprime (ADR-032): el hallazgo del Sprint 19, por la vía del
// atacante. Con lo que hay en el servidor —el ledger y el fichero de la passphrase— y
// las piezas internas, sin pasar por erase ni por seal: abre el vault, borra la copia
// cifrada y sella un evento de supresión firmado con la clave del tenant. Con ADR-031 y
// su enmienda, eso era una supresión: reconcile salía con 0. Ahora sigue en 2, con el
// registro faltante y el evento como supresión no autorizada.
func TestLaClaveDelServidorNoSuprime(t *testing.T) {
	c := newCLI(t)
	sp := c.initConSupresion(t)
	c.sealFile(`{"venta":"001","importe":"10000.00"}`)
	c.sealFile(`{"venta":"002","importe":"75.00"}`)
	h0, _ := contenidoDe(t, c.dir, 0)

	func() {
		s, _, err := store.Open(filepath.Join(c.dir, "nucleo.db"))
		if err != nil {
			t.Fatal(err)
		}
		defer s.Close()
		v, err := vault.Unlock(s, []byte(testPassphrase))
		if err != nil {
			t.Fatal(err)
		}
		defer v.Close()
		id, err := identity.Load(v, s)
		if err != nil {
			t.Fatal(err)
		}
		payload, err := erasure.Payload(h0)
		if err != nil {
			t.Fatal(err)
		}
		prev, err := s.LastBlock()
		if err != nil {
			t.Fatal(err)
		}
		hd, err := ledger.NewHeader(prev, testTenant, erasure.Type, payload, "none://", id.TenantPublic(), now())
		if err != nil {
			t.Fatal(err)
		}
		ev, err := ledger.Seal(hd, id.Tenant)
		if err != nil {
			t.Fatal(err)
		}
		if err := s.AppendRecord(store.Record{Block: ev, EraseBlob: h0, DeleteMeta: []string{metaCommitPrefix + h0}}); err != nil {
			t.Fatal(err)
		}
	}()
	if _, ct := contenidoDe(t, c.dir, 0); ct != nil {
		t.Fatal("el ataque no borró la copia cifrada: el test no comprobaría nada")
	}

	vivos := ficheroVivo(t, c.dir, 1, `{"venta":"002","importe":"75.00"}`)
	out, _ := c.runWant(t, exitVerify, "--json", "reconcile", "--source", vivos, "--policy-file", sp.politica)
	var r struct {
		Findings []struct {
			Status string `json:"status"`
			Index  uint64 `json:"index"`
			Reason string `json:"reason"`
		} `json:"findings"`
		Erased []any `json:"erased"`
	}
	if err := json.Unmarshal([]byte(out), &r); err != nil {
		t.Fatal(err)
	}
	if len(r.Erased) != 0 || len(r.Findings) != 2 ||
		r.Findings[0].Index != 0 || r.Findings[0].Status != "faltante" ||
		r.Findings[1].Index != 2 || r.Findings[1].Status != "supresión no autorizada" || r.Findings[1].Reason == "" {
		t.Errorf("reconcile tras el evento forjado:\n%s", out)
	}
	// Y la vía legítima sigue abierta: con la autorización, erase sella un evento que la
	// lleva —el contenido ya no estaba, no hay nada que borrar— y el registro cuenta como
	// suprimido. El evento forjado sigue siendo un hallazgo: no lo arregla nadie.
	c.mustRun("--json", "erase", "--block", "0", "--policy-file", sp.politica,
		"--authorization", c.autoriza(t, sp, h0, 0), "--assume-confirmed")
	out, _ = c.runWant(t, exitVerify, "--json", "reconcile", "--source", vivos, "--policy-file", sp.politica)
	r.Findings, r.Erased = nil, nil
	if err := json.Unmarshal([]byte(out), &r); err != nil {
		t.Fatal(err)
	}
	if len(r.Erased) != 1 || len(r.Findings) != 1 || r.Findings[0].Index != 2 {
		t.Errorf("reconcile tras la supresión autorizada:\n%s", out)
	}
}

// TestCadaSupresionAbreUnaAlarma: cada supresión abre una alarma durable, que viaja en
// el JSON de cada comando y solo se cierra con `alert ack`. Y como se deduce de la
// cadena, borrar su reconocimiento la vuelve a abrir en vez de esconderla.
func TestCadaSupresionAbreUnaAlarma(t *testing.T) {
	c := newCLI(t)
	sp := c.initConSupresion(t)
	c.sealFile(`{"venta":"001","cliente":"María Pérez"}`)
	h, _ := contenidoDe(t, c.dir, 0)
	c.mustRun("--json", "erase", "--block", "0", "--policy-file", sp.politica,
		"--authorization", c.autoriza(t, sp, h, 0), "--assume-confirmed")

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
