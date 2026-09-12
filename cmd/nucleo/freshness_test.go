//go:build testhooks

package main

import (
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nucleoledger/nucleo/internal/store"
	_ "modernc.org/sqlite"
)

// forjarRegistroLocal es el INSERT de la segunda auditoría adversarial: un
// registro de "última atestación" escrito a mano en log_state, con un testigo
// que no existe y una fecha de hace un instante. Antes de este sprint, `status`
// respondía "frescura : ✔ atestación de hace 0 segundos, por testigo.inventado/w9".
func forjarRegistroLocal(t *testing.T, c *cli, at time.Time) {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(c.dir, "nucleo.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rec, _ := json.Marshal(store.AttestationRecord{
		Witness: "testigo.inventado/w9", At: at, Size: 1, RecordedAt: at,
	})
	if _, err := db.Exec(`INSERT OR REPLACE INTO log_state(k, v) VALUES(?, ?)`,
		store.LastAttestedKey, string(rec)); err != nil {
		t.Fatal(err)
	}
}

// TestFrescuraNoSeFiaDelRegistroLocal: la frescura está subordinada a la
// atestación verificada. Un registro local forjado no compra un ✔ en ningún
// modo, y en JSON `verified` y `source` dicen de dónde salió la fecha.
func TestFrescuraNoSeFiaDelRegistroLocal(t *testing.T) {
	c := newCLI(t)
	c.initLedger()
	c.sealFile(`{"x":1}`)
	ahora, _ := time.Parse(time.RFC3339, testClockRFC)
	forjarRegistroLocal(t, c, ahora.Add(-time.Minute))

	// Sin política: la fecha forjada aparece, pero calificada, y sin ✔.
	out, _, code := c.run("status")
	if code != exitOK {
		t.Fatalf("status salió con %d", code)
	}
	if strings.Contains(out, "frescura  : ✔") {
		t.Errorf("EXPLOTADO: un registro local forjado compró un ✔:\n%s", out)
	}
	for _, want := range []string{"frescura  : ◐ registro local de hace 1 minutos, por testigo.inventado/w9 — NO verificado", "estado    : ⚠ SIN ATESTIGUAR"} {
		if !strings.Contains(out, want) {
			t.Errorf("status no dice %q:\n%s", want, out)
		}
	}
	js, _, _ := c.run("--json", "status")
	f := freshness(t, js)
	if f["verified"] != false || f["source"] != "local_record" || f["witness"] != "testigo.inventado/w9" {
		t.Errorf("freshness JSON = %v, want verified:false source:local_record", f)
	}

	// Con la política de un testigo REAL que nunca vio este log: el registro
	// local sigue ahí, la atestación no verifica, y la frescura lo dice igual.
	_, name, key := startTestWitness(t, c.logPubKey(t))
	out, _, _ = c.run("status", "--witness-name", name, "--witness-key", key)
	if strings.Contains(out, "frescura  : ✔") {
		t.Errorf("EXPLOTADO con política y sin cosignature:\n%s", out)
	}
	if !strings.Contains(out, "NO verificado") {
		t.Errorf("status con política no califica el registro local:\n%s", out)
	}
}

// TestFrescuraVerificadaSaleDeLaCosignature: con atestación verificada, la fecha
// es la de la cosignature que se comprobó, y el registro local —aunque esté
// forjado con una fecha más reciente— ni se mira.
func TestFrescuraVerificadaSaleDeLaCosignature(t *testing.T) {
	c := newCLI(t)
	c.initLedger()
	c.sealFile(`{"x":1}`)
	url, name, key := startTestWitness(t, c.logPubKey(t))
	c.mustRun("sync", "--witness", url, "--witness-name", name, "--witness-key", key)

	// Cuatro días después, alguien "refresca" el registro local a mano.
	avanzaReloj(t, 100*time.Hour)
	ahora, _ := time.Parse(time.RFC3339, testClockRFC)
	forjarRegistroLocal(t, c, ahora.Add(100*time.Hour))

	// Sin política: la fecha forjada, calificada. Con política: la real, vieja.
	out, errOut, _ := c.run("status")
	if !strings.Contains(out, "registro local de hace 0 segundos, por testigo.inventado/w9 — NO verificado") {
		t.Errorf("sin política:\n%s", out)
	}
	if avisoDeFrescura(errOut) {
		t.Errorf("sin política no hay atestación verificada que juzgar vieja; el registro local no dispara alarma:\n%s", errOut)
	}
	js, errOut, _ := c.run("--json", "status", "--witness-name", name, "--witness-key", key)
	if !avisoDeFrescura(errOut) || strings.Contains(errOut, "registro local") {
		t.Errorf("con política, la alarma sale de la cosignature verificada:\n%s", errOut)
	}
	f := freshness(t, js)
	if f["verified"] != true || f["source"] != "attestation" || f["witness"] != name || f["stale"] != true {
		t.Errorf("freshness JSON = %v, want verified:true source:attestation stale:true witness:%s", f, name)
	}
	if _, hay := f["recorded_at"]; hay {
		t.Errorf("recorded_at es del registro local y no debería salir con la atestación verificada: %v", f)
	}
}

// TestSealYReconcileExponenAtestacion: seal --json y reconcile --json llevan
// attestation, attested, attested_size, signer y freshness con la misma semántica
// que status.
func TestSealYReconcileExponenAtestacion(t *testing.T) {
	c := newCLI(t)
	c.initLedger()
	c.sealFile(`{"x":1}`)
	url, name, key := startTestWitness(t, c.logPubKey(t))
	c.mustRun("sync", "--witness", url, "--witness-name", name, "--witness-key", key)
	// El sistema vivo, con los tres registros que habrá cuando llegue reconcile:
	// el sellado arriba y los dos que sellan los subtests de seal.
	var vivo strings.Builder
	for i, p := range []string{`{"x":1}`, `{"x":2}`, `{"x":3}`} {
		fmt.Fprintf(&vivo, `{"index":%d,"payload_b64":"%s"}`+"\n", i, base64.StdEncoding.EncodeToString([]byte(p)))
	}
	live := c.writeTemp(t, vivo.String())

	for _, cs := range []struct {
		nombre string
		args   []string
		quiero string // attestation esperada
	}{
		{"seal sin política", []string{"--json", "seal", "--tenant", testTenant, "--type", "sri.factura.v1", "--payload", c.writeTemp(t, `{"x":2}`)}, "unverified"},
		{"seal con política", []string{"--json", "seal", "--witness-name", name, "--witness-key", key, "--tenant", testTenant, "--type", "sri.factura.v1", "--payload", c.writeTemp(t, `{"x":3}`)}, "verified"},
		{"reconcile sin política", []string{"--json", "reconcile", "--source", live}, "unverified"},
		{"reconcile con política", []string{"--json", "reconcile", "--witness-name", name, "--witness-key", key, "--source", live}, "verified"},
	} {
		t.Run(cs.nombre, func(t *testing.T) {
			out, errOut, code := c.run(cs.args...)
			if code != exitOK {
				t.Fatalf("código %d:\n%s", code, errOut)
			}
			var v map[string]any
			if err := json.Unmarshal([]byte(out), &v); err != nil {
				t.Fatalf("%v:\n%s", err, out)
			}
			if v["attestation"] != cs.quiero || v["attested"] != (cs.quiero == "verified") {
				t.Errorf("attestation = %v attested = %v, want %s", v["attestation"], v["attested"], cs.quiero)
			}
			sg, _ := v["signer"].(map[string]any)
			if sg["state"] != "unverified" || sg["pubkey"] == "" {
				t.Errorf("signer = %v, want unverified con pubkey (no se pasó --signer-key)", v["signer"])
			}
			f, _ := v["freshness"].(map[string]any)
			if f["verified"] != (cs.quiero == "verified") {
				t.Errorf("freshness.verified = %v, want %v", f["verified"], cs.quiero == "verified")
			}
			if v["ok"] != true {
				t.Errorf("ok = %v", v["ok"])
			}
		})
	}
}
