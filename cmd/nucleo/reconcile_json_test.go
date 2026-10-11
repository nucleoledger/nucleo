//go:build testhooks

package main

import (
	"crypto/ed25519"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nucleoledger/nucleo/internal/checkpoint"
	"github.com/nucleoledger/nucleo/internal/ledger"
	"github.com/nucleoledger/nucleo/internal/store"
	"github.com/nucleoledger/nucleo/internal/witness"
)

// firmaInvalidaYaAtestiguada monta, sobre el ledger de ledgerConPolitica, el escenario
// de internal/store/attested_test.go#TestVerifyFullCazaUnaFirmaInvalidaYaATESTIGUADA:
// el emisor destroza la firma del bloque 1 y se hace cosignar la raíz que la incluye.
//
// La apertura atestiguada lo deja pasar —la raíz cosignada cuadra con lo que hay en
// disco, basura incluida, y por debajo del checkpoint no se recomputa ninguna firma— y
// solo VerifyFull lo caza. El checkpoint lo firma la clave del log de los tests (la
// semilla del gancho) y lo cosigna la clave del testigo de startTestWitness (semilla
// 200), así que la política que sync guardó lo da por VERIFICADO.
func firmaInvalidaYaAtestiguada(t *testing.T, c *cli, nombreTestigo string) {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(c.dir, "nucleo.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, q := range []string{
		"DROP TRIGGER blocks_no_update",
		"DROP TRIGGER checkpoints_no_delete",
		`UPDATE blocks SET signature = '` + strings.Repeat("00", ed25519.SignatureSize) + `' WHERE idx = 1`,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}

	// Las hojas sobre la firma destrozada, como las calcula la apertura (leaf/v2).
	rows, err := db.Query(`SELECT hash, signature FROM blocks ORDER BY idx`)
	if err != nil {
		t.Fatal(err)
	}
	var hojas [][]byte
	for rows.Next() {
		var hh, hs string
		if err := rows.Scan(&hh, &hs); err != nil {
			t.Fatal(err)
		}
		h, err1 := hex.DecodeString(hh)
		sig, err2 := hex.DecodeString(hs)
		if err1 != nil || err2 != nil {
			t.Fatalf("hash o firma no hex: %v %v", err1, err2)
		}
		hoja, err := ledger.LeafData(h, sig)
		if err != nil {
			t.Fatal(err)
		}
		hojas = append(hojas, hoja)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	rows.Close()

	id, err := newIdentity(testOrigin)
	if err != nil {
		t.Fatal(err)
	}
	lg, err := id.NewLog()
	if err != nil {
		t.Fatal(err)
	}
	nota, err := lg.Sign(checkpoint.Checkpoint{Origin: testOrigin, Size: uint64(len(hojas)), RootHash: ledger.Root(hojas)})
	if err != nil {
		t.Fatal(err)
	}
	semilla := make([]byte, ed25519.SeedSize)
	for i := range semilla {
		semilla[i] = 200 + byte(i) // la de startTestWitness
	}
	w, err := witness.New(nombreTestigo, ed25519.NewKeyFromSeed(semilla), now)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.AddLog(testOrigin, id.LogPublic()); err != nil {
		t.Fatal(err)
	}
	cosignada, err := w.Cosign(nota, nil)
	if err != nil {
		t.Fatal(err)
	}

	// La historia atestiguada pasa a ser la de la firma destrozada: fuera el checkpoint
	// honesto y lo que la base recuerda de él.
	for _, q := range []string{
		`DELETE FROM checkpoints`,
		`DELETE FROM log_state WHERE k IN ('` + store.LastAttestedKey + `', '` +
			store.LastCosignatureKey + `', '` + store.LastSignedKey + `')`,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.Exec(`INSERT INTO checkpoints (tree_size, note) VALUES (?, ?)`, len(hojas), string(cosignada)); err != nil {
		t.Fatal(err)
	}
}

// vivoDeTres es el JSONL del sistema vivo con los tres registros de ledgerConPolitica.
func vivoDeTres(t *testing.T, c *cli) string {
	t.Helper()
	var vivo strings.Builder
	for i, p := range []string{`{"x":1}`, `{"x":2}`, `{"x":3}`} {
		fmt.Fprintf(&vivo, `{"index":%d,"payload_b64":"%s"}`+"\n", i, base64.StdEncoding.EncodeToString([]byte(p)))
	}
	return c.writeTemp(t, vivo.String())
}

// TestReconcileJSONConVerifyFullFallidoEsUnSoloObjeto es H1 de la revisión del
// 2026-10-11: con un VerifyFull fallido, reconcile --json imprimía el informe —que ya
// lleva full_verify y ok:false— y, encima, el objeto de error de main. Dos objetos en
// stdout, cuando CLI-JSON.md promete uno.
//
// La firma destrozada no cambia ningún contenido, así que el cotejo no tiene hallazgos:
// lo único que falla es la verificación exhaustiva. Salida 2, y un solo objeto.
func TestReconcileJSONConVerifyFullFallidoEsUnSoloObjeto(t *testing.T) {
	c, pol, nombre, _ := ledgerConPolitica(t)
	firmaInvalidaYaAtestiguada(t, c, nombre)

	// La premisa: la apertura atestiguada lo deja pasar. Si no, el test probaría otra cosa.
	st, _ := c.runWant(t, exitOK, "--json", "status", "--policy-file", pol)
	if !strings.Contains(st, `"attestation": "verified"`) {
		t.Fatalf("la apertura tenía que dar la historia por verificada:\n%s", st)
	}

	out, _ := c.runWant(t, exitVerify, "--json", "reconcile", "--source", vivoDeTres(t, c), "--policy-file", pol)
	if err := unSoloValorJSON(out); err != nil {
		t.Fatalf("%v:\n%s", err, out)
	}
	var v map[string]any
	if err := json.Unmarshal([]byte(out), &v); err != nil {
		t.Fatal(err)
	}
	if v["ok"] != false {
		t.Errorf("ok = %v, want false", v["ok"])
	}
	fv, _ := v["full_verify"].(map[string]any)
	if fv == nil || fv["ok"] != false {
		t.Errorf("full_verify = %v, want un objeto con ok:false", v["full_verify"])
	}
	if f, ok := v["findings"].([]any); !ok || len(f) != 0 {
		t.Errorf("findings = %v, want []", v["findings"])
	}
	for _, campo := range []string{"error", "exit_code", "error_class"} {
		if _, ok := v[campo]; ok {
			t.Errorf("el informe lleva %q: es el objeto de error, no el de reconcile", campo)
		}
	}
}

// TestReconcileConVerifyFullFallidoLoDiceAPersonas: el arreglo de H1 es solo para
// --json. En texto el informe acaba en «✔ el sistema vivo coincide» —el contenido
// coincide—, y el fallo del ledger lo dicen «ledger : ✘» y la línea «error:» de stderr.
func TestReconcileConVerifyFullFallidoLoDiceAPersonas(t *testing.T) {
	c, pol, nombre, _ := ledgerConPolitica(t)
	firmaInvalidaYaAtestiguada(t, c, nombre)
	out, errOut := c.runWant(t, exitVerify, "reconcile", "--source", vivoDeTres(t, c), "--policy-file", pol)
	if !strings.Contains(out, "ledger     : ✘") {
		t.Errorf("stdout no dice que el ledger no pasó:\n%s", out)
	}
	if !strings.Contains(errOut, "error: la verificación exhaustiva falló") {
		t.Errorf("stderr no lleva la línea de error:\n%s", errOut)
	}
}

// TestReconcileJSONConPoliticaDeOtroOrigin: la pregunta abierta de la revisión del
// 2026-10-11, fijada. Con la política de otro log, el ledger no llega a abrirse: no hay
// informe de reconcile —ni findings, ni erased, ni full_verify—, sino el objeto de error,
// uno solo, con salida 2 y clase integrity. Hasta ahora solo lo fijaba status
// (TestPolicyFileEsFormatoDeCable, origin_de_otro_log).
func TestReconcileJSONConPoliticaDeOtroOrigin(t *testing.T) {
	c, pol, _, _ := ledgerConPolitica(t)
	raw, err := os.ReadFile(pol)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	doc["origin"] = "otro.example/log"
	ajena, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	polAjena := filepath.Join(c.dir, "politica-de-otro-log.json")
	if err := os.WriteFile(polAjena, ajena, 0o600); err != nil {
		t.Fatal(err)
	}

	out, _ := c.runWant(t, exitVerify, "--json", "reconcile", "--source", vivoDeTres(t, c), "--policy-file", polAjena)
	if err := unSoloValorJSON(out); err != nil {
		t.Fatalf("%v:\n%s", err, out)
	}
	var v map[string]any
	if err := json.Unmarshal([]byte(out), &v); err != nil {
		t.Fatal(err)
	}
	if v["ok"] != false || v["error_class"] != claseIntegridad || v["exit_code"] != float64(exitVerify) {
		t.Errorf("want ok:false, error_class %q y exit_code %d:\n%s", claseIntegridad, exitVerify, out)
	}
	if msg, _ := v["error"].(string); !strings.Contains(msg, "otro.example/log") {
		t.Errorf("el error no nombra el origin de la política:\n%s", out)
	}
	for _, campo := range []string{"findings", "erased", "full_verify"} {
		if _, ok := v[campo]; ok {
			t.Errorf("lleva %q: el ledger no se abrió y no hay informe de reconcile", campo)
		}
	}
}
