//go:build testhooks

package main

import (
	"crypto/ed25519"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nucleoledger/nucleo/internal/ledger"
)

// El hallazgo MEDIO #3 de la tercera auditoría (E.3): seal y sync tenían la clave
// legítima en la mano y no la comparaban con la cadena.

// atacanteCLI es la clave con la que se reescribe la cadena.
var atacanteCLI = ed25519.NewKeyFromSeed([]byte("tercera auditoria, 32 bytes....."))

// reescribirCadena es rewrite.py de la auditoría, portado a Go para que corra en el
// CI sin depender de un Python con `cryptography`: reescribe los bloques [0, hasta)
// con la clave del atacante, re-encadenados y con firmas autoconsistentes, y borra
// los checkpoints y el registro local, como hizo la auditoría.
func reescribirCadena(t *testing.T, c *cli, hasta int) {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(c.dir, "nucleo.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, q := range []string{"DROP TRIGGER blocks_no_update", "DROP TRIGGER checkpoints_no_delete"} {
		if _, err := db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	rows, err := db.Query(`SELECT idx, header_json FROM blocks ORDER BY idx`)
	if err != nil {
		t.Fatal(err)
	}
	type fila struct {
		idx int
		hj  string
	}
	var filas []fila
	for rows.Next() {
		var f fila
		if err := rows.Scan(&f.idx, &f.hj); err != nil {
			t.Fatal(err)
		}
		filas = append(filas, f)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	rows.Close()
	prevHash := ""
	for _, f := range filas[:hasta] {
		var h ledger.Header
		if err := json.Unmarshal([]byte(f.hj), &h); err != nil {
			t.Fatal(err)
		}
		h.SignerPubKey = hex.EncodeToString(atacanteCLI.Public().(ed25519.PublicKey))
		if prevHash != "" {
			h.PrevHash = prevHash
		}
		b, err := ledger.Seal(h, atacanteCLI)
		if err != nil {
			t.Fatal(err)
		}
		canon, err := b.Header.Canonical()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(`UPDATE blocks SET header_json = ?, hash = ?, signature = ? WHERE idx = ?`,
			string(canon), b.Hash, b.Signature, f.idx); err != nil {
			t.Fatal(err)
		}
		prevHash = b.Hash
	}
	for _, q := range []string{`DELETE FROM checkpoints`, `DELETE FROM log_state WHERE k = 'log/last-attested/v1'`} {
		if _, err := db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
}

// ledgerConPolitica crea un ledger de tres bloques, sincronizado, y guarda la
// política que sync imprime.
func ledgerConPolitica(t *testing.T) (*cli, string, string, string) {
	t.Helper()
	c := newCLI(t)
	c.initLedger()
	for _, p := range []string{`{"x":1}`, `{"x":2}`, `{"x":3}`} {
		c.sealFile(p)
	}
	url, name, key := startTestWitness(t, c.logPubKey(t))
	js := c.mustRun("--json", "sync", "--witness", url, "--witness-name", name, "--witness-key", key)
	var v struct {
		Policy json.RawMessage `json:"policy"`
	}
	if err := json.Unmarshal([]byte(js), &v); err != nil {
		t.Fatal(err)
	}
	pol := filepath.Join(c.dir, "politica.json")
	if err := os.WriteFile(pol, v.Policy, 0o600); err != nil {
		t.Fatal(err)
	}
	return c, pol, name, key
}

func treeSize(t *testing.T, c *cli) float64 {
	t.Helper()
	var st map[string]any
	if err := json.Unmarshal([]byte(c.mustRun("--json", "status")), &st); err != nil {
		t.Fatal(err)
	}
	return st["tree_size"].(float64)
}

func TestSealSobreCadenaAjena(t *testing.T) {
	c, _, _, _ := ledgerConPolitica(t)
	reescribirCadena(t, c, 3)

	out, _ := c.runWant(t, exitVerify, "--json", "seal", "--tenant", testTenant, "--type", "sri.factura.v1",
		"--payload", c.writeTemp(t, `{"x":4}`))
	if !strings.Contains(out, "no se sella") || !strings.Contains(out, "cadena entera fue reescrita") {
		t.Errorf("el error no explica qué pasa:\n%s", out)
	}
	if n := treeSize(t, c); n != 3 {
		t.Errorf("tree_size = %v: el bloque se escribió igualmente", n)
	}
}

func TestSyncSobreCadenaAjenaNoContactaAlTestigo(t *testing.T) {
	c, _, name, key := ledgerConPolitica(t)
	reescribirCadena(t, c, 3)

	// Un testigo inalcanzable: si sync llegara a contactarlo, saldría con 3.
	// Con 2, la comprobación ocurrió ANTES de enseñarle nada.
	_, errOut := c.runWant(t, exitVerify, "sync", "--witness", "http://127.0.0.1:1", "--witness-name", name, "--witness-key", key)
	if !strings.Contains(errOut, "no se sincroniza") {
		t.Errorf("el error no explica qué pasa:\n%s", errOut)
	}
}

func TestCadenaMixtaAcusaAlIntrusoConPolitica(t *testing.T) {
	c, pol, _, _ := ledgerConPolitica(t)
	reescribirCadena(t, c, 2) // bloques 0 y 1 ajenos, el 2 legítimo

	_, errOut, code := c.run("status", "--policy-file", pol)
	if code != exitVerify || !strings.Contains(errOut, "el bloque 0 lo firma") {
		t.Errorf("con política el error tiene que señalar al bloque 0, el intruso (esperado código %d):\n%s", exitVerify, c.ultima())
	}
	_, errOut, code = c.run("status")
	if code != exitVerify || !strings.Contains(errOut, "no se puede saber cuál de las dos es la legítima") ||
		strings.Contains(errOut, "política espera") {
		t.Errorf("sin política el error no debe acusar a nadie (esperado código %d):\n%s", exitVerify, c.ultima())
	}
}
