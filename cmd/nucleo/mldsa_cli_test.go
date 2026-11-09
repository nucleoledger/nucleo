//go:build testhooks

package main

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nucleoledger/nucleo/internal/identity"
	"github.com/nucleoledger/nucleo/internal/store"
	"github.com/nucleoledger/nucleo/internal/vault"
)

// clavePQDelLedger abre el vault del despliegue de prueba y devuelve la clave pública
// ML-DSA-44 de su identidad en hexadecimal.
func clavePQDelLedger(t *testing.T, c *cli) string {
	t.Helper()
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
	pq, err := id.PQSigner()
	if err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(pq.PublicKey())
}

// politicaCon escribe la política del despliegue con logMLDSAKey y devuelve su ruta.
func politicaCon(t *testing.T, c *cli, nombre, url, name, key, logMLDSAKey string) string {
	t.Helper()
	raw, err := json.Marshal(policyDoc{Origin: testOrigin, LogKey: c.logPubKey(t), LogMLDSAKey: logMLDSAKey,
		Witnesses: map[string]string{name: key}, Quorum: 1})
	if err != nil {
		t.Fatal(err)
	}
	ruta := filepath.Join(c.dir, nombre)
	if err := os.WriteFile(ruta, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return ruta
}

// TestSyncImprimeLogMLDSAKey (ADR-034, decisión 9): sync imprime SIEMPRE logMLDSAKey en la
// política que propone, en texto y en --json, y es la clave ML-DSA-44 de la identidad. Con
// una política de fichero que no la trae, el objeto policy de --json la completa y el
// texto da la línea que hay que añadir.
func TestSyncImprimeLogMLDSAKey(t *testing.T) {
	c := newCLI(t)
	c.initLedger()
	c.sealFile(`{"x":1}`)
	url, name, key := startTestWitness(t, c.logPubKey(t))
	pq := clavePQDelLedger(t, c)
	if len(pq) != 2624 {
		t.Fatalf("clave ML-DSA-44 de %d caracteres", len(pq))
	}

	texto := c.mustRun("sync", "--witness", url, "--witness-name", name, "--witness-key", key)
	if !strings.Contains(texto, `"logMLDSAKey": "`+pq+`"`) {
		t.Errorf("la política del texto no trae logMLDSAKey:\n%s", texto)
	}
	var js struct {
		Policy policyDoc `json:"policy"`
	}
	out := c.mustRun("--json", "sync", "--witness", url, "--witness-name", name, "--witness-key", key)
	if err := json.Unmarshal([]byte(out), &js); err != nil {
		t.Fatal(err)
	}
	if js.Policy.LogMLDSAKey != pq {
		t.Errorf("policy.logMLDSAKey de --json = %.16s…, y la de la identidad %.16s…", js.Policy.LogMLDSAKey, pq)
	}

	sinClave := politicaCon(t, c, "sin-clave.json", url, name, key, "")
	texto = c.mustRun("sync", "--witness", url, "--policy-file", sinClave)
	if !strings.Contains(texto, `"logMLDSAKey": "`+pq+`"`) || !strings.Contains(texto, "no fija la clave ML-DSA-44") {
		t.Errorf("con una política sin la clave, el texto no da la línea:\n%s", texto)
	}
	js.Policy = policyDoc{}
	out = c.mustRun("--json", "sync", "--witness", url, "--policy-file", sinClave)
	if err := json.Unmarshal([]byte(out), &js); err != nil {
		t.Fatal(err)
	}
	if js.Policy.LogMLDSAKey != pq {
		t.Errorf("con una política sin la clave, policy.logMLDSAKey de --json = %.16s…", js.Policy.LogMLDSAKey)
	}

	// La política que imprime sync se usa TAL CUAL: abre, sella y emite un recibo cuya
	// autoverificación comprueba la ML-DSA-44 ("verified").
	conClave := filepath.Join(c.dir, "impresa.json")
	impresa, _ := json.Marshal(js.Policy)
	if err := os.WriteFile(conClave, impresa, 0o600); err != nil {
		t.Fatal(err)
	}
	c.mustRun("--json", "sync", "--witness", url, "--policy-file", conClave)
	out = c.mustRun("--json", "receipt", "--block", "0", "--recipient", "Ana", "--policy-file", conClave)
	var rec struct {
		LogMLDSA string `json:"log_mldsa"`
	}
	if err := json.Unmarshal([]byte(out), &rec); err != nil {
		t.Fatal(err)
	}
	if rec.LogMLDSA != "verified" {
		t.Errorf("receipt --json: log_mldsa %q", rec.LogMLDSA)
	}
}

// TestLaAperturaCotejaLogMLDSAKey (PROTOCOL 0.8-draft §3.2): una política cuya logMLDSAKey no
// es la de la identidad la rechazan las órdenes que abren la identidad —seal, sync, receipt,
// erase—, y las que no la abren —status, verify, reconcile— no la cotejan y no dicen que
// la cotejaron: no hablan de ella.
func TestLaAperturaCotejaLogMLDSAKey(t *testing.T) {
	c := newCLI(t)
	c.initLedger()
	c.sealFile(`{"x":1}`)
	url, name, key := startTestWitness(t, c.logPubKey(t))
	c.mustRun("sync", "--witness", url, "--witness-name", name, "--witness-key", key)
	pq := clavePQDelLedger(t, c)
	otra := strings.Repeat("ab", 1312)
	mala := politicaCon(t, c, "mala.json", url, name, key, otra)
	buena := politicaCon(t, c, "buena.json", url, name, key, pq)
	doc := c.writeTemp(t, `{"x":2}`)

	t.Run("donde se abre la identidad, se coteja", func(t *testing.T) {
		for _, args := range [][]string{
			{"seal", "--tenant", testTenant, "--type", "sri.factura.v1", "--payload", doc, "--policy-file", mala},
			{"sync", "--witness", url, "--policy-file", mala},
			{"receipt", "--block", "0", "--recipient", "Ana", "--policy-file", mala},
		} {
			_, errOut := c.runWant(t, exitUsage, args...)
			if !strings.Contains(errOut, "la logMLDSAKey de la política no es la clave ML-DSA-44 de este ledger") {
				t.Errorf("%s: no dice por qué:\n%s", args[0], errOut)
			}
		}
		if bloques(t, c.dir) != 1 {
			t.Error("seal selló con una logMLDSAKey ajena")
		}
		c.mustRun("seal", "--tenant", testTenant, "--type", "sri.factura.v1", "--payload", doc, "--policy-file", buena)
	})

	t.Run("donde no se abre, ni se coteja ni se dice", func(t *testing.T) {
		for _, args := range [][]string{
			{"status", "--policy-file", mala},
			{"verify", "--policy-file", mala},
		} {
			out, errOut := c.runWant(t, exitOK, args...)
			for _, dicho := range []string{"logMLDSAKey", "ML-DSA", "post-cuántica"} {
				if strings.Contains(out+errOut, dicho) {
					t.Errorf("%s habla de %q sin haber abierto la identidad:\n%s\n%s", args[0], dicho, out, errOut)
				}
			}
		}
	})
}
