//go:build testhooks

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// politicaConTestigos escribe una política de este ledger con los testigos dados y
// quórum 1: la que se da a los clientes tras sustituir un testigo (OPERACION §1).
func politicaConTestigos(t *testing.T, c *cli, testigos map[string]string) string {
	t.Helper()
	out, _ := c.runWant(t, exitOK, "--json", "status")
	var st map[string]any
	if err := json.Unmarshal([]byte(out), &st); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(map[string]any{
		"origin": st["origin"], "logKey": st["log_pubkey"], "signerKey": st["signer_pubkey"],
		"witnesses": testigos, "quorum": 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	ruta := filepath.Join(c.dir, "politica-varios.json")
	if err := os.WriteFile(ruta, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return ruta
}

// TestSyncConLaPoliticaDeLosClientes: tras perder un testigo, la política de los
// clientes lleva el viejo y el nuevo, y sync la usa tal cual eligiendo el testigo por
// nombre. Antes exigía exactamente un testigo y el cron necesitaba otro fichero.
func TestSyncConLaPoliticaDeLosClientes(t *testing.T) {
	c := newCLI(t)
	c.initLedger()
	c.sealFile(`{"factura":"uno"}`)
	logPub := c.logPubKey(t)

	url1, n1, k1 := startTestWitnessComo(t, logPub, "witness.example/w1", 200, 0)
	c.mustRun("sync", "--witness", url1, "--witness-name", n1, "--witness-key", k1)
	c.sealFile(`{"factura":"dos"}`)

	// El testigo w1 se pierde. Se levanta w2, con otro nombre y otra clave.
	url2, n2, k2 := startTestWitnessComo(t, logPub, "witness.example/w2", 100, 0)
	ambos := politicaConTestigos(t, c, map[string]string{n1: k1, n2: k2})

	t.Run("con varios testigos, sin nombre, pide elegir", func(t *testing.T) {
		_, errOut := c.runWant(t, exitUsage, "sync", "--policy-file", ambos, "--witness", url2)
		for _, q := range []string{"trae 2 testigos", n1, n2, "--witness-name"} {
			if !strings.Contains(errOut, q) {
				t.Errorf("no dice %q:\n%s", q, c.ultima())
			}
		}
	})
	t.Run("un nombre que no está en la política", func(t *testing.T) {
		_, errOut := c.runWant(t, exitUsage, "sync", "--policy-file", ambos, "--witness", url2,
			"--witness-name", "witness.example/w3")
		if !strings.Contains(errOut, "no tiene ningún testigo llamado") || !strings.Contains(errOut, n2) {
			t.Errorf("no lo explica:\n%s", c.ultima())
		}
	})
	t.Run("el fichero y una clave suelta siguen sin combinarse", func(t *testing.T) {
		c.runWant(t, exitUsage, "sync", "--policy-file", ambos, "--witness", url2,
			"--witness-name", n2, "--witness-key", k2)
	})
	t.Run("eligiendo w2 por nombre, sincroniza", func(t *testing.T) {
		out, _ := c.runWant(t, exitOK, "--json", "sync", "--policy-file", ambos, "--witness", url2,
			"--witness-name", n2)
		var r struct {
			Attested bool `json:"attested"`
			Policy   struct {
				Witnesses map[string]string `json:"witnesses"`
				Quorum    int               `json:"quorum"`
			} `json:"policy"`
		}
		if err := json.Unmarshal([]byte(out), &r); err != nil {
			t.Fatal(err)
		}
		if !r.Attested {
			t.Errorf("no quedó atestiguado:\n%s", out)
		}
		// La política que devuelve es la del fichero, ENTERA: con los dos testigos.
		if r.Policy.Witnesses[n1] != k1 || r.Policy.Witnesses[n2] != k2 || r.Policy.Quorum != 1 {
			t.Errorf("la política devuelta no es la del fichero: %+v", r.Policy)
		}
	})
	t.Run("status con la misma política lo da por atestiguado", func(t *testing.T) {
		out, _ := c.runWant(t, exitOK, "--json", "status", "--policy-file", ambos)
		var st struct {
			Attestation string `json:"attestation"`
		}
		if err := json.Unmarshal([]byte(out), &st); err != nil || st.Attestation != "verified" {
			t.Errorf("status no verifica la atestación (%v):\n%s", err, out)
		}
	})
	t.Run("y el cron repite lo mismo al día siguiente", func(t *testing.T) {
		c.sealFile(`{"factura":"tres"}`)
		c.runWant(t, exitOK, "sync", "--policy-file", ambos, "--witness", url2, "--witness-name", n2)
	})
}

// TestSyncConUnSoloTestigoSigueIgual: con la política de un testigo, el nombre sobra; si
// se da, tiene que ser el suyo.
func TestSyncConUnSoloTestigoSigueIgual(t *testing.T) {
	c := newCLI(t)
	c.initLedger()
	c.sealFile(`{"factura":"uno"}`)
	url, n, k := startTestWitness(t, c.logPubKey(t))
	pol := politicaDeTest(t, c, n, k)
	c.mustRun("sync", "--policy-file", pol, "--witness", url)
	c.mustRun("sync", "--policy-file", pol, "--witness", url, "--witness-name", n)
	c.runWant(t, exitUsage, "sync", "--policy-file", pol, "--witness", url, "--witness-name", "otro")
}
