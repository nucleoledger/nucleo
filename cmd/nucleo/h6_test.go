//go:build testhooks

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// H6 de la cuarta auditoría: un log SIN bloques nuevos, con el cron de sync corriendo.
// La nota guardada es la PRIMERA de ese tamaño —correcto para el tiempo demostrable, que
// es el mínimo—, y la frescura con política leía esa nota: status acababa diciendo que
// el cron lleva días roto mientras el cron funciona.
func TestFrescuraConLogParadoYCronVivo(t *testing.T) {
	c := newCLI(t)
	c.initLedger()
	c.sealFile(`{"x":1}`)
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

	// Pasan cuatro días. El log no crece, pero el cron sincroniza.
	avanzaReloj(t, 100*time.Hour)
	c.mustRun("sync", "--witness", url, "--witness-name", name, "--witness-key", key)

	out, errOut := c.runWant(t, exitOK, "--json", "status", "--policy-file", pol)
	f := freshness(t, out)
	if f["stale"] == true || avisoDeFrescura(errOut) {
		t.Errorf("EXPLOTADO H6: el cron sincronizó hace un instante y status dice que lleva días roto\nfreshness=%v\n%s", f, errOut)
	}
	if f["verified"] != true {
		t.Errorf("la evidencia de contacto reciente tiene que ser verificada: %v", f)
	}
	humano, _ := c.runWant(t, exitOK, "status", "--policy-file", pol)
	if !strings.Contains(humano, "frescura  : ✔") {
		t.Errorf("status humano:\n%s", humano)
	}

	// Y la otra mitad: el tiempo HISTÓRICO no se toca. El recibo sigue demostrando que
	// el registro existía desde la PRIMERA cosignature —el mínimo, la mejor prueba de
	// antigüedad—, no desde la de hace un instante.
	recibo, _ := c.runWant(t, exitOK, "receipt", "--block", "0", "--recipient", "María Pérez", "--policy-file", pol)
	if !strings.Contains(recibo, "TIEMPO DEMOSTRABLE: "+testClockRFC) {
		t.Errorf("el tiempo demostrable debe seguir siendo el de la primera cosignature (%s):\n%s",
			testClockRFC, recibo)
	}
	// El estado lo dice con las dos fechas: la atestación es de hace cuatro días y el
	// contacto, de ahora.
	g := freshness(t, c.mustRun("--json", "status", "--policy-file", pol))
	if g["first_attested_at"] != testClockRFC {
		t.Errorf("first_attested_at = %v, want %s (desde cuándo consta)", g["first_attested_at"], testClockRFC)
	}
	if g["attested_at"] == testClockRFC {
		t.Errorf("attested_at debería ser el del último contacto, no el de la primera vez: %v", g["attested_at"])
	}
	if !strings.Contains(humano, "consta desde "+testClockRFC) {
		t.Errorf("el status humano no dice desde cuándo consta:\n%s", humano)
	}
}
