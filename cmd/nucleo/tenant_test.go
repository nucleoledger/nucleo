//go:build testhooks

package main

import (
	"strings"
	"testing"
)

// TestSealRechazaTenantMultilinea reproduce, por la vía del usuario, el caso que
// la auditoría adversarial ejecutó: `seal --tenant $'ACME\nS.A.'`. Antes el
// sellado pasaba, `receipt` decía "✔ recibo escrito" y todo verificador lo
// rechazaba. Ahora el rechazo ocurre donde el error señala a quien lo puede
// corregir: al sellar, con código de uso y un mensaje que dice por qué.
func TestSealRechazaTenantMultilinea(t *testing.T) {
	c := newCLI(t)
	c.initLedger()
	payload := c.writeTemp(t, `{"a":1}`)

	for _, tenant := range []string{"ACME\nS.A.", "ACME\rS.A.", "ACME\tS.A."} {
		_, errOut, code := c.run("seal", "--tenant", tenant, "--type", "t.v1", "--payload", payload)
		if code != exitUsage {
			t.Errorf("tenant %q: código = %d, want %d", tenant, code, exitUsage)
		}
		if !strings.Contains(errOut, "una línea") {
			t.Errorf("tenant %q: el error no explica que tiene que caber en una línea:\n%s", tenant, errOut)
		}
	}

	// Y el ledger sigue vacío: ningún intento llegó a escribir.
	out := c.mustRun("--json", "status")
	if !strings.Contains(out, `"tree_size": 0`) {
		t.Errorf("un tenant inválido dejó bloques en el ledger:\n%s", out)
	}
}
