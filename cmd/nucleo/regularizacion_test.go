//go:build testhooks

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// conRetiradas escribe, junto a la política del despliegue, otra con el miembro
// retiredErasureKeys dado, y devuelve su ruta.
func conRetiradas(t *testing.T, c *cli, sp *conSupresion, nombre string, retiradas map[string]uint64, sinActual bool) string {
	t.Helper()
	raw, err := os.ReadFile(sp.politica)
	if err != nil {
		t.Fatal(err)
	}
	var p map[string]any
	if err := json.Unmarshal(raw, &p); err != nil {
		t.Fatal(err)
	}
	p["retiredErasureKeys"] = retiradas
	if sinActual {
		delete(p, "erasureKey")
	}
	raw, _ = json.Marshal(p)
	ruta := filepath.Join(c.dir, nombre)
	if err := os.WriteFile(ruta, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return ruta
}

// claveC es una clave que ningún test de este paquete usa en otro papel: la C de
// testdata/vectors/erasure/rotacion.json.
const claveC = "2543b92ff1095511476adc8369db6ddc933665a11978dda1404ee1066ca9559d"

// TestAvisoDeCorteAbierto (ADR-033 §C): un corte por encima del último índice de la cadena
// deja una ventana —la clave retirada autorizaría lo que se selle hasta él— y reconcile lo
// avisa por stderr, sin cambiar la salida. Un corte igual al último índice no deja ventana
// y no se avisa.
func TestAvisoDeCorteAbierto(t *testing.T) {
	c := newCLI(t)
	sp := c.initConSupresion(t)
	c.sealFile(`{"x":1}`)
	c.sealFile(`{"x":2}`)
	vivos := ficheroUnico(t, c.dir, "vivo-*.jsonl",
		`{"index":0,"payload_b64":"eyJ4IjoxfQ=="}`+"\n"+`{"index":1,"payload_b64":"eyJ4IjoyfQ=="}`+"\n")

	abierto := conRetiradas(t, c, sp, "abierta.json", map[string]uint64{claveC: 2}, false)
	_, errOut := c.runWant(t, exitOK, "reconcile", "--source", vivos, "--policy-file", abierto)
	if !strings.Contains(errOut, "la clave retirada "+claveC+" todavía autoriza eventos hasta el índice 2, y la cadena va\n  por el 1") {
		t.Errorf("no avisa del corte abierto:\n%s", errOut)
	}
	cerrado := conRetiradas(t, c, sp, "cerrada.json", map[string]uint64{claveC: 1}, false)
	if _, errOut := c.runWant(t, exitOK, "reconcile", "--source", vivos, "--policy-file", cerrado); strings.Contains(errOut, "todavía autoriza") {
		t.Errorf("avisa con el corte en el último índice:\n%s", errOut)
	}
}
