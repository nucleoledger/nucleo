package policy

import (
	"bytes"
	"encoding/json"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// FuzzPoliticaFrenteAV04 es el fuzz DIFERENCIAL de la política (Sprint 31, cierre del C1):
// el Parse de hoy frente al de v0.4.0-alpha (v04_copia_test.go), sobre cualquier
// documento. La 0.8-draft promete que una política sin sus dos miembros nuevos se acepta
// y se rechaza igual que antes y significa lo mismo (ADR-033 y ADR-034, «La
// compatibilidad»); los vectores lo comprueban en los casos que alguien pensó, y esto en
// los que no.
//
// Cubre el lector estricto entero, no solo la tabla: los dos Parse llevan dentro su propio
// internal/estricto (el de entonces, copiado; el de hoy, el del paquete).
//
// Los documentos CON miembros 0.8 no entran en la comparación, porque el lector viejo los
// rechaza por diseño. El filtro es exacto y no adivina nada del texto: se excluye un
// documento cuando el lector de HOY lo acepta y su resultado trae retiredErasureKeys o
// logMLDSAKey. Si el de hoy lo rechaza, el viejo también tiene que rechazarlo (y entra en
// la comparación). Y lo excluido no se tira: se exige que el viejo lo rechace como miembro
// desconocido, que es lo que la tabla de compatibilidad dice que hace un verificador 0.4.
func FuzzPoliticaFrenteAV04(f *testing.F) {
	for _, s := range semillasDePolitica(f) {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		hoy, errHoy := Parse(raw)
		antes, errAntes := parseV04(raw)
		if errHoy == nil && (hoy.RetiredErasureKeys != nil || hoy.LogMLDSAKey != "") {
			if errAntes == nil || !strings.Contains(errAntes.Error(), "miembro desconocido") {
				t.Fatalf("documento con miembros 0.8: v0.4.0-alpha tenía que rechazarlo como miembro desconocido, y da %v", errAntes)
			}
			return
		}
		if (errHoy == nil) != (errAntes == nil) {
			t.Fatalf("veredictos distintos: hoy %v, v0.4.0-alpha %v\n%q", errHoy, errAntes, raw)
		}
		if errHoy != nil {
			return
		}
		if hoy.Origin != antes.Origin || hoy.LogKey != antes.LogKey || hoy.SignerKey != antes.SignerKey ||
			hoy.ErasureKey != antes.ErasureKey || hoy.Quorum != antes.Quorum || !maps.Equal(hoy.Witnesses, antes.Witnesses) {
			t.Fatalf("aceptan los dos con resultados distintos:\nhoy   %+v\nantes %+v\n%q", *hoy, *antes, raw)
		}
	})
}

// semillasDePolitica es el corpus inicial: el texto de cada vector de
// testdata/vectors/policy/ y unas mutaciones de cada uno, que llevan al fuzzer a los
// bordes de la gramática desde el primer segundo.
func semillasDePolitica(tb testing.TB) [][]byte {
	tb.Helper()
	files, err := filepath.Glob(filepath.Join("..", "..", "testdata", "vectors", "policy", "*.json"))
	if err != nil || len(files) < 50 {
		tb.Fatalf("vectores de política: %d, %v", len(files), err)
	}
	var out [][]byte
	for _, file := range files {
		raw, err := os.ReadFile(file)
		if err != nil {
			tb.Fatal(err)
		}
		var v struct {
			Text string `json:"text"`
		}
		if err := json.Unmarshal(raw, &v); err != nil {
			tb.Fatal(err)
		}
		t := []byte(v.Text)
		out = append(out, t, t[:len(t)/2], append(bytes.Clone(t), ' ', '}'),
			bytes.Replace(t, []byte(`"quorum"`), []byte(`"Quorum"`), 1),
			bytes.Replace(t, []byte(`":"`), []byte(`":"A`), 1),
			bytes.Replace(t, []byte(`"erasureKey"`), []byte(`"logMLDSAKey"`), 1),
			bytes.Replace(t, []byte(`,`), []byte(`,"retiredErasureKeys":{},`), 1))
		if len(t) > 2 {
			m := bytes.Clone(t)
			m[len(m)/2] ^= 0x20
			out = append(out, m)
		}
	}
	return out
}
