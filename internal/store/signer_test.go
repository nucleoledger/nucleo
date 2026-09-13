package store

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// TestSignerOfVectoresGolden: la extracción rápida de signer_pubkey contra
// testdata/signer/vectores.json, cuyos valores esperados calcula generar.py con
// json.loads y la regla escrita a mano, sin una línea de este código (E.9).
func TestSignerOfVectoresGolden(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "signer", "vectores.json"))
	if err != nil {
		t.Fatal(err)
	}
	var casos []struct {
		Name       string `json:"name"`
		HeaderJSON string `json:"header_json"`
		Signer     string `json:"signer"`
		Error      string `json:"error"`
	}
	if err := json.Unmarshal(raw, &casos); err != nil {
		t.Fatal(err)
	}
	if len(casos) < 15 {
		t.Fatalf("solo %d vectores", len(casos))
	}
	for _, c := range casos {
		t.Run(c.Name, func(t *testing.T) {
			got, err := signerOf(c.HeaderJSON)
			switch {
			case c.Error != "" && err == nil:
				t.Errorf("debía fallar (%s) y devolvió %s", c.Error, got)
			case c.Error == "" && err != nil:
				t.Errorf("debía devolver %s: %v", c.Signer, err)
			case c.Error == "" && got != c.Signer:
				t.Errorf("signer = %s, want %s", got, c.Signer)
			}
		})
	}
}

// TestSignerOfCoincideConLaCadenaReal: sobre headers producidos por ledger.Seal —los
// que de verdad hay en una base—, la extracción rápida da lo mismo que decodificar
// el header entero. No es un golden (usa el código de producción para fabricar la
// entrada), es la propiedad de equivalencia sobre la que se apoya E.9.
func TestSignerOfCoincideConLaCadenaReal(t *testing.T) {
	for _, b := range chain(t, 200, 0) {
		canon, err := b.Header.Canonical()
		if err != nil {
			t.Fatal(err)
		}
		got, err := signerOf(string(canon))
		if err != nil || got != b.Header.SignerPubKey {
			t.Fatalf("bloque %d: signerOf = %q, %v; want %q", b.Header.Index, got, err, b.Header.SignerPubKey)
		}
	}
}

func BenchmarkSignerOf(b *testing.B) {
	canon, err := chain(b, 1, 0)[0].Header.Canonical()
	if err != nil {
		b.Fatal(err)
	}
	h := string(canon)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := signerOf(h); err != nil {
			b.Fatal(err)
		}
	}
}
