package void

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Los vectores de testdata/vectors/void/ los calculó void/generar.py, FUERA de este código
// (regla anti-circularidad): aquí solo se leen y se comparan.

var dirVectores = filepath.Join("..", "..", "testdata", "vectors", "void")

func leeVector(t *testing.T, nombre string, v any) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dirVectores, nombre))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, v); err != nil {
		t.Fatalf("%s: %v", nombre, err)
	}
}

type vectoresPayload struct {
	Requires string
	Valid    []struct {
		Name              string
		VoidedIndex       string `json:"voided_index"`
		VoidedPayloadHash string `json:"voided_payload_hash"`
		Payload           string
		PayloadLength     int    `json:"payload_length"`
		PayloadSHA256     string `json:"payload_sha256"`
	}
	Invalid []struct {
		Name          string
		Payload       string
		PayloadSHA256 string `json:"payload_sha256"`
	}
}

func TestElPayloadCoincideConLosVectores(t *testing.T) {
	var v vectoresPayload
	leeVector(t, "payload.json", &v)
	if v.Requires != "0.9-draft" || len(v.Valid) != 4 || len(v.Invalid) != 6 {
		t.Fatalf("payload.json: requires %q, %d válidos, %d inválidos", v.Requires, len(v.Valid), len(v.Invalid))
	}
	validos := map[string]bool{}
	for _, c := range v.Valid {
		i := indiceDelVector(t, c.VoidedIndex)
		p, err := Payload(i, c.VoidedPayloadHash)
		if err != nil {
			t.Fatalf("%s: %v", c.Name, err)
		}
		if string(p) != c.Payload || len(p) != c.PayloadLength {
			t.Errorf("%s: payload = %s (%d bytes)\nwant      %s (%d)", c.Name, p, len(p), c.Payload, c.PayloadLength)
		}
		h, err := EventPayloadHash(i, c.VoidedPayloadHash)
		if err != nil || h != c.PayloadSHA256 {
			t.Errorf("%s: EventPayloadHash = %s, %v; want %s", c.Name, h, err, c.PayloadSHA256)
		}
		validos[h] = true
	}
	// Ninguno de los inválidos es lo que produce Payload: su hash no es el de ningún válido.
	for _, c := range v.Invalid {
		if validos[c.PayloadSHA256] {
			t.Errorf("%s: el hash de un payload inválido coincide con uno válido", c.Name)
		}
	}
	// Y Payload no construye los que se podrían pedir: 2^53 y un hash en mayúsculas.
	const h = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	if _, err := Payload(1<<53, h); err == nil {
		t.Error("Payload(2^53) no falló")
	}
	if _, err := Payload(3, strings.ToUpper(h)); err == nil {
		t.Error("Payload con el hash en mayúsculas no falló")
	}
	if _, err := Payload(3, h[:63]); err == nil {
		t.Error("Payload con un hash corto no falló")
	}
}

func indiceDelVector(t *testing.T, s string) uint64 {
	t.Helper()
	var i uint64
	for _, c := range s {
		i = i*10 + uint64(c-'0')
	}
	return i
}

func TestElCidCoincideConLosVectores(t *testing.T) {
	var v struct {
		Valid []struct {
			PayloadCID  string `json:"payload_cid"`
			VoidedIndex string `json:"voided_index"`
		}
		Invalid []struct {
			PayloadCID string `json:"payload_cid"`
		}
	}
	leeVector(t, "cid.json", &v)
	if len(v.Valid) != 3 || len(v.Invalid) != 7 {
		t.Fatalf("cid.json: %d válidos, %d inválidos", len(v.Valid), len(v.Invalid))
	}
	for _, c := range v.Valid {
		i, err := ParseCID(c.PayloadCID)
		if err != nil || i != indiceDelVector(t, c.VoidedIndex) {
			t.Errorf("ParseCID(%q) = %d, %v; want %s", c.PayloadCID, i, err, c.VoidedIndex)
		}
		if got := CID(i); got != c.PayloadCID {
			t.Errorf("CID(%d) = %q, want %q", i, got, c.PayloadCID)
		}
	}
	for _, c := range v.Invalid {
		if i, err := ParseCID(c.PayloadCID); err == nil {
			t.Errorf("ParseCID(%q) aceptó un cid inválido (índice %d)", c.PayloadCID, i)
		}
	}
}
