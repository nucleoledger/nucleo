package erasure

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// Los vectores de testdata/vectors/erasure/ los calcula generar.py con la biblioteca
// `cryptography` de Python, y se comprobaron además con OpenSSL 3 (PROTOCOL §5.1): nada
// de este paquete interviene en ellos (regla anti-circularidad).

func leeVector(t *testing.T, nombre string, v any) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "vectors", "erasure", nombre))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, v); err != nil {
		t.Fatal(err)
	}
}

func clavePublica(t *testing.T, h string) ed25519.PublicKey {
	t.Helper()
	b, err := hex.DecodeString(h)
	if err != nil || len(b) != ed25519.PublicKeySize {
		t.Fatalf("clave %q: %v", h, err)
	}
	return b
}

func TestLaAutorizacionCoincideConElVector(t *testing.T) {
	var v struct {
		Seed              string `json:"seed"`
		PublicKey         string `json:"public_key"`
		Origin            string `json:"origin"`
		ErasedPayloadHash string `json:"erased_payload_hash"`
		Through           uint64 `json:"through"`
		Message           string `json:"message"`
		PayloadCID        string `json:"payload_cid"`
		EventPayloadHash  string `json:"event_payload_hash"`
	}
	leeVector(t, "autorizacion.json", &v)
	seed, _ := hex.DecodeString(v.Seed)
	priv := ed25519.NewKeyFromSeed(seed)
	if got := hex.EncodeToString(priv.Public().(ed25519.PublicKey)); got != v.PublicKey {
		t.Fatalf("clave pública = %s, want %s", got, v.PublicKey)
	}

	txt, err := AuthorizationText(v.Origin, v.ErasedPayloadHash, v.Through)
	if err != nil {
		t.Fatal(err)
	}
	if string(txt) != v.Message {
		t.Errorf("texto = %q\nwant    %q", txt, v.Message)
	}
	cid, err := Authorize(priv, v.Origin, v.ErasedPayloadHash, v.Through)
	if err != nil {
		t.Fatal(err)
	}
	if cid != v.PayloadCID {
		t.Errorf("payload_cid = %s\nwant          %s", cid, v.PayloadCID)
	}
	through, err := VerifyCID(clavePublica(t, v.PublicKey), v.Origin, v.ErasedPayloadHash, v.PayloadCID)
	if err != nil || through != v.Through {
		t.Errorf("VerifyCID = %d, %v", through, err)
	}
	if eph, _ := EventPayloadHash(v.ErasedPayloadHash); eph != v.EventPayloadHash {
		t.Errorf("hash del evento = %s, want %s", eph, v.EventPayloadHash)
	}
}

func TestCasosDeLaAutorizacion(t *testing.T) {
	var v struct {
		Cases []struct {
			Name              string `json:"name"`
			PublicKey         string `json:"public_key"`
			Origin            string `json:"origin"`
			ErasedPayloadHash string `json:"erased_payload_hash"`
			PayloadCID        string `json:"payload_cid"`
			Valid             bool   `json:"valid"`
		} `json:"cases"`
	}
	leeVector(t, "casos.json", &v)
	if len(v.Cases) < 15 {
		t.Fatalf("solo %d casos", len(v.Cases))
	}
	for _, c := range v.Cases {
		t.Run(c.Name, func(t *testing.T) {
			_, err := VerifyCID(clavePublica(t, c.PublicKey), c.Origin, c.ErasedPayloadHash, c.PayloadCID)
			if c.Valid && err != nil {
				t.Errorf("debía verificar: %v", err)
			}
			if !c.Valid && err == nil {
				t.Errorf("debía rechazarse")
			}
		})
	}
}

// TestSinClaveNadaEstaAutorizado: sin erasureKey en la política no hay contra qué
// comprobar, y lo que no se puede comprobar no se da por bueno (ADR-032 §D).
func TestSinClaveNadaEstaAutorizado(t *testing.T) {
	var v struct {
		Origin            string `json:"origin"`
		ErasedPayloadHash string `json:"erased_payload_hash"`
		PayloadCID        string `json:"payload_cid"`
	}
	leeVector(t, "autorizacion.json", &v)
	if _, err := VerifyCID(nil, v.Origin, v.ErasedPayloadHash, v.PayloadCID); err == nil {
		t.Error("sin clave, la autorización verificó")
	}
}
