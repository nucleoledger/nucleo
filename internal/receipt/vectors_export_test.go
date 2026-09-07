package receipt

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nucleoledger/nucleo/internal/proof"
)

// Estos vectores son LA VARA del verificador de TypeScript.
//
// Se exportan desde un test para que no puedan desincronizarse del código que
// los produce: si el formato del recibo cambia, este test los reescribe y el
// diff sale en la revisión. Un fichero generado a mano se queda viejo en
// silencio, que es la peor forma de tener vectores.

// vectorFile es la forma de cada fichero exportado.
type vectorFile struct {
	// Name identifica el caso.
	Name string `json:"name"`
	// Description dice qué demuestra, en español, para quien lea el JSON.
	Description string `json:"description"`
	// Receipt es el recibo COMPLETO, tal cual se entrega.
	Receipt string `json:"receipt"`
	// Policy son las claves con las que hay que verificarlo.
	Policy vectorPolicy `json:"policy"`
	// EntryHash es la hoja de Merkle esperada: SHA-256(JCS(header)).
	EntryHash string `json:"entry_hash"`
	// Valid dice si debe verificar.
	Valid bool `json:"valid"`
	// Reason nombra el motivo del rechazo cuando Valid es false.
	Reason string `json:"reason,omitempty"`
	// DeclaredTime y ProvableTime son lo que el verificador debe extraer.
	DeclaredTime string `json:"declared_time"`
	ProvableTime string `json:"provable_time,omitempty"`
	BlockIndex   uint64 `json:"block_index"`
}

type vectorPolicy struct {
	Origin    string            `json:"origin"`
	LogKey    string            `json:"log_key"`
	Witnesses map[string]string `json:"witnesses"`
	Quorum    int               `json:"quorum"`
}

// TestExportReceiptVectors escribe testdata/vectors/receipt/.
func TestExportReceiptVectors(t *testing.T) {
	dir := filepath.Join("..", "..", "testdata", "vectors", "receipt")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}

	sc := newScene(t, 1)
	r, err := Issue(sc.store, "María Pérez (cédula 1712345678)", 2)
	if err != nil {
		t.Fatal(err)
	}
	pol := sc.policy()
	data, err := Format(r, pol)
	if err != nil {
		t.Fatal(err)
	}
	entryHash, err := r.EntryHash()
	if err != nil {
		t.Fatal(err)
	}
	declared, err := r.DeclaredTime()
	if err != nil {
		t.Fatal(err)
	}
	provable, hasProvable, err := r.ProvableTime(pol)
	if err != nil {
		t.Fatal(err)
	}
	if !hasProvable {
		t.Fatal("el vector válido debe tener tiempo demostrable")
	}

	exported := vectorPolicy{
		Origin:    pol.Origin,
		LogKey:    hex.EncodeToString(pol.LogKey),
		Witnesses: map[string]string{},
		Quorum:    pol.Quorum,
	}
	for name, pub := range pol.Witnesses {
		exported.Witnesses[name] = hex.EncodeToString(pub)
	}

	valid := vectorFile{
		Name:         "valido-1-cosignature",
		Description:  "Recibo correcto con una cosignature de un testigo aceptado. Debe verificar.",
		Receipt:      string(data),
		Policy:       exported,
		EntryHash:    hex.EncodeToString(entryHash),
		Valid:        true,
		DeclaredTime: declared.UTC().Format(timeLayout),
		ProvableTime: provable.UTC().Format(timeLayout),
		BlockIndex:   r.Proof.Index,
	}

	// Caso 2: encabezado retocado. La prueba sigue siendo impecable; lo que
	// falla es que el texto visible ya no dice lo que dicen los bytes.
	altered := valid
	altered.Name = "alterado-encabezado"
	altered.Description = "El mismo recibo con el tenant cambiado EN EL TEXTO. La prueba verifica, pero el encabezado ya no se deriva de ella: debe rechazarse."
	altered.Receipt = strings.Replace(valid.Receipt, "emisor (tenant)   : "+testTenant,
		"emisor (tenant)   : 9999999999001", 1)
	altered.Valid = false
	altered.Reason = "header_mismatch"
	if altered.Receipt == valid.Receipt {
		t.Fatal("la alteración no se aplicó: el vector no probaría nada")
	}

	// Caso 3: la cosignature es de una clave que la política NO acepta.
	untrusted := valid
	untrusted.Name = "cosignature-no-confiable"
	untrusted.Description = "El mismo recibo verificado con una política que no acepta a ese testigo. La firma del log verifica, pero el tiempo demostrable que muestra no lo respalda nadie aceptado: debe rechazarse."
	untrusted.Valid = false
	untrusted.Reason = "untrusted_cosignature"
	untrusted.Policy = vectorPolicy{
		Origin: exported.Origin, LogKey: exported.LogKey,
		Witnesses: map[string]string{}, Quorum: 0,
	}
	untrusted.ProvableTime = ""

	for _, v := range []vectorFile{valid, altered, untrusted} {
		raw, err := json.MarshalIndent(v, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		raw = append(raw, '\n')
		path := filepath.Join(dir, v.Name+".json")
		if err := os.WriteFile(path, raw, 0o644); err != nil {
			t.Fatal(err)
		}
	}

	// Y se comprueba aquí mismo que los tres vectores dicen la verdad, para que
	// no se exporte nunca un vector que el propio Go no respalda.
	assertVector(t, valid)
	assertVector(t, altered)
	assertVector(t, untrusted)
}

// assertVector comprueba que el vector se comporte como declara.
func assertVector(t *testing.T, v vectorFile) {
	t.Helper()
	pol := policyFromVector(t, v.Policy)
	parsed, err := Parse([]byte(v.Receipt), pol)
	if v.Valid {
		if err != nil {
			t.Fatalf("%s: debía verificar y no lo hace: %v", v.Name, err)
		}
		if _, err := parsed.Verify(pol); err != nil {
			t.Fatalf("%s: Verify falló: %v", v.Name, err)
		}
		return
	}
	if err == nil {
		if _, err := parsed.Verify(pol); err == nil {
			t.Fatalf("%s: debía rechazarse y verificó", v.Name)
		}
	}
}

// policyFromVector reconstruye la política desde su forma exportada, que es la
// misma que leerá el verificador de TypeScript.
func policyFromVector(t *testing.T, v vectorPolicy) proof.Policy {
	t.Helper()
	logKey, err := hex.DecodeString(v.LogKey)
	if err != nil {
		t.Fatal(err)
	}
	pol := proof.Policy{
		Origin:    v.Origin,
		LogKey:    ed25519.PublicKey(logKey),
		Quorum:    v.Quorum,
		Witnesses: map[string]ed25519.PublicKey{},
	}
	for name, hexKey := range v.Witnesses {
		raw, err := hex.DecodeString(hexKey)
		if err != nil {
			t.Fatal(err)
		}
		pol.Witnesses[name] = ed25519.PublicKey(raw)
	}
	return pol
}
