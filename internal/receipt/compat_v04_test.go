package receipt

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nucleoledger/nucleo/internal/policy"
)

// LA COMPATIBILIDAD CON v0.4.0-alpha (Sprint 31, ADR-034 «La compatibilidad»): con una
// política SIN logMLDSAKey, cada recibo da el mismo veredicto que daba el verificador de Go
// de v0.4.0-alpha.
//
// El veredicto de entonces NO lo calcula este paquete: está en
// testdata/compat-v0.4.0-alpha.json, y lo calculó el código del tag v0.4.0-alpha
// —internal/policy.Parse, ProofPolicy, Parse y Verify de entonces—, en un worktree del tag,
// sobre los casos que escribe este test con NUCLEO_COMPAT_CASOS_OUT (cómo regenerarlo, en
// la cabecera del fichero). Los casos: los 25 recibos de testdata/vectors/receipt/ —los
// 0.8-draft con su política sin la clave—, las mutaciones de catalogoDeMutaciones sobre
// cada uno, y el catálogo re-firmado del diferencial. Cada caso se identifica por el
// sha256 del recibo y de su política, así que un caso que cambie de bytes no encuentra su
// veredicto y el test falla: no compara contra lo que no es.

// casoCompat es un recibo con la política, en formato de cable, con la que se verifica.
type casoCompat struct {
	Nombre  string `json:"nombre"`
	Receipt string `json:"receipt"`
	Policy  string `json:"policy"`
}

// id es el sha256 de recibo ‖ 0x00 ‖ política: la clave del veredicto en el fichero.
func (c casoCompat) id() string {
	h := sha256.New()
	h.Write([]byte(c.Receipt))
	h.Write([]byte{0})
	h.Write([]byte(c.Policy))
	return hex.EncodeToString(h.Sum(nil))
}

// veredictoCompat es lo que se compara: si vale y, si vale, su tiempo demostrable.
type veredictoCompat struct {
	Valid        bool   `json:"valid"`
	ProvableTime string `json:"provable_time,omitempty"`
}

func casosDeCompatibilidad(t *testing.T) []casoCompat {
	t.Helper()
	files, err := filepath.Glob(filepath.Join("..", "..", "testdata", "vectors", "receipt", "*.json"))
	if err != nil || len(files) < 20 {
		t.Fatalf("vectores: %d, %v", len(files), err)
	}
	var out []casoCompat
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var v vectorFile
		if err := json.Unmarshal(raw, &v); err != nil {
			t.Fatal(err)
		}
		// La política del vector SIN logMLDSAKey: la única que entendía v0.4.0-alpha.
		pol, err := json.Marshal(map[string]any{"origin": v.Policy.Origin, "logKey": v.Policy.LogKey,
			"signerKey": v.Policy.SignerKey, "witnesses": v.Policy.Witnesses, "quorum": v.Policy.Quorum})
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, casoCompat{Nombre: v.Name, Receipt: v.Receipt, Policy: string(pol)})
		for _, m := range catalogoDeMutaciones(v.Receipt) {
			out = append(out, casoCompat{Nombre: v.Name + " / " + m.Nombre, Receipt: m.Receipt, Policy: string(pol)})
		}
	}
	for _, m := range catalogoRefirmado(t) {
		pol, err := json.Marshal(m.Policy)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, casoCompat{Nombre: m.Vector + " / " + m.Nombre, Receipt: m.Receipt, Policy: string(pol)})
	}
	return out
}

func veredictoDeHoy(t *testing.T, c casoCompat) veredictoCompat {
	t.Helper()
	f, err := policy.Parse([]byte(c.Policy))
	if err != nil {
		t.Fatalf("%s: la política del caso no parsea: %v", c.Nombre, err)
	}
	if f.LogMLDSAKey != "" {
		t.Fatalf("%s: la política trae logMLDSAKey", c.Nombre)
	}
	pol := f.ProofPolicy()
	r, err := Parse([]byte(c.Receipt), pol)
	if err != nil {
		return veredictoCompat{}
	}
	res, err := r.Verify(pol)
	if err != nil {
		return veredictoCompat{}
	}
	v := veredictoCompat{Valid: true}
	if len(res.Cosigners) > 0 {
		v.ProvableTime = res.ProvableTime.UTC().Format(time.RFC3339Nano)
	}
	return v
}

func TestCompatibilidadConV040AlphaSinLogMLDSAKey(t *testing.T) {
	casos := casosDeCompatibilidad(t)
	if out := os.Getenv("NUCLEO_COMPAT_CASOS_OUT"); out != "" {
		raw, err := json.MarshalIndent(casos, "", " ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(out, raw, 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("%d casos escritos en %s", len(casos), out)
	}
	raw, err := os.ReadFile(filepath.Join("testdata", "compat-v0.4.0-alpha.json"))
	if err != nil {
		t.Fatal(err)
	}
	var golden struct {
		Tag   string                     `json:"tag"`
		Casos map[string]veredictoCompat `json:"casos"`
	}
	if err := json.Unmarshal(raw, &golden); err != nil {
		t.Fatal(err)
	}
	distintos := map[string]bool{}
	for _, c := range casos {
		distintos[c.id()] = true
	}
	// Hay casos repetidos —dos mutaciones que dan los mismos bytes—, y el fichero los guarda
	// una vez.
	if golden.Tag != "v0.4.0-alpha" || len(golden.Casos) != len(distintos) {
		t.Fatalf("el fichero es de %q con %d casos, y hoy hay %d distintos", golden.Tag, len(golden.Casos), len(distintos))
	}
	validos := 0
	for _, c := range casos {
		antes, ok := golden.Casos[c.id()]
		if !ok {
			t.Errorf("%s: sin veredicto de v0.4.0-alpha (¿cambió de bytes?)", c.Nombre)
			continue
		}
		if hoy := veredictoDeHoy(t, c); hoy != antes {
			t.Errorf("%s: hoy %+v, v0.4.0-alpha %+v", c.Nombre, hoy, antes)
		}
		if antes.Valid {
			validos++
		}
	}
	if validos == 0 || validos == len(casos) {
		t.Errorf("%d válidos de %d: el fichero no distingue nada", validos, len(casos))
	}
}
