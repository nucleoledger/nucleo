package receipt

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
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
	// LeafData es leaf_data de la hoja, en hex: hash ‖ signature (leaf/v2,
	// PROTOCOL.md §2.1). Lo que el verificador mete en la prueba de inclusión.
	LeafData string `json:"leaf_data"`
	// LeafRule nombra la regla con la que se construyó, para que un verificador
	// futuro sepa qué está leyendo sin deducirlo del tamaño.
	LeafRule string `json:"leaf_rule"`
	// BlockSig es la firma del bloque en hex, la que el recibo ahora transporta.
	BlockSig string `json:"block_signature"`
	// Valid dice si debe verificar.
	Valid bool `json:"valid"`
	// Reason nombra el motivo del rechazo cuando Valid es false.
	Reason string `json:"reason,omitempty"`
	// DeclaredTime y ProvableTime son lo que el verificador debe extraer.
	DeclaredTime string `json:"declared_time"`
	ProvableTime string `json:"provable_time,omitempty"`
	BlockIndex   uint64 `json:"block_index"`
	// Requires nombra la versión del protocolo que el vector exige: "0.8-draft" en los
	// recibos con una política que fija log_mldsa_key (ADR-034 §F). Valid y Reason son
	// entonces los de Go con ML-DSA, y Verdicts dice el de cada verificador.
	Requires string `json:"requires,omitempty"`
	Verdicts struct {
		// Go es el veredicto de este verificador con la política tal cual, log_mldsa_key
		// incluida: el que manda aquí desde el Sprint C2.
		Go veredictoVector `json:"go"`
		// WithoutLogMLDSAKey es el veredicto con la política sin log_mldsa_key: el de
		// todo lector 0.7-draft, y el de este con esa política.
		WithoutLogMLDSAKey veredictoVector `json:"without_log_mldsa_key"`
	} `json:"verdicts"`
}

// veredictoVector es el veredicto de un verificador en un vector 0.8-draft.
type veredictoVector struct {
	Valid    bool   `json:"valid"`
	Reason   string `json:"reason,omitempty"`
	LogMLDSA string `json:"log_mldsa,omitempty"`
}

type vectorPolicy struct {
	Origin    string            `json:"origin"`
	LogKey    string            `json:"log_key"`
	SignerKey string            `json:"signer_key"`
	Witnesses map[string]string `json:"witnesses"`
	Quorum    int               `json:"quorum"`
	// LogMLDSAKey es logMLDSAKey en hexadecimal, o "" (ADR-034).
	LogMLDSAKey string `json:"log_mldsa_key,omitempty"`
}

// LOS VECTORES GOLDEN NO LOS GENERA ESTE PAQUETE.
//
// Los escribe testdata/vectors/receipt/generar.py, un oráculo independiente que
// implementa los formatos desde la especificación y no importa una línea de Go. La
// cuarta auditoría señaló que la regla del proyecto —"todo valor golden se calcula FUERA
// del código bajo prueba"— no se cumplía justo aquí: los recibos golden salían de
// internal/receipt, el paquete que verifican, así que reproducían sus propios errores.
//
// Tampoco los bytes ML-DSA-44: desde el Sprint 29 los firma OpenSSL 3.5.9, la
// implementación independiente de ADR-034 (decisión 7), y no Go. Aquí vivía
// TestRegeneraMaterialMLDSA, que escribía material/mldsa.json con
// checkpoint.MLDSASigner; se borra con el material (ADR-024, enmienda del 2026-10-24).
// OpenSSL firma los mismos bytes que firmaba Go —lo comprueba
// internal/checkpoint.TestMLDSAVectoresOpenSSL—, así que valido-firma-mldsa-del-log no
// cambió ni uno.

// TestVectoresGoldenDicenLaVerdad lee TODOS los vectores del directorio —vengan del
// oráculo o de aquí— y comprueba que Go se comporta como cada uno declara. Es la otra
// mitad del trato: el oráculo dice qué debe pasar, este test dice si pasa.
func TestVectoresGoldenDicenLaVerdad(t *testing.T) {
	files, err := filepath.Glob(filepath.Join("..", "..", "testdata", "vectors", "receipt", "*.json"))
	if err != nil || len(files) < 17 {
		t.Fatalf("vectores: %d, %v", len(files), err)
	}
	presentes := 0
	defer func() {
		// Los dos estados sin clave tienen que salir en algún vector, o el test no prueba
		// la distinción: hoy, valido-firma-mldsa-del-log es el "present-unverified".
		if presentes == 0 {
			t.Error(`ningún vector válido sin clave trae la línea ML-DSA-44: "present-unverified" sin probar`)
		}
	}()
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var v vectorFile
		if err := json.Unmarshal(raw, &v); err != nil {
			t.Fatal(err)
		}
		switch v.Requires {
		case "":
		case "0.8-draft":
			// Desde el Sprint C2 este verificador lee log_mldsa_key y verifica la ML-DSA-44:
			// manda el veredicto declarado para Go. Y, con la misma política sin la clave,
			// el de todo lector 0.7-draft (TestVectoresMLDSASinClave).
			if v.Verdicts.Go.Valid != v.Valid {
				t.Fatalf("%s: verdicts.go.valid %v y valid %v: el vector se contradice", v.Name, v.Verdicts.Go.Valid, v.Valid)
			}
		default:
			t.Fatalf("%s: requires %q, una versión que este test no conoce", v.Name, v.Requires)
		}
		if v.Valid && v.Policy.LogMLDSAKey == "" && tieneLineaConFormaMLDSA(v.Receipt, v.Policy.Origin) {
			presentes++
		}
		t.Run(v.Name, func(t *testing.T) {
			assertVector(t, v)
			assertLogMLDSA(t, v)
			if v.Valid {
				pol := policyFromVector(t, v.Policy)
				r, err := Parse([]byte(v.Receipt), pol)
				if err != nil {
					t.Fatal(err)
				}
				// Los campos que el vector publica tienen que ser los que Go calcula:
				// si el oráculo y Go difieren en el tiempo o en la hoja, se ve aquí.
				if r.Header.Timestamp != v.DeclaredTime {
					t.Errorf("declared_time = %s, el header dice %s", v.DeclaredTime, r.Header.Timestamp)
				}
				hoja, err := r.LeafData()
				if err != nil {
					t.Fatal(err)
				}
				if hex.EncodeToString(hoja) != v.LeafData {
					t.Errorf("leaf_data no coincide con la hoja que recompone Go")
				}
				provable, ok, err := r.ProvableTime(pol)
				if err != nil {
					t.Fatal(err)
				}
				if !ok || provable.UTC().Format(timeLayout) != v.ProvableTime {
					t.Errorf("provable_time = %s, Go calcula %s", v.ProvableTime, provable.UTC().Format(timeLayout))
				}
			}
		})
	}
}

// Aquí vivía exportValid, que escribía un vector desde este paquete. Se borra con el
// Sprint 8 (ADR-024): ya no queda ni un vector de recibo que Go escriba, así que el
// código que sabía escribirlos tampoco tiene que quedarse. Lo que Go aporta son los
// bytes ML-DSA de material/mldsa.json, y eso lo hacía TestRegeneraMaterialMLDSA sin
// tocar ningún vector (ya no: los firma OpenSSL, arriba).

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

// assertLogMLDSA comprueba el campo de tres estados (PROTOCOL 0.8-draft §3.3) y el motivo
// de Go. Con la clave en la política: "verified" en los válidos, y en los inválidos el
// motivo del vector —mldsa_signature_invalid o mldsa_signature_missing—. Sin ella:
// "present-unverified" si la nota trae una línea a nombre del log con forma de ML-DSA-44
// y "absent" si no; nunca "verified".
func assertLogMLDSA(t *testing.T, v vectorFile) {
	t.Helper()
	pol := policyFromVector(t, v.Policy)
	r, err := Parse([]byte(v.Receipt), pol)
	var res proof.Result
	if err == nil {
		res, err = r.Verify(pol)
	}
	if v.Requires == "0.8-draft" && !v.Valid {
		want := map[string]error{"mldsa_signature_invalid": proof.ErrMLDSASignature,
			"mldsa_signature_missing": proof.ErrMLDSAMissing}[v.Verdicts.Go.Reason]
		if want == nil || !errors.Is(err, want) {
			t.Errorf("motivo de Go %q, y el error es %v", v.Verdicts.Go.Reason, err)
		}
		return
	}
	if !v.Valid {
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	if v.Policy.LogMLDSAKey != "" {
		if res.LogMLDSA != proof.LogMLDSAVerified || v.Verdicts.Go.LogMLDSA != proof.LogMLDSAVerified {
			t.Errorf("logMLDSA %q con la clave en la política (el vector dice %q)", res.LogMLDSA, v.Verdicts.Go.LogMLDSA)
		}
		return
	}
	want := proof.LogMLDSAAbsent
	if tieneLineaConFormaMLDSA(v.Receipt, v.Policy.Origin) {
		want = proof.LogMLDSAPresentUnverified
	}
	if res.LogMLDSA != want {
		t.Errorf("logMLDSA %q sin clave en la política, y tenía que ser %q", res.LogMLDSA, want)
	}
}

// tieneLineaConFormaMLDSA dice, leyendo el recibo a mano y sin internal/proof, si trae una
// línea de firma a nombre del origin cuyo base64 decodifica a 4 + 2420 bytes: la forma de
// la firma ML-DSA-44 del log (PROTOCOL 0.8-draft §3.3).
func tieneLineaConFormaMLDSA(recibo, origin string) bool {
	for _, l := range strings.Split(recibo, "\n") {
		b64, ok := strings.CutPrefix(l, "— "+origin+" ")
		if !ok {
			continue
		}
		if raw, err := base64.StdEncoding.DecodeString(b64); err == nil && len(raw) == 4+2420 {
			return true
		}
	}
	return false
}

// TestVectoresMLDSASinClave: cada recibo 0.8-draft, con su política SIN log_mldsa_key, da el
// veredicto de without_log_mldsa_key —el de v0.4.0-alpha— y su logMLDSA.
func TestVectoresMLDSASinClave(t *testing.T) {
	files, err := filepath.Glob(filepath.Join("..", "..", "testdata", "vectors", "receipt", "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var v vectorFile
		if err := json.Unmarshal(raw, &v); err != nil {
			t.Fatal(err)
		}
		if v.Requires != "0.8-draft" {
			continue
		}
		n++
		t.Run(v.Name, func(t *testing.T) {
			v.Policy.LogMLDSAKey = ""
			pol := policyFromVector(t, v.Policy)
			r, err := Parse([]byte(v.Receipt), pol)
			var res proof.Result
			if err == nil {
				res, err = r.Verify(pol)
			}
			w := v.Verdicts.WithoutLogMLDSAKey
			if (err == nil) != w.Valid {
				t.Fatalf("sin log_mldsa_key: válido %v, el vector dice %v (%v)", err == nil, w.Valid, err)
			}
			if err == nil && w.LogMLDSA != "" && res.LogMLDSA != w.LogMLDSA {
				t.Errorf("sin log_mldsa_key: logMLDSA %q, el vector dice %q", res.LogMLDSA, w.LogMLDSA)
			}
			if res.LogMLDSA == proof.LogMLDSAVerified {
				t.Error(`"verified" sin clave en la política`)
			}
		})
	}
	if n != 7 {
		t.Fatalf("%d recibos 0.8-draft; son 7 (el séptimo, invalido-mldsa-fijada-mide-2419, del Sprint 32)", n)
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
	signerKey, err := hex.DecodeString(v.SignerKey)
	if err != nil {
		t.Fatal(err)
	}
	pol := proof.Policy{
		Origin:    v.Origin,
		LogKey:    ed25519.PublicKey(logKey),
		SignerKey: ed25519.PublicKey(signerKey),
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
	if v.LogMLDSAKey != "" {
		if pol.LogMLDSAKey, err = hex.DecodeString(v.LogMLDSAKey); err != nil {
			t.Fatal(err)
		}
	}
	return pol
}

// TestMain vigila que la suite NO modifique los vectores.
//
// Un golden que el propio test reescribe no es un golden: se adapta al código en vez de
// juzgarlo, y durante meses aquí pasó eso sin que nadie lo viera. Se toma la huella del
// directorio antes y después de correr todo el paquete.
func TestMain(m *testing.M) {
	dir := filepath.Join("..", "..", "testdata", "vectors", "receipt")
	antes := huellaDeVectores(dir)
	code := m.Run()
	// Sin excepciones desde que se fue el material ML-DSA prestado (ADR-024, enmienda del
	// 2026-10-24): cualquier escritura en el directorio hunde la ejecución.
	if despues := huellaDeVectores(dir); despues != antes {
		fmt.Fprintln(os.Stderr, "los tests MODIFICARON los vectores golden: un golden que el test reescribe no juzga nada")
		if code == 0 {
			code = 1
		}
	}
	os.Exit(code)
}

// huellaDeVectores resume el contenido del directorio en un hash.
//
// Incluía material/, el material ML-DSA prestado; se fue con ADR-024 enmendado.
func huellaDeVectores(dir string) string {
	files, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil {
		return "error: " + err.Error()
	}
	sort.Strings(files)
	h := sha256.New()
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			return "error: " + err.Error()
		}
		fmt.Fprintf(h, "%s:%x\n", filepath.ToSlash(f), sha256.Sum256(raw))
	}
	return hex.EncodeToString(h.Sum(nil))
}
