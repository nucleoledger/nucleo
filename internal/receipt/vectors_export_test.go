package receipt

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"testing"

	"github.com/nucleoledger/nucleo/internal/checkpoint"
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
}

type vectorPolicy struct {
	Origin    string            `json:"origin"`
	LogKey    string            `json:"log_key"`
	SignerKey string            `json:"signer_key"`
	Witnesses map[string]string `json:"witnesses"`
	Quorum    int               `json:"quorum"`
}

// LOS VECTORES GOLDEN NO LOS GENERA ESTE PAQUETE.
//
// Los escribe testdata/vectors/receipt/generar.py, un oráculo independiente que
// implementa los formatos desde la especificación y no importa una línea de Go. La
// cuarta auditoría señaló que la regla del proyecto —"todo valor golden se calcula FUERA
// del código bajo prueba"— no se cumplía justo aquí: los recibos golden salían de
// internal/receipt, el paquete que verifican, así que reproducían sus propios errores.
//
// Lo único que Go sigue aportando a los vectores son los BYTES ML-DSA-44 de
// valido-firma-mldsa-del-log —la clave pública y la firma—, porque no hay ML-DSA en la
// caja de herramientas del oráculo (ADR-024). El vector entero lo construye el oráculo:
// la nota, el árbol, la hoja, el texto, la firma del emisor y hasta el key ID de la
// propia línea ML-DSA, que recompone desde la especificación. Y comprueba que la firma
// prestada es sobre exactamente el cuerpo de nota que él produce.
//
// El material se regenera en dos pasos, porque el oráculo tiene que decir primero QUÉ
// hay que firmar:
//
//	NUCLEO_REGENERAR_MATERIAL_MLDSA=1 go test ./internal/receipt -run TestRegeneraMaterialMLDSA
//
// (ese test ejecuta `generar.py --mldsa-body` por su cuenta para no copiar el cuerpo a
// mano, que es exactamente donde se cuela una divergencia).
func TestRegeneraMaterialMLDSA(t *testing.T) {
	if os.Getenv("NUCLEO_REGENERAR_MATERIAL_MLDSA") != "1" {
		t.Skip("solo se regenera a petición: NUCLEO_REGENERAR_MATERIAL_MLDSA=1")
	}
	dir := filepath.Join("..", "..", "testdata", "vectors", "receipt")
	cuerpo, err := exec.Command("python3", filepath.Join(dir, "generar.py"), "--mldsa-body").Output()
	if err != nil {
		t.Fatalf("el oráculo tiene que decir qué cuerpo firmar: %v", err)
	}
	seed := make([]byte, checkpoint.MLDSASeedSize)
	for i := range seed {
		seed[i] = byte(200 + i)
	}
	mldsa, err := checkpoint.NewMLDSASigner(testOrigin, seed)
	if err != nil {
		t.Fatal(err)
	}
	firma, err := mldsa.Sign(cuerpo)
	if err != nil {
		t.Fatal(err)
	}
	material := map[string]any{
		"comentario": "La única pieza de los vectores de recibo que no sale del oráculo Python: " +
			"los bytes ML-DSA-44. Ningún verificador los comprueba. Ver ADR-024 y generar.py.",
		"origin":           testOrigin,
		"alg":              checkpoint.AlgMLDSA44Ext,
		"extension_id":     checkpoint.MLDSAExtensionID,
		"public_key_hex":   hex.EncodeToString(mldsa.PublicKey()),
		"signature_hex":    hex.EncodeToString(firma),
		"signed_note_body": string(cuerpo),
		"firmado_por":      "internal/checkpoint.MLDSASigner.Sign (determinista), semilla 200..231",
	}
	raw, err := json.MarshalIndent(material, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "material", "mldsa.json"), append(raw, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("material/mldsa.json escrito: %d bytes de firma sobre %d bytes de cuerpo", len(firma), len(cuerpo))
}

// TestVectoresGoldenDicenLaVerdad lee TODOS los vectores del directorio —vengan del
// oráculo o de aquí— y comprueba que Go se comporta como cada uno declara. Es la otra
// mitad del trato: el oráculo dice qué debe pasar, este test dice si pasa.
func TestVectoresGoldenDicenLaVerdad(t *testing.T) {
	files, err := filepath.Glob(filepath.Join("..", "..", "testdata", "vectors", "receipt", "*.json"))
	if err != nil || len(files) < 17 {
		t.Fatalf("vectores: %d, %v", len(files), err)
	}
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var v vectorFile
		if err := json.Unmarshal(raw, &v); err != nil {
			t.Fatal(err)
		}
		t.Run(v.Name, func(t *testing.T) {
			assertVector(t, v)
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
// bytes ML-DSA de material/mldsa.json, y eso lo hace TestRegeneraMaterialMLDSA sin
// tocar ningún vector.

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
	// La única excepción, y es explícita: la regeneración del material ML-DSA escribe a
	// propósito, y solo con su variable puesta. Sin ella, cualquier escritura en el
	// directorio hunde la ejecución, que es de lo que va este guardián.
	if os.Getenv("NUCLEO_REGENERAR_MATERIAL_MLDSA") == "1" {
		os.Exit(code)
	}
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
// Incluye el material prestado de material/: no es un vector, pero es material golden y
// una suite que lo reescribiera estaría haciendo lo mismo que este guardián prohíbe.
func huellaDeVectores(dir string) string {
	files, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil {
		return "error: " + err.Error()
	}
	mat, err := filepath.Glob(filepath.Join(dir, "material", "*.json"))
	if err != nil {
		return "error: " + err.Error()
	}
	files = append(files, mat...)
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
