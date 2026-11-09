//go:build testhooks

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// vectorDeRecibo es lo que verify-receipt necesita de un vector de testdata/vectors/receipt/.
type vectorDeRecibo struct {
	Name     string `json:"name"`
	Receipt  string `json:"receipt"`
	Valid    bool   `json:"valid"`
	Requires string `json:"requires"`
	Policy   struct {
		Origin      string            `json:"origin"`
		LogKey      string            `json:"log_key"`
		SignerKey   string            `json:"signer_key"`
		Witnesses   map[string]string `json:"witnesses"`
		Quorum      int               `json:"quorum"`
		LogMLDSAKey string            `json:"log_mldsa_key"`
	} `json:"policy"`
	Verdicts struct {
		Go struct {
			Valid    bool   `json:"valid"`
			LogMLDSA string `json:"log_mldsa"`
		} `json:"go"`
	} `json:"verdicts"`
}

// vectoresDeRecibo lee todos los vectores de recibo.
func vectoresDeRecibo(t *testing.T) []vectorDeRecibo {
	t.Helper()
	files, err := filepath.Glob(filepath.Join("..", "..", "testdata", "vectors", "receipt", "*.json"))
	if err != nil || len(files) < 20 {
		t.Fatalf("vectores de recibo: %d, %v", len(files), err)
	}
	var out []vectorDeRecibo
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var v vectorDeRecibo
		if err := json.Unmarshal(raw, &v); err != nil {
			t.Fatal(err)
		}
		out = append(out, v)
	}
	return out
}

// ficherosDeVector escribe el recibo y la política del vector (con la clave ML-DSA-44 o
// sin ella) en el formato de cable, y devuelve sus rutas.
func ficherosDeVector(t *testing.T, dir string, v vectorDeRecibo, conClaveMLDSA bool) (string, string) {
	t.Helper()
	doc := policyDoc{Origin: v.Policy.Origin, LogKey: v.Policy.LogKey, SignerKey: v.Policy.SignerKey,
		Witnesses: v.Policy.Witnesses, Quorum: v.Policy.Quorum}
	if conClaveMLDSA {
		doc.LogMLDSAKey = v.Policy.LogMLDSAKey
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	pol := filepath.Join(dir, v.Name+"-politica.json")
	rec := filepath.Join(dir, v.Name+".recibo")
	if err := os.WriteFile(pol, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rec, []byte(v.Receipt), 0o600); err != nil {
		t.Fatal(err)
	}
	return rec, pol
}

// resultadoVerifyReceipt es la salida --json de verify-receipt.
type resultadoVerifyReceipt struct {
	OK           bool     `json:"ok"`
	Valid        bool     `json:"valid"`
	Reasons      []string `json:"reasons"`
	LogMLDSA     *string  `json:"logMLDSA"`
	DeclaredTime *string  `json:"declaredTime"`
	ProvableTime *string  `json:"provableTime"`
	BlockIndex   *uint64  `json:"blockIndex"`
}

// verificaRecibo ejecuta verify-receipt --json y exige el código de salida.
func verificaRecibo(t *testing.T, c *cli, rec, pol string, codigo int) resultadoVerifyReceipt {
	t.Helper()
	out, _ := c.runWant(t, codigo, "--json", "verify-receipt", "--receipt", rec, "--policy-file", pol)
	var r resultadoVerifyReceipt
	if err := json.Unmarshal([]byte(out), &r); err != nil {
		t.Fatalf("verify-receipt --json no es un objeto (%v):\n%s", err, out)
	}
	if r.OK != r.Valid {
		t.Errorf("ok %v y valid %v se contradicen", r.OK, r.Valid)
	}
	return r
}

// TestVerifyReceiptDaElVeredictoDeGoDeLosVectores (ADR-034, decisión 8): verify-receipt da,
// para TODOS los recibos de testdata/vectors/receipt/, el veredicto de Go —el de
// verdicts.go en los 0.8-draft—, con la salida 0 o 2 que le toca y, cuando vale, los
// tiempos y el índice del vector.
func TestVerifyReceiptDaElVeredictoDeGoDeLosVectores(t *testing.T) {
	c := newCLI(t)
	for _, v := range vectoresDeRecibo(t) {
		t.Run(v.Name, func(t *testing.T) {
			rec, pol := ficherosDeVector(t, c.dir, v, true)
			want := v.Valid
			if v.Requires != "" {
				want = v.Verdicts.Go.Valid
			}
			codigo := exitOK
			if !want {
				codigo = exitVerify
			}
			r := verificaRecibo(t, c, rec, pol, codigo)
			if r.Valid != want {
				t.Fatalf("valid %v, y Go dice %v", r.Valid, want)
			}
			if !want {
				if len(r.Reasons) != 1 || r.Reasons[0] == "" || r.LogMLDSA != nil {
					t.Errorf("un recibo que no vale: reasons %q, logMLDSA %v", r.Reasons, r.LogMLDSA)
				}
				return
			}
			if r.LogMLDSA == nil || r.DeclaredTime == nil || r.BlockIndex == nil {
				t.Fatalf("faltan campos en un recibo válido: %+v", r)
			}
			if v.Verdicts.Go.LogMLDSA != "" && *r.LogMLDSA != v.Verdicts.Go.LogMLDSA {
				t.Errorf("logMLDSA %q, y el vector dice %q", *r.LogMLDSA, v.Verdicts.Go.LogMLDSA)
			}
			if v.Policy.LogMLDSAKey == "" && *r.LogMLDSA == "verified" {
				t.Error(`"verified" sin logMLDSAKey en la política`)
			}
		})
	}
}

// TestVerifyReceiptCasos: los cuatro casos que el Sprint 31 nombra, con su salida y su
// texto. La regla de los mensajes: cuando no vale, una frase que entienda quien no es
// criptógrafo.
func TestVerifyReceiptCasos(t *testing.T) {
	c := newCLI(t)
	porNombre := map[string]vectorDeRecibo{}
	for _, v := range vectoresDeRecibo(t) {
		porNombre[v.Name] = v
	}

	t.Run("válido", func(t *testing.T) {
		rec, pol := ficherosDeVector(t, c.dir, porNombre["valido-mldsa-fijada-verificada"], true)
		r := verificaRecibo(t, c, rec, pol, exitOK)
		if *r.LogMLDSA != "verified" || *r.DeclaredTime != "2026-09-06T14:32:00Z" || r.ProvableTime == nil ||
			*r.ProvableTime != "2026-09-06T15:00:00Z" || *r.BlockIndex != 2 {
			t.Errorf("%+v", r)
		}
		out, _ := c.runWant(t, exitOK, "verify-receipt", "--receipt", rec, "--policy-file", pol)
		if !strings.Contains(out, "✔ el recibo vale") || !strings.Contains(out, "verificada con la clave de la política") {
			t.Errorf("texto:\n%s", out)
		}
	})

	t.Run("alterado", func(t *testing.T) {
		v := porNombre["valido-n2-i1"]
		v.Name = "alterado-a-mano"
		v.Receipt = strings.Replace(v.Receipt, "María Pérez", "Maria Perez", 1)
		rec, pol := ficherosDeVector(t, c.dir, v, false)
		r := verificaRecibo(t, c, rec, pol, exitVerify)
		if r.Valid || !strings.Contains(r.Reasons[0], "se modificó después de firmarlo") &&
			!strings.Contains(r.Reasons[0], "alguien lo editó") {
			t.Errorf("motivo: %q", r.Reasons)
		}
		out, _ := c.runWant(t, exitVerify, "verify-receipt", "--receipt", rec, "--policy-file", pol)
		if !strings.Contains(out, "✘ el recibo NO vale: ") {
			t.Errorf("texto:\n%s", out)
		}
	})

	t.Run("ML-DSA mala con la clave en la política", func(t *testing.T) {
		rec, pol := ficherosDeVector(t, c.dir, porNombre["invalido-mldsa-fijada-alterada"], true)
		r := verificaRecibo(t, c, rec, pol, exitVerify)
		if !strings.Contains(r.Reasons[0], "firma post-cuántica del log no es la de la clave que fija tu política") {
			t.Errorf("motivo: %q", r.Reasons)
		}
	})

	t.Run("la misma sin la clave en la política", func(t *testing.T) {
		v := porNombre["invalido-mldsa-fijada-alterada"]
		v.Name += "-sin-clave"
		rec, pol := ficherosDeVector(t, c.dir, v, false)
		r := verificaRecibo(t, c, rec, pol, exitOK)
		if *r.LogMLDSA != "present-unverified" {
			t.Errorf("logMLDSA %q", *r.LogMLDSA)
		}
		out, _ := c.runWant(t, exitOK, "verify-receipt", "--receipt", rec, "--policy-file", pol)
		if !strings.Contains(out, "presente, NO verificada (la política no fija su clave: logMLDSAKey)") {
			t.Errorf("texto:\n%s", out)
		}
	})

	t.Run("sin la firma y la clave en la política", func(t *testing.T) {
		rec, pol := ficherosDeVector(t, c.dir, porNombre["invalido-mldsa-fijada-ausente"], true)
		r := verificaRecibo(t, c, rec, pol, exitVerify)
		if !strings.Contains(r.Reasons[0], "exige la firma post-cuántica del log (logMLDSAKey) y el recibo no la trae") {
			t.Errorf("motivo: %q", r.Reasons)
		}
	})
}

// TestVerifyReceiptUsoMal: sin --receipt, sin --policy-file, un fichero que no existe, una
// política inválida o sin signerKey son errores de uso: salida 1, sin abrir ningún ledger.
func TestVerifyReceiptUsoMal(t *testing.T) {
	c := newCLI(t)
	var v vectorDeRecibo
	for _, x := range vectoresDeRecibo(t) {
		if x.Name == "valido-n1-i0" {
			v = x
		}
	}
	rec, pol := ficherosDeVector(t, c.dir, v, false)
	invalida := filepath.Join(c.dir, "invalida.json")
	if err := os.WriteFile(invalida, []byte(`{"origin":"x"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	sinFirmante := filepath.Join(c.dir, "sin-firmante.json")
	raw, _ := json.Marshal(policyDoc{Origin: v.Policy.Origin, LogKey: v.Policy.LogKey, Witnesses: v.Policy.Witnesses, Quorum: 1})
	if err := os.WriteFile(sinFirmante, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"verify-receipt", "--policy-file", pol},
		{"verify-receipt", "--receipt", rec},
		{"verify-receipt", "--receipt", rec, "--policy-file", ""},
		{"verify-receipt", "--receipt", filepath.Join(c.dir, "no-existe"), "--policy-file", pol},
		{"verify-receipt", "--receipt", rec, "--policy-file", invalida},
		{"verify-receipt", "--receipt", rec, "--policy-file", sinFirmante},
		{"verify-receipt", "--receipt", rec, "--policy-file", pol, "sobra"},
	} {
		c.runWant(t, exitUsage, args...)
	}
	if _, err := os.Stat(filepath.Join(c.dir, "nucleo.db")); err == nil {
		t.Error("verify-receipt creó un ledger")
	}
}
