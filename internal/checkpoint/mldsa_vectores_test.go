package checkpoint

import (
	"bytes"
	"crypto/mldsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// El cruce de implementaciones de ADR-034 («Los vectores»): crypto/mldsa contra OpenSSL
// 3.5.9 y contra el ACVP del NIST. Ninguno de los dos ficheros lo escribe Go: los genera
// testdata/vectors/mldsa/generar.py con OpenSSL, y acvp.py los extrae del NIST en un
// commit fijado. Lo que se compara no es un golden que Go se calculó a sí mismo: es una
// implementación contra otra, byte a byte.

type vectoresMLDSA struct {
	Keys []struct {
		Name      string `json:"name"`
		Seed      string `json:"seed"`
		PublicKey string `json:"public_key"`
	} `json:"keys"`
	Cases []struct {
		Name      string `json:"name"`
		PublicKey string `json:"public_key"`
		Message   string `json:"message"`
		Signature string `json:"signature"`
		Valid     bool   `json:"valid"`
		How       struct {
			Key                      string `json:"key"`
			SignedBy                 string `json:"signed_by"`
			SignedMessage            string `json:"signed_message"`
			SignedContext            string `json:"signed_context"`
			Mutation                 string `json:"mutation"`
			UnmutatedSignatureSHA256 string `json:"unmutated_signature_sha256"`
		} `json:"how"`
	} `json:"cases"`
}

func directorioMLDSA() string {
	return filepath.Join("..", "..", "testdata", "vectors", "mldsa")
}

func desdeHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex: %v", err)
	}
	return b
}

// TestMLDSAVectoresOpenSSL: con la misma semilla, crypto/mldsa deriva la MISMA clave
// pública que OpenSSL; con la misma semilla y el mismo mensaje, MLDSASigner.Sign
// (SignDeterministic, contexto vacío) firma EXACTAMENTE los bytes que firmó OpenSSL; y
// crypto/mldsa da, con contexto vacío, el veredicto de cada vector.
func TestMLDSAVectoresOpenSSL(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(directorioMLDSA(), "firmas.json"))
	if err != nil {
		t.Fatal(err)
	}
	var v vectoresMLDSA
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	if len(v.Keys) != 2 || len(v.Cases) != 15 {
		t.Fatalf("%d claves y %d casos; el fichero tiene 2 y 15", len(v.Keys), len(v.Cases))
	}

	semillas := map[string][]byte{}
	for _, k := range v.Keys {
		seed := desdeHex(t, k.Seed)
		sk, err := mldsa.NewPrivateKey(mldsa.MLDSA44(), seed)
		if err != nil {
			t.Fatal(err)
		}
		if got := sk.PublicKey().Bytes(); !bytes.Equal(got, desdeHex(t, k.PublicKey)) {
			t.Errorf("clave %s: crypto/mldsa deriva otra clave pública que OpenSSL desde la misma semilla", k.Name)
		}
		semillas[k.Name] = seed
	}

	for _, c := range v.Cases {
		t.Run(c.Name, func(t *testing.T) {
			pub := desdeHex(t, c.PublicKey)
			msg := desdeHex(t, c.Message)
			sig := desdeHex(t, c.Signature)

			// La firma antes de la mutación, hecha por Go con la misma semilla, el mismo
			// mensaje y el mismo contexto: tiene que ser la de OpenSSL.
			seed := semillas[c.How.SignedBy]
			sk, err := mldsa.NewPrivateKey(mldsa.MLDSA44(), seed)
			if err != nil {
				t.Fatal(err)
			}
			firmado := desdeHex(t, c.How.SignedMessage)
			ctx := string(desdeHex(t, c.How.SignedContext))
			deGo, err := sk.SignDeterministic(firmado, &mldsa.Options{Context: ctx})
			if err != nil {
				t.Fatal(err)
			}
			if h := sha256.Sum256(deGo); hex.EncodeToString(h[:]) != c.How.UnmutatedSignatureSHA256 {
				t.Errorf("SignDeterministic de crypto/mldsa NO es la firma determinista de OpenSSL")
			}
			if c.How.Mutation == "" && !bytes.Equal(deGo, sig) {
				t.Errorf("SignDeterministic de crypto/mldsa NO es byte a byte la firma del vector")
			}
			// Y lo que firma el log en producción, con contexto vacío, es eso mismo.
			if ctx == "" {
				s, err := NewMLDSASigner("nucleoledger.com/recibos", seed)
				if err != nil {
					t.Fatal(err)
				}
				deLog, err := s.Sign(firmado)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(deLog, deGo) {
					t.Errorf("MLDSASigner.Sign no es SignDeterministic con contexto vacío")
				}
			}

			pk, err := mldsa.NewPublicKey(mldsa.MLDSA44(), pub)
			if err != nil {
				t.Fatal(err)
			}
			if got := mldsa.Verify(pk, msg, sig, &mldsa.Options{}) == nil; got != c.Valid {
				t.Errorf("crypto/mldsa dice valid=%v; OpenSSL, %v", got, c.Valid)
			}
			// MLDSAVerifier, lo que usará internal/proof, dice lo mismo.
			ver, err := NewMLDSAVerifier("nucleoledger.com/recibos", pub)
			if err != nil {
				t.Fatal(err)
			}
			if got := ver.Verify(msg, sig); got != c.Valid {
				t.Errorf("MLDSAVerifier dice valid=%v; OpenSSL, %v", got, c.Valid)
			}
		})
	}
}

// TestMLDSAVectoresACVP: crypto/mldsa da el veredicto del NIST en el subconjunto sigVer
// del ACVP (ML-DSA-44, interfaz externa, variante pura, contexto vacío; acvp.py).
func TestMLDSAVectoresACVP(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(directorioMLDSA(), "acvp-sigver-mldsa44.json"))
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Source struct {
			Commit string `json:"commit"`
		} `json:"source"`
		Tests []struct {
			TcID       int    `json:"tcId"`
			PK         string `json:"pk"`
			Message    string `json:"message"`
			Context    string `json:"context"`
			Signature  string `json:"signature"`
			TestPassed bool   `json:"testPassed"`
			Reason     string `json:"reason"`
		} `json:"tests"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	if v.Source.Commit != "a7f283cdc87d2d6dd93c1bac59e5622c5f9f8324" || len(v.Tests) == 0 {
		t.Fatalf("subconjunto del ACVP inesperado: commit %q, %d casos", v.Source.Commit, len(v.Tests))
	}
	for _, c := range v.Tests {
		if c.Context != "" {
			t.Fatalf("tcId %d: contexto no vacío en un subconjunto de contexto vacío", c.TcID)
		}
		pk, err := mldsa.NewPublicKey(mldsa.MLDSA44(), desdeHex(t, c.PK))
		if err != nil {
			t.Fatal(err)
		}
		got := mldsa.Verify(pk, desdeHex(t, c.Message), desdeHex(t, c.Signature), &mldsa.Options{}) == nil
		if got != c.TestPassed {
			t.Errorf("tcId %d (%s): el NIST dice %v y crypto/mldsa %v", c.TcID, c.Reason, c.TestPassed, got)
		}
	}
}
