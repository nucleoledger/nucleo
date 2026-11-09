package proof

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nucleoledger/nucleo/internal/checkpoint"
	"github.com/nucleoledger/nucleo/internal/ledger"
	"github.com/nucleoledger/nucleo/internal/witness"
)

// La firma ML-DSA-44 del log con una política que fija logMLDSAKey (PROTOCOL 0.8-draft
// §3.3, ADR-034). Los vectores de testdata/vectors/receipt/ prueban los casos del oráculo
// —firmados por OpenSSL—; aquí van las reglas que necesitan construir la nota a medida:
// la longitud, el key ID ajeno, la Ed25519 obligatoria, y el key ID contra un valor
// calculado fuera del código.

// TestMLDSAKeyIDCalculadoFuera: el key ID de P es
// SHA-256(origin ‖ "\n" ‖ 0xff ‖ "nucleoledger.com/sig/ml-dsa-44@v1" ‖ "\n" ‖ P)[:4], y el
// valor esperado NO lo calcula Go: salió de Python hashlib y de sha256sum (Sprint 31),
// sobre la clave de la política del vector valido-mldsa-fijada-verificada —que generó
// OpenSSL— y su origin:
//
//	python3 -c "import json,hashlib; d=json.load(open('testdata/vectors/receipt/valido-mldsa-fijada-verificada.json'));
//	  o=d['policy']['origin'].encode(); P=bytes.fromhex(d['policy']['log_mldsa_key']);
//	  print(hashlib.sha256(o+b'\n\xffnucleoledger.com/sig/ml-dsa-44@v1\n'+P).hexdigest()[:8])"
//	{ printf 'nucleoledger.com/recibos\n\377nucleoledger.com/sig/ml-dsa-44@v1\n'; printf '%s' "$P" | xxd -r -p; } | sha256sum
//
// Los dos dan f2c2d51c. Y es el key ID que lleva la línea ML-DSA-44 de ese recibo.
func TestMLDSAKeyIDCalculadoFuera(t *testing.T) {
	const fuera = "f2c2d51c"
	var v struct {
		Receipt string `json:"receipt"`
		Policy  struct {
			Origin      string `json:"origin"`
			LogMLDSAKey string `json:"log_mldsa_key"`
		} `json:"policy"`
	}
	raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "vectors", "receipt", "valido-mldsa-fijada-verificada.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	pub, err := hex.DecodeString(v.Policy.LogMLDSAKey)
	if err != nil {
		t.Fatal(err)
	}
	mv, err := checkpoint.NewMLDSAVerifier(v.Policy.Origin, pub)
	if err != nil {
		t.Fatal(err)
	}
	var got [4]byte
	binary.BigEndian.PutUint32(got[:], mv.KeyHash())
	if hex.EncodeToString(got[:]) != fuera {
		t.Fatalf("key ID de Go %x, calculado fuera %s", got, fuera)
	}
	encontrado := false
	for _, l := range strings.Split(v.Receipt, "\n") {
		b64, ok := strings.CutPrefix(l, "— "+v.Policy.Origin+" ")
		if !ok {
			continue
		}
		if blob, err := base64.StdEncoding.DecodeString(b64); err == nil && len(blob) == 4+2420 &&
			hex.EncodeToString(blob[:4]) == fuera {
			encontrado = true
		}
	}
	if !encontrado {
		t.Error("el recibo no trae una línea ML-DSA-44 con ese key ID")
	}
}

// mldsaEnv es un log con firma Ed25519 y ML-DSA-44, cosignado por un testigo.
type mldsaEnv struct {
	note   []byte // la nota completa, con la cosignature
	text   []byte // el texto firmado
	logEd  string // la línea Ed25519 del log
	logPQ  string // la línea ML-DSA-44 del log
	cosig  string // la línea del testigo
	otra   string // una línea ML-DSA-44 válida del log con OTRA clave
	policy Policy
	leaf   []byte
	rec    Receipt
}

func newMLDSAEnv(t *testing.T) *mldsaEnv {
	t.Helper()
	leaves := make([][]byte, 3)
	for i := range leaves {
		d, err := ledger.LeafData(ledger.LeafHash([]byte{byte(i)}), make([]byte, ed25519.SignatureSize))
		if err != nil {
			t.Fatal(err)
		}
		leaves[i] = d
	}
	logPriv := ed25519.NewKeyFromSeed(seed(0))
	ed, err := checkpoint.NewSigner(testOrigin, logPriv)
	if err != nil {
		t.Fatal(err)
	}
	pq, err := checkpoint.NewMLDSASigner(testOrigin, seed(50))
	if err != nil {
		t.Fatal(err)
	}
	otra, err := checkpoint.NewMLDSASigner(testOrigin, seed(60))
	if err != nil {
		t.Fatal(err)
	}
	c := checkpoint.Checkpoint{Origin: testOrigin, Size: uint64(len(leaves)), RootHash: ledger.Root(leaves)}
	msg, err := checkpoint.Sign(c, ed, pq)
	if err != nil {
		t.Fatal(err)
	}
	conOtra, err := checkpoint.Sign(c, otra)
	if err != nil {
		t.Fatal(err)
	}
	witPriv := ed25519.NewKeyFromSeed(seed(100))
	w, err := witness.New(witnessOne, witPriv, func() time.Time { return time.Unix(fixedUnixTS, 0).UTC() })
	if err != nil {
		t.Fatal(err)
	}
	if err := w.AddLog(testOrigin, logPriv.Public().(ed25519.PublicKey)); err != nil {
		t.Fatal(err)
	}
	cosigned, err := w.Cosign(msg, nil)
	if err != nil {
		t.Fatal(err)
	}
	e := &mldsaEnv{note: cosigned, leaf: leaves[1]}
	e.text, e.logEd, e.logPQ, e.cosig = partirNota(t, cosigned)
	_, e.otra, _, _ = partirNota(t, conOtra)
	path, err := ledger.InclusionProof(leaves, 1)
	if err != nil {
		t.Fatal(err)
	}
	e.rec = Receipt{Index: 1, InclusionProof: path}
	e.policy = Policy{
		Origin: testOrigin, LogKey: logPriv.Public().(ed25519.PublicKey), Quorum: 1,
		Witnesses:   map[string]ed25519.PublicKey{witnessOne: witPriv.Public().(ed25519.PublicKey)},
		LogMLDSAKey: pq.PublicKey(),
	}
	return e
}

// partirNota devuelve el texto y las líneas de firma de una nota, en orden: la primera,
// la segunda y la tercera (vacías si no las hay).
func partirNota(t *testing.T, n []byte) ([]byte, string, string, string) {
	t.Helper()
	i := bytes.LastIndex(n, []byte("\n\n"))
	lineas := strings.Split(strings.TrimSuffix(string(n[i+2:]), "\n"), "\n")
	for len(lineas) < 3 {
		lineas = append(lineas, "")
	}
	return n[:i+1], lineas[0], lineas[1], lineas[2]
}

// conLineas arma la nota con el texto y estas líneas de firma.
func (e *mldsaEnv) conLineas(lineas ...string) Receipt {
	r := e.rec
	r.CheckpointNote = append(append(append([]byte{}, e.text...), '\n'), []byte(strings.Join(lineas, "\n")+"\n")...)
	return r
}

// lineaMLDSAConFirma devuelve la línea ML-DSA-44 del log con la firma (tras el key ID)
// sustituida por sig.
func (e *mldsaEnv) lineaMLDSAConFirma(t *testing.T, sig []byte) string {
	t.Helper()
	b64 := strings.TrimPrefix(e.logPQ, "— "+testOrigin+" ")
	blob, err := base64.StdEncoding.DecodeString(b64)
	if err != nil || len(blob) != 4+2420 {
		t.Fatalf("la línea ML-DSA-44 no tiene la forma esperada (%d bytes, %v)", len(blob), err)
	}
	return "— " + testOrigin + " " + base64.StdEncoding.EncodeToString(append(blob[:4:4], sig...))
}

// TestMLDSAConLaClaveEnLaPolitica: las reglas de §3.3 con logMLDSAKey, una por caso.
func TestMLDSAConLaClaveEnLaPolitica(t *testing.T) {
	e := newMLDSAEnv(t)
	b64 := strings.TrimPrefix(e.logPQ, "— "+testOrigin+" ")
	blob, _ := base64.StdEncoding.DecodeString(b64)
	alterada := append([]byte{}, blob[4:]...)
	alterada[1032] ^= 0x08

	casos := []struct {
		nombre string
		lineas []string
		want   error // nil: válido y "verified"
	}{
		{"la nota tal cual", []string{e.logEd, e.logPQ, e.cosig}, nil},
		{"firma alterada", []string{e.logEd, e.lineaMLDSAConFirma(t, alterada), e.cosig}, ErrMLDSASignature},
		{"dos líneas, la buena y una mala", []string{e.logEd, e.logPQ, e.lineaMLDSAConFirma(t, alterada), e.cosig}, ErrMLDSASignature},
		{"dos líneas, la mala primero", []string{e.logEd, e.lineaMLDSAConFirma(t, alterada), e.logPQ, e.cosig}, ErrMLDSASignature},
		{"sin la línea", []string{e.logEd, e.cosig}, ErrMLDSAMissing},
		{"solo la de otra clave", []string{e.logEd, e.otra, e.cosig}, ErrMLDSAMissing},
		{"la buena y la de otra clave", []string{e.logEd, e.otra, e.logPQ, e.cosig}, nil},
		{"su key ID con 2419 bytes", []string{e.logEd, e.logPQ, e.lineaMLDSAConFirma(t, blob[4:2423]), e.cosig}, ErrMLDSASignature},
		{"su key ID con 2421 bytes", []string{e.logEd, e.logPQ, e.lineaMLDSAConFirma(t, append(append([]byte{}, blob[4:]...), 0)), e.cosig}, ErrMLDSASignature},
		{"su key ID con 64 bytes", []string{e.logEd, e.logPQ, e.lineaMLDSAConFirma(t, blob[4:68]), e.cosig}, ErrMLDSASignature},
		// La regla 3: ML-DSA-44 se suma, no sustituye.
		// x/mod abre la nota con la cosignature del testigo; la rechaza VerifyNote.
		{"sin la Ed25519 del log", []string{e.logPQ, e.cosig}, ErrOrigin},
	}
	for _, c := range casos {
		t.Run(c.nombre, func(t *testing.T) {
			res, err := e.conLineas(c.lineas...).Verify(e.leaf, e.policy)
			if c.want == nil {
				if err != nil {
					t.Fatalf("tenía que valer: %v", err)
				}
				if res.LogMLDSA != LogMLDSAVerified {
					t.Errorf("logMLDSA %q", res.LogMLDSA)
				}
				return
			}
			if err == nil {
				t.Fatalf("tenía que rechazarse (%v), y vale con logMLDSA %q", c.want, res.LogMLDSA)
			}
			if !errors.Is(err, c.want) {
				t.Errorf("error %v, y tenía que ser %v", err, c.want)
			}
		})
	}
}

// TestMLDSASinLaClaveEnLaPolitica: sin logMLDSAKey, todo como en 0.7-draft —la línea no
// decide nada, ni alterada—, y LogMLDSA dice lo único que se sabe: presente sin verificar,
// o ausente. Nunca "verified".
func TestMLDSASinLaClaveEnLaPolitica(t *testing.T) {
	e := newMLDSAEnv(t)
	pol := e.policy
	pol.LogMLDSAKey = nil
	b64 := strings.TrimPrefix(e.logPQ, "— "+testOrigin+" ")
	blob, _ := base64.StdEncoding.DecodeString(b64)
	alterada := append([]byte{}, blob[4:]...)
	alterada[0] ^= 1
	casos := []struct {
		nombre string
		lineas []string
		want   string
	}{
		{"la nota tal cual", []string{e.logEd, e.logPQ, e.cosig}, LogMLDSAPresentUnverified},
		{"firma alterada", []string{e.logEd, e.lineaMLDSAConFirma(t, alterada), e.cosig}, LogMLDSAPresentUnverified},
		{"solo la de otra clave", []string{e.logEd, e.otra, e.cosig}, LogMLDSAPresentUnverified},
		{"sin la línea", []string{e.logEd, e.cosig}, LogMLDSAAbsent},
	}
	for _, c := range casos {
		t.Run(c.nombre, func(t *testing.T) {
			res, err := e.conLineas(c.lineas...).Verify(e.leaf, pol)
			if err != nil {
				t.Fatalf("sin logMLDSAKey tenía que valer: %v", err)
			}
			if res.LogMLDSA != c.want {
				t.Errorf("logMLDSA %q, want %q", res.LogMLDSA, c.want)
			}
		})
	}
}

// TestMLDSAClaveDeLaPoliticaMalMedida: una clave que no mide 1312 bytes es una política
// inválida, no una firma que no verifica.
func TestMLDSAClaveDeLaPoliticaMalMedida(t *testing.T) {
	e := newMLDSAEnv(t)
	pol := e.policy
	pol.LogMLDSAKey = pol.LogMLDSAKey[:1311]
	if _, err := e.conLineas(e.logEd, e.logPQ, e.cosig).Verify(e.leaf, pol); !errors.Is(err, ErrPolicy) {
		t.Fatalf("clave de 1311 bytes: %v", err)
	}
}
