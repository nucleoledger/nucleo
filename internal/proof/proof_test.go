package proof

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/nucleoledger/nucleo/internal/checkpoint"
	"github.com/nucleoledger/nucleo/internal/ledger"
	"github.com/nucleoledger/nucleo/internal/witness"
)

const (
	testOrigin  = "nucleoledger.com/poc"
	witnessOne  = "witness.nucleoledger.com/w1"
	witnessTwo  = "witness.nucleoledger.com/w2"
	fixedUnixTS = 1_800_000_000
)

func seed(b byte) []byte {
	s := make([]byte, ed25519.SeedSize)
	for i := range s {
		s[i] = b + byte(i)
	}
	return s
}

type env struct {
	t        *testing.T
	leaves   [][]byte
	logPriv  ed25519.PrivateKey
	witPriv  map[string]ed25519.PrivateKey
	receipt  Receipt
	policy   Policy
	entry    []byte
	entryIdx int
}

// newEnv construye un log de 5 hojas, lo cosigna con un testigo y emite el
// recibo de la entrada 2.
func newEnv(t *testing.T) *env {
	t.Helper()
	e := &env{t: t, entryIdx: 2, witPriv: map[string]ed25519.PrivateKey{}}
	e.leaves = make([][]byte, 5)
	for i := range e.leaves {
		h := ledger.LeafHash([]byte(fmt.Sprintf("bloque-%d", i)))
		e.leaves[i] = h // hojas de 32 bytes, como los hashes de bloque reales
	}
	e.entry = e.leaves[e.entryIdx]

	e.logPriv = ed25519.NewKeyFromSeed(seed(0))
	logSigner, err := checkpoint.NewSigner(testOrigin, e.logPriv)
	if err != nil {
		t.Fatal(err)
	}
	msg, err := checkpoint.Sign(checkpoint.Checkpoint{
		Origin: testOrigin, Size: uint64(len(e.leaves)), RootHash: ledger.Root(e.leaves),
	}, logSigner)
	if err != nil {
		t.Fatal(err)
	}

	e.witPriv[witnessOne] = ed25519.NewKeyFromSeed(seed(100))
	clk := func() time.Time { return time.Unix(fixedUnixTS, 0).UTC() }
	w, err := witness.New(witnessOne, e.witPriv[witnessOne], clk)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.AddLog(testOrigin, e.logPriv.Public().(ed25519.PublicKey)); err != nil {
		t.Fatal(err)
	}
	cosigned, err := w.Cosign(msg, nil)
	if err != nil {
		t.Fatal(err)
	}

	path, err := ledger.InclusionProof(e.leaves, e.entryIdx)
	if err != nil {
		t.Fatal(err)
	}
	e.receipt = Receipt{Index: uint64(e.entryIdx), InclusionProof: path, CheckpointNote: cosigned}
	e.policy = Policy{
		Origin:    testOrigin,
		LogKey:    e.logPriv.Public().(ed25519.PublicKey),
		Witnesses: map[string]ed25519.PublicKey{witnessOne: e.witPriv[witnessOne].Public().(ed25519.PublicKey)},
		Quorum:    1,
	}
	return e
}

// TestVerifyValidReceipt es el camino feliz, y comprueba de paso el tiempo
// demostrable de ADR-002.
func TestVerifyValidReceipt(t *testing.T) {
	e := newEnv(t)
	res, err := e.receipt.Verify(e.entry, e.policy)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.Checkpoint.Size != 5 {
		t.Errorf("tamaño = %d, want 5", res.Checkpoint.Size)
	}
	if len(res.Cosigners) != 1 || res.Cosigners[0] != witnessOne {
		t.Errorf("cosignantes = %v, want [%s]", res.Cosigners, witnessOne)
	}
	if res.ProvableTime.Unix() != fixedUnixTS {
		t.Errorf("tiempo demostrable = %d, want %d", res.ProvableTime.Unix(), fixedUnixTS)
	}
	if len(res.IgnoredSigs) != 0 {
		t.Errorf("firmas ignoradas = %v, want ninguna", res.IgnoredSigs)
	}
}

// TestFormatParseRoundTrip comprueba que serializar y volver a leer no pierde ni
// altera nada, y que Parse(Format(x)) da los mismos bytes.
func TestFormatParseRoundTrip(t *testing.T) {
	e := newEnv(t)
	data, err := Format(e.receipt)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(data, []byte(Magic+"\n")) {
		t.Errorf("el recibo no empieza por %q", Magic)
	}
	got, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got.Index != e.receipt.Index {
		t.Errorf("índice = %d, want %d", got.Index, e.receipt.Index)
	}
	if len(got.InclusionProof) != len(e.receipt.InclusionProof) {
		t.Fatalf("nodos = %d, want %d", len(got.InclusionProof), len(e.receipt.InclusionProof))
	}
	for i := range got.InclusionProof {
		if !bytes.Equal(got.InclusionProof[i], e.receipt.InclusionProof[i]) {
			t.Errorf("nodo %d difiere", i)
		}
	}
	if !bytes.Equal(got.CheckpointNote, e.receipt.CheckpointNote) {
		t.Error("la nota del checkpoint no sobrevivió el round-trip")
	}
	again, err := Format(got)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, again) {
		t.Error("Format(Parse(x)) no reproduce los mismos bytes")
	}
	// Y el recibo releído sigue verificando.
	if _, err := got.Verify(e.entry, e.policy); err != nil {
		t.Errorf("el recibo releído no verifica: %v", err)
	}
}

// TestVerifyRejectsRewrittenTree: el log reescribe una entrada y firma la nueva
// raíz. El recibo antiguo delata la diferencia.
func TestVerifyRejectsRewrittenTree(t *testing.T) {
	e := newEnv(t)

	rewritten := make([][]byte, len(e.leaves))
	copy(rewritten, e.leaves)
	rewritten[1] = ledger.LeafHash([]byte("factura alterada"))

	logSigner, err := checkpoint.NewSigner(testOrigin, e.logPriv)
	if err != nil {
		t.Fatal(err)
	}
	evilNote, err := checkpoint.Sign(checkpoint.Checkpoint{
		Origin: testOrigin, Size: uint64(len(rewritten)), RootHash: ledger.Root(rewritten),
	}, logSigner)
	if err != nil {
		t.Fatal(err)
	}

	// El recibo viejo con el checkpoint nuevo: la entrada ya no está.
	tampered := e.receipt
	tampered.CheckpointNote = evilNote
	policy := e.policy
	policy.Quorum = 0 // el checkpoint falso ni siquiera tiene cosignature
	if _, err := tampered.Verify(e.entry, policy); !errors.Is(err, ErrInclusion) {
		t.Errorf("acepta un checkpoint de un árbol reescrito: err = %v", err)
	}

	// El log sí puede fabricar un recibo coherente de la entrada 2 en su árbol
	// falso —la hoja 2 no cambió, así que sigue incluida—, y ese recibo verifica.
	// Eso no es un fallo del verificador: una prueba de inclusión demuestra
	// pertenencia a UN árbol, no que ese árbol sea legítimo.
	//
	// Lo que delata la reescritura es que la raíz es otra. El tenedor del recibo
	// antiguo tiene firmada por el log una raíz que el log ahora niega, y esa
	// contradicción es la evidencia. Detectarla en vivo es trabajo del testigo.
	evilPath, err := ledger.InclusionProof(rewritten, e.entryIdx)
	if err != nil {
		t.Fatal(err)
	}
	tampered.InclusionProof = evilPath
	evilRes, err := tampered.Verify(e.entry, policy)
	if err != nil {
		t.Fatalf("el recibo del árbol falso debería ser internamente coherente: %v", err)
	}
	honest, err := e.receipt.Verify(e.entry, e.policy)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(evilRes.Checkpoint.RootHash, honest.Checkpoint.RootHash) {
		t.Fatal("la reescritura no cambió la raíz: el escenario del test es inválido")
	}
	// Y el recibo honesto sigue verificando: quien lo guardó conserva la prueba
	// de una raíz que el log ya no reconoce.
	if honest.Checkpoint.Size != evilRes.Checkpoint.Size {
		t.Errorf("los dos checkpoints deberían declarar el mismo tamaño: %d vs %d",
			honest.Checkpoint.Size, evilRes.Checkpoint.Size)
	}
}

// TestVerifyQuorum comprueba la regla de quórum en ambos sentidos.
func TestVerifyQuorum(t *testing.T) {
	e := newEnv(t)

	// Quórum 2 con una sola cosignature: debe fallar.
	policy := e.policy
	policy.Witnesses = map[string]ed25519.PublicKey{
		witnessOne: e.witPriv[witnessOne].Public().(ed25519.PublicKey),
		witnessTwo: ed25519.NewKeyFromSeed(seed(200)).Public().(ed25519.PublicKey),
	}
	policy.Quorum = 2
	if _, err := e.receipt.Verify(e.entry, policy); !errors.Is(err, ErrQuorum) {
		t.Errorf("acepta con quórum no alcanzado: err = %v", err)
	}

	// Quórum 0: el recibo vale aunque no haya testigos que la política conozca.
	policy.Witnesses = nil
	policy.Quorum = 0
	res, err := e.receipt.Verify(e.entry, policy)
	if err != nil {
		t.Fatalf("con quórum 0: %v", err)
	}
	// La cosignature del testigo desconocido se ignora, no rompe.
	if len(res.IgnoredSigs) != 1 || res.IgnoredSigs[0] != witnessOne {
		t.Errorf("firmas ignoradas = %v, want [%s]", res.IgnoredSigs, witnessOne)
	}
	if len(res.Cosigners) != 0 {
		t.Errorf("no debería contar testigos fuera de la política: %v", res.Cosigners)
	}

	// Una política con más quórum que testigos configurados es incoherente.
	policy.Quorum = 1
	if _, err := e.receipt.Verify(e.entry, policy); !errors.Is(err, ErrPolicy) {
		t.Errorf("acepta una política incoherente: err = %v", err)
	}
}

// TestVerifyRejectsWrongInputs recorre los rechazos de Verify.
func TestVerifyRejectsWrongInputs(t *testing.T) {
	e := newEnv(t)

	otherEntry := ledger.LeafHash([]byte("otra entrada"))
	if _, err := e.receipt.Verify(otherEntry, e.policy); !errors.Is(err, ErrInclusion) {
		t.Errorf("acepta una entrada que no es la del recibo: err = %v", err)
	}
	if _, err := e.receipt.Verify(e.entry[:31], e.policy); err == nil {
		t.Error("acepta un hash de entrada de longitud inválida")
	}

	wrongOrigin := e.policy
	wrongOrigin.Origin = "otro.example/log"
	if _, err := e.receipt.Verify(e.entry, wrongOrigin); err == nil {
		t.Error("acepta un recibo de otro origin")
	}

	wrongKey := e.policy
	wrongKey.LogKey = ed25519.NewKeyFromSeed(seed(77)).Public().(ed25519.PublicKey)
	if _, err := e.receipt.Verify(e.entry, wrongKey); err == nil {
		t.Error("acepta un recibo con la clave del log equivocada")
	}

	badIndex := e.receipt
	badIndex.Index = 99
	if _, err := badIndex.Verify(e.entry, e.policy); !errors.Is(err, ErrIndex) {
		t.Errorf("acepta un índice fuera del árbol: err = %v", err)
	}

	// Camino manipulado nodo a nodo.
	for i := range e.receipt.InclusionProof {
		mutated := Receipt{Index: e.receipt.Index, CheckpointNote: e.receipt.CheckpointNote}
		for j, n := range e.receipt.InclusionProof {
			c := append([]byte(nil), n...)
			if i == j {
				c[0] ^= 0xff
			}
			mutated.InclusionProof = append(mutated.InclusionProof, c)
		}
		if _, err := mutated.Verify(e.entry, e.policy); err == nil {
			t.Errorf("acepta el camino con el nodo %d alterado", i)
		}
	}

	// Política sin clave de log.
	noKey := e.policy
	noKey.LogKey = nil
	if _, err := e.receipt.Verify(e.entry, noKey); !errors.Is(err, ErrPolicy) {
		t.Errorf("acepta una política sin clave de log: err = %v", err)
	}
}

// TestParseRejectsMalformed recorre las formas de recibo inválido.
func TestParseRejectsMalformed(t *testing.T) {
	e := newEnv(t)
	valid, err := Format(e.receipt)
	if err != nil {
		t.Fatal(err)
	}
	v := string(valid)

	cases := []struct {
		name string
		data string
	}{
		{"vacío", ""},
		{"sin encabezado", strings.TrimPrefix(v, Magic+"\n")},
		{"encabezado equivocado", "c2sp.org/tlog-proof@v2\n" + strings.TrimPrefix(v, Magic+"\n")},
		{"sin índice", Magic + "\n"},
		{"índice con cero a la izquierda", strings.Replace(v, "\n2\n", "\n02\n", 1)},
		{"índice no numérico", strings.Replace(v, "\n2\n", "\ndos\n", 1)},
		{"sin línea en blanco", Magic + "\n2\n"},
		{"sin checkpoint", Magic + "\n2\n\n"},
		{"nodo no base64", Magic + "\n2\nno-base64!!\n\n" + string(e.receipt.CheckpointNote)},
		{"nodo de tamaño incorrecto", Magic + "\n2\nAAAA\n\n" + string(e.receipt.CheckpointNote)},
		{"última línea sin salto", strings.TrimSuffix(v, "\n")},
	}
	for _, c := range cases {
		if _, err := Parse([]byte(c.data)); err == nil {
			t.Errorf("%s: Parse aceptó un recibo inválido", c.name)
		}
	}
}

// TestFormatRejectsInvalidReceipt cubre el dominio del serializador.
func TestFormatRejectsInvalidReceipt(t *testing.T) {
	e := newEnv(t)
	cases := []struct {
		name string
		r    Receipt
	}{
		{"sin nota", Receipt{Index: 1}},
		{"nota sin salto final", Receipt{Index: 1, CheckpointNote: []byte("abc")}},
		{"nodo corto", Receipt{Index: 1, InclusionProof: [][]byte{{1, 2, 3}}, CheckpointNote: e.receipt.CheckpointNote}},
	}
	for _, c := range cases {
		if _, err := Format(c.r); err == nil {
			t.Errorf("%s: Format aceptó un recibo inválido", c.name)
		}
	}
}
