package vault

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"testing"
	"time"

	"github.com/nucleoledger/nucleo/internal/ledger"
)

// erasedStore simula la persistencia a efectos del borrado.
type erasedStore struct {
	deleted map[string]bool
	fail    error
}

func (e *erasedStore) DeleteBlob(h string) error {
	if e.fail != nil {
		return e.fail
	}
	if e.deleted == nil {
		e.deleted = map[string]bool{}
	}
	e.deleted[h] = true
	return nil
}

// TestEraseBlobLeavesLedgerProvable es el cumplimiento de la LOPDP por
// construcción, comprobado en vez de afirmado: tras borrar el payload en claro,
// la cadena sigue verificando, la raíz no cambia y la prueba de inclusión del
// bloque que lo comprometía sigue siendo válida.
//
// El dato desaparece; la prueba de que existió, no. Eso es exactamente lo que
// permite atender un derecho de supresión sin renunciar a la integridad del
// registro, y lo que separa a Núcleo de un log que guarda el contenido.
func TestEraseBlobLeavesLedgerProvable(t *testing.T) {
	dek := bytes.Repeat([]byte{0x44}, DEKLen)
	priv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{5}, ed25519.SeedSize))
	pub := priv.Public().(ed25519.PublicKey)
	t0 := time.Date(2026, 9, 5, 10, 0, 0, 0, time.UTC)

	// Tres bloques; el del medio compromete un payload sensible.
	payloads := [][]byte{[]byte("apertura"), []byte("DATO PERSONAL SENSIBLE"), []byte("cierre")}
	var blocks []*ledger.Block
	var prev *ledger.Block
	for i, p := range payloads {
		h, err := ledger.NewHeader(prev, testTenant, "sri.factura.v1", p, "blob://x", pub,
			t0.Add(time.Duration(i)*time.Minute))
		if err != nil {
			t.Fatal(err)
		}
		b, err := ledger.Seal(h, priv)
		if err != nil {
			t.Fatal(err)
		}
		blocks = append(blocks, b)
		prev = b
	}

	sensitiveHash := blocks[1].Header.PayloadHash
	ct, nonce, err := EncryptBlob(dek, testTenant, sensitiveHash, payloads[1])
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecryptBlob(dek, testTenant, sensitiveHash, ct, nonce); err != nil {
		t.Fatalf("control: el blob debería descifrar antes del borrado: %v", err)
	}

	leaves := make([][]byte, 0, len(blocks))
	for _, b := range blocks {
		hb, err := b.HashBytes()
		if err != nil {
			t.Fatal(err)
		}
		leaves = append(leaves, hb)
	}
	rootBefore := ledger.Root(leaves)
	proof, err := ledger.InclusionProof(leaves, 1)
	if err != nil {
		t.Fatal(err)
	}

	// Se ejerce el derecho de supresión.
	es := &erasedStore{}
	if err := EraseBlob(es, sensitiveHash); err != nil {
		t.Fatal(err)
	}
	if !es.deleted[sensitiveHash] {
		t.Fatal("EraseBlob no borró el blob")
	}

	// La cadena sigue verificando...
	if err := ledger.VerifyChain(blocks, pub); err != nil {
		t.Errorf("la cadena dejó de verificar tras el borrado: %v", err)
	}
	// ...la raíz anclada no cambió...
	if !bytes.Equal(ledger.Root(leaves), rootBefore) {
		t.Error("la raíz cambió tras borrar un payload")
	}
	// ...y la prueba de inclusión del bloque afectado sigue siendo válida.
	if err := ledger.VerifyInclusion(leaves[1], 1, len(leaves), proof, rootBefore); err != nil {
		t.Errorf("la prueba de inclusión dejó de verificar tras el borrado: %v", err)
	}
	// El compromiso permanece: sigue demostrando QUÉ se selló, sin revelarlo.
	if blocks[1].Header.PayloadHash != sensitiveHash {
		t.Error("el compromiso desapareció del ledger")
	}
	// Y lo borrado ya no es recuperable desde el ledger: solo queda el hash.
	if bytes.Contains([]byte(blocks[1].Header.PayloadHash), payloads[1]) {
		t.Error("el payload en claro es visible en el header")
	}
}

// TestEraseBlobPropagatesError comprueba que un fallo del almacén no se traga.
func TestEraseBlobPropagatesError(t *testing.T) {
	boom := errors.New("disco lleno")
	if err := EraseBlob(&erasedStore{fail: boom}, hashHex("x")); !errors.Is(err, boom) {
		t.Errorf("err = %v, want %v", err, boom)
	}
}
