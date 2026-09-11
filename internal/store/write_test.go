package store

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/nucleoledger/nucleo/internal/checkpoint"
	"github.com/nucleoledger/nucleo/internal/ledger"
)

const testTenant = "1790012345001"

var testBase = time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)

func testKeys(t testing.TB, b byte) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	s := make([]byte, ed25519.SeedSize)
	for i := range s {
		s[i] = b + byte(i)
	}
	priv := ed25519.NewKeyFromSeed(s)
	return priv.Public().(ed25519.PublicKey), priv
}

// chain sella n bloques encadenados con la clave indicada.
func chain(t testing.TB, n int, keyByte byte) []*ledger.Block {
	t.Helper()
	pub, priv := testKeys(t, keyByte)
	out := make([]*ledger.Block, 0, n)
	var prev *ledger.Block
	for i := 0; i < n; i++ {
		h, err := ledger.NewHeader(prev, testTenant, "sri.factura.v1",
			[]byte(fmt.Sprintf("payload-%d", i)), "blob://x", pub, testBase.Add(time.Duration(i)*time.Minute))
		if err != nil {
			t.Fatal(err)
		}
		b, err := ledger.Seal(h, priv)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, b)
		prev = b
	}
	return out
}

// TestAppendBlockSequence cubre el camino feliz y la lectura de vuelta.
func TestAppendBlockSequence(t *testing.T) {
	s := openTemp(t)
	blocks := chain(t, 5, 0)

	if _, err := s.LastBlock(); !errors.Is(err, ErrNotFound) {
		t.Errorf("ledger vacío: err = %v, want %v", err, ErrNotFound)
	}
	for _, b := range blocks {
		if err := s.AppendBlock(b); err != nil {
			t.Fatalf("bloque %d: %v", b.Header.Index, err)
		}
	}

	n, err := s.Count()
	if err != nil {
		t.Fatal(err)
	}
	if n != 5 {
		t.Errorf("Count = %d, want 5", n)
	}

	last, err := s.LastBlock()
	if err != nil {
		t.Fatal(err)
	}
	if last.Header.Index != 4 || last.Hash != blocks[4].Hash {
		t.Errorf("LastBlock = %+v", last.Header)
	}

	// Los bloques leídos de vuelta deben verificar: es lo que prueba que el
	// header se guardó en su forma canónica y no en otra equivalente.
	all, err := s.AllBlocks()
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 5 {
		t.Fatalf("AllBlocks = %d bloques, want 5", len(all))
	}
	pub, _ := testKeys(t, 0)
	if err := ledger.VerifyChain(all, pub); err != nil {
		t.Fatalf("la cadena leída de la base no verifica: %v", err)
	}
	for i, b := range all {
		if b.Hash != blocks[i].Hash || b.Signature != blocks[i].Signature {
			t.Errorf("bloque %d difiere tras el round-trip", i)
		}
	}

	// Rangos.
	mid, err := s.Blocks(1, 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(mid) != 2 || mid[0].Header.Index != 1 || mid[1].Header.Index != 2 {
		t.Errorf("Blocks(1,3) devolvió %d bloques", len(mid))
	}
	if empty, err := s.Blocks(3, 3); err != nil || len(empty) != 0 {
		t.Errorf("Blocks(3,3) = %v, %v", empty, err)
	}
	if empty, err := s.Blocks(9, 2); err != nil || len(empty) != 0 {
		t.Errorf("Blocks(9,2) = %v, %v", empty, err)
	}

	// Las hojas del árbol son hash ‖ signature, en orden (leaf/v2, PROTOCOL.md
	// §2.1). Se comprueban las dos mitades por separado y no la concatenación ya
	// hecha: así el test detecta también un orden invertido, que daría la misma
	// longitud y pasaría desapercibido.
	leaves, err := s.LeafData()
	if err != nil {
		t.Fatal(err)
	}
	if len(leaves) != 5 {
		t.Fatalf("LeafData = %d, want 5", len(leaves))
	}
	for i, l := range leaves {
		if len(l) != ledger.LeafDataSize {
			t.Errorf("hoja %d mide %d bytes, want %d", i, len(l), ledger.LeafDataSize)
			continue
		}
		if got := hex.EncodeToString(l[:32]); got != blocks[i].Hash {
			t.Errorf("hoja %d, primera mitad = %s, want el hash %s", i, got, blocks[i].Hash)
		}
		if got := hex.EncodeToString(l[32:]); got != blocks[i].Signature {
			t.Errorf("hoja %d, segunda mitad = %s, want la firma %s", i, got, blocks[i].Signature)
		}
	}
}

// TestAppendBlockRejects cubre lo que el almacén NO debe aceptar.
func TestAppendBlockRejects(t *testing.T) {
	blocks := chain(t, 4, 0)

	t.Run("bloque nulo", func(t *testing.T) {
		s := openTemp(t)
		if err := s.AppendBlock(nil); err == nil {
			t.Error("aceptó un bloque nulo")
		}
	})

	t.Run("el primero no es génesis", func(t *testing.T) {
		s := openTemp(t)
		if err := s.AppendBlock(blocks[1]); !errors.Is(err, ledger.ErrIndexSequence) {
			t.Errorf("err = %v, want %v", err, ledger.ErrIndexSequence)
		}
	})

	t.Run("bloque alterado", func(t *testing.T) {
		s := openTemp(t)
		bad := *blocks[0]
		bad.Header.Tenant = "9999999999001"
		if err := s.AppendBlock(&bad); !errors.Is(err, ledger.ErrHashMismatch) {
			t.Errorf("err = %v, want %v", err, ledger.ErrHashMismatch)
		}
	})

	t.Run("salto de índice", func(t *testing.T) {
		s := openTemp(t)
		if err := s.AppendBlock(blocks[0]); err != nil {
			t.Fatal(err)
		}
		if err := s.AppendBlock(blocks[2]); !errors.Is(err, ledger.ErrIndexSequence) {
			t.Errorf("err = %v, want %v", err, ledger.ErrIndexSequence)
		}
	})

	t.Run("prev_hash de otra cadena", func(t *testing.T) {
		s := openTemp(t)
		if err := s.AppendBlock(blocks[0]); err != nil {
			t.Fatal(err)
		}
		other := chain(t, 2, 100)
		if err := s.AppendBlock(other[1]); !errors.Is(err, ledger.ErrPrevHashMismatch) {
			t.Errorf("err = %v, want %v", err, ledger.ErrPrevHashMismatch)
		}
	})

	t.Run("mismo bloque dos veces", func(t *testing.T) {
		s := openTemp(t)
		if err := s.AppendBlock(blocks[0]); err != nil {
			t.Fatal(err)
		}
		if err := s.AppendBlock(blocks[0]); err == nil {
			t.Error("aceptó el mismo bloque dos veces")
		}
	})
}

// TestCheckpointRoundTrip cubre el guardado de notas firmadas.
func TestCheckpointRoundTrip(t *testing.T) {
	s := openTemp(t)
	_, priv := testKeys(t, 7)
	signer, err := checkpoint.NewSigner("nucleoledger.com/poc", priv)
	if err != nil {
		t.Fatal(err)
	}
	note := func(size uint64, seed byte) []byte {
		root := make([]byte, 32)
		for i := range root {
			root[i] = seed + byte(i)
		}
		msg, err := checkpoint.Sign(checkpoint.Checkpoint{
			Origin: "nucleoledger.com/poc", Size: size, RootHash: root,
		}, signer)
		if err != nil {
			t.Fatal(err)
		}
		return msg
	}

	if _, err := s.LastCheckpoint(); !errors.Is(err, ErrNotFound) {
		t.Errorf("sin checkpoints: err = %v, want %v", err, ErrNotFound)
	}

	n5, n9 := note(5, 1), note(9, 2)
	if err := s.PutCheckpoint(n5); err != nil {
		t.Fatal(err)
	}
	if err := s.PutCheckpoint(n9); err != nil {
		t.Fatal(err)
	}

	got, err := s.LastCheckpoint()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, n9) {
		t.Error("LastCheckpoint no devolvió el de mayor tamaño")
	}
	if got, err := s.Checkpoint(5); err != nil || !bytes.Equal(got, n5) {
		t.Errorf("Checkpoint(5) = %v", err)
	}
	if _, err := s.Checkpoint(7); !errors.Is(err, ErrNotFound) {
		t.Errorf("Checkpoint(7): err = %v, want %v", err, ErrNotFound)
	}

	// Reemitir el mismo checkpoint es inocuo; cambiarlo, no.
	if err := s.PutCheckpoint(n5); err != nil {
		t.Errorf("reemitir el mismo checkpoint falló: %v", err)
	}
	if err := s.PutCheckpoint(note(5, 42)); !errors.Is(err, ErrAppendOnly) {
		t.Errorf("dos raíces para el tamaño 5: err = %v, want %v", err, ErrAppendOnly)
	}
	// Una nota que no es un checkpoint se rechaza antes de tocar la base.
	if err := s.PutCheckpoint([]byte("esto no es una nota")); err == nil {
		t.Error("aceptó algo que no es una nota firmada")
	}
}

// TestBlobLifecycle cubre el ciclo del payload cifrado, incluido el borrado.
func TestBlobLifecycle(t *testing.T) {
	s := openTemp(t)
	h := strings.Repeat("ab", 32)
	ct := []byte("texto cifrado")
	nonce := bytes.Repeat([]byte{7}, 24)

	if _, err := s.GetBlob(h); !errors.Is(err, ErrNotFound) {
		t.Errorf("blob ausente: err = %v, want %v", err, ErrNotFound)
	}
	if err := s.PutBlob(h, ct, nonce); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetBlob(h)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Ciphertext, ct) || !bytes.Equal(got.Nonce, nonce) {
		t.Error("el blob no sobrevivió el round-trip")
	}
	if got.CreatedAt == "" {
		t.Error("created_at vacío")
	}

	// Sustituir el contenido bajo el mismo compromiso no se permite.
	if err := s.PutBlob(h, []byte("otro texto"), nonce); err == nil {
		t.Error("permitió sustituir el contenido de un blob")
	}

	// Entradas inválidas.
	if err := s.PutBlob("corto", ct, nonce); err == nil {
		t.Error("aceptó un payload_hash inválido")
	}
	if err := s.PutBlob(strings.Repeat("cd", 32), nil, nonce); err == nil {
		t.Error("aceptó un blob sin texto cifrado")
	}

	// Borrado: permitido, e idempotente.
	if err := s.DeleteBlob(h); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetBlob(h); !errors.Is(err, ErrNotFound) {
		t.Errorf("tras borrar: err = %v, want %v", err, ErrNotFound)
	}
	if err := s.DeleteBlob(h); err != nil {
		t.Errorf("borrar dos veces debería ser inocuo: %v", err)
	}
}

// TestMetaRoundTrip cubre vault_meta, la única tabla que sí admite actualización.
func TestMetaRoundTrip(t *testing.T) {
	s := openTemp(t)
	if _, err := s.GetMeta("salt"); !errors.Is(err, ErrNotFound) {
		t.Errorf("clave ausente: err = %v, want %v", err, ErrNotFound)
	}
	if err := s.PutMeta("salt", []byte{1, 2, 3}); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetMeta("salt")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, []byte{1, 2, 3}) {
		t.Errorf("GetMeta = %v", got)
	}
	// vault_meta sí se actualiza: guarda parámetros, no historia.
	if err := s.PutMeta("salt", []byte{9}); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.GetMeta("salt"); !bytes.Equal(got, []byte{9}) {
		t.Errorf("la actualización no se aplicó: %v", got)
	}
}

// TestClosedStore comprueba que usar un Store cerrado no entre en pánico.
func TestClosedStore(t *testing.T) {
	s, _, err := Open(t.TempDir() + "/nucleo.db")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Errorf("cerrar dos veces debería ser inocuo: %v", err)
	}

	if _, err := s.LastBlock(); !errors.Is(err, ErrClosed) {
		t.Errorf("LastBlock: err = %v, want %v", err, ErrClosed)
	}
	if _, err := s.Count(); !errors.Is(err, ErrClosed) {
		t.Errorf("Count: err = %v, want %v", err, ErrClosed)
	}
	if err := s.AppendBlock(chain(t, 1, 0)[0]); !errors.Is(err, ErrClosed) {
		t.Errorf("AppendBlock: err = %v, want %v", err, ErrClosed)
	}
	if _, err := s.GetBlob(strings.Repeat("ab", 32)); !errors.Is(err, ErrClosed) {
		t.Errorf("GetBlob: err = %v, want %v", err, ErrClosed)
	}
	if _, err := s.LastCheckpoint(); !errors.Is(err, ErrClosed) {
		t.Errorf("LastCheckpoint: err = %v, want %v", err, ErrClosed)
	}
}

// TestConcurrentAppendsSerialize comprueba que el candado de escritura convierte
// la concurrencia en espera y no en corrupción: solo uno de los escritores puede
// ganar cada índice, y el ledger queda coherente.
func TestConcurrentAppendsSerialize(t *testing.T) {
	s := openTemp(t)
	blocks := chain(t, 1, 0)
	if err := s.AppendBlock(blocks[0]); err != nil {
		t.Fatal(err)
	}

	// Dos bloques distintos que pretenden ocupar el índice 1.
	pub, priv := testKeys(t, 0)
	rivals := make([]*ledger.Block, 2)
	for i := range rivals {
		h, err := ledger.NewHeader(blocks[0], testTenant, "sri.factura.v1",
			[]byte(fmt.Sprintf("rival-%d", i)), "blob://x", pub, testBase.Add(time.Minute))
		if err != nil {
			t.Fatal(err)
		}
		b, err := ledger.Seal(h, priv)
		if err != nil {
			t.Fatal(err)
		}
		rivals[i] = b
	}

	errs := make(chan error, 2)
	for _, b := range rivals {
		go func(b *ledger.Block) { errs <- s.AppendBlock(b) }(b)
	}
	ok := 0
	for i := 0; i < 2; i++ {
		if err := <-errs; err == nil {
			ok++
		}
	}
	if ok != 1 {
		t.Errorf("escrituras aceptadas = %d, want exactamente 1", ok)
	}
	n, err := s.Count()
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Errorf("bloques persistidos = %d, want 2", n)
	}
}

// TestLastSignedRoundTrip cubre el estado duradero del cerrojo del log.
//
// A diferencia de blocks y checkpoints, log_state es MUTABLE por diseño: guarda
// el último checkpoint firmado y ese valor avanza. Por eso no lleva
// disparadores de append-only, y por eso conviene un test que lo diga.
func TestLastSignedRoundTrip(t *testing.T) {
	s := openTemp(t)

	raw, err := s.LastSigned()
	if err != nil || raw != nil {
		t.Fatalf("base nueva: LastSigned = %v, %v, want nil, nil", raw, err)
	}

	_, priv := testKeys(t, 7)
	signer, err := checkpoint.NewSigner("nucleoledger.com/poc", priv)
	if err != nil {
		t.Fatal(err)
	}
	sign := func(size uint64) []byte {
		root := make([]byte, 32)
		root[0] = byte(size)
		msg, err := checkpoint.Sign(checkpoint.Checkpoint{
			Origin: "nucleoledger.com/poc", Size: size, RootHash: root,
		}, signer)
		if err != nil {
			t.Fatal(err)
		}
		return msg
	}

	first := sign(5)
	if err := s.PutLastSigned(first); err != nil {
		t.Fatal(err)
	}
	got, err := s.LastSigned()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, first) {
		t.Error("no se recuperaron los bytes exactos que se guardaron")
	}

	// Avanza: sobrescribe, y eso es correcto aquí.
	second := sign(9)
	if err := s.PutLastSigned(second); err != nil {
		t.Fatalf("el cerrojo no pudo avanzar: %v", err)
	}
	got, err = s.LastSigned()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, second) {
		t.Error("el cerrojo no avanzó al segundo checkpoint")
	}

	// Lo que no se admite es guardar algo que no sea una nota de checkpoint.
	if err := s.PutLastSigned([]byte("esto no es una nota")); err == nil {
		t.Error("se guardó una nota ilegible como último checkpoint firmado")
	}

	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.LastSigned(); !errors.Is(err, ErrClosed) {
		t.Errorf("base cerrada: err = %v, want %v", err, ErrClosed)
	}
	if err := s.PutLastSigned(first); !errors.Is(err, ErrClosed) {
		t.Errorf("base cerrada: err = %v, want %v", err, ErrClosed)
	}
}
