package integration

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/nucleoledger/nucleo/internal/checkpoint"
	"github.com/nucleoledger/nucleo/internal/ledger"
	"github.com/nucleoledger/nucleo/internal/proof"
	"github.com/nucleoledger/nucleo/internal/store"
	"github.com/nucleoledger/nucleo/internal/vault"
	"github.com/nucleoledger/nucleo/internal/witness"
)

const (
	origin      = "nucleoledger.com/test"
	witnessName = "witness.test/w1"
	tenant      = "1790012345001"
	vaultID     = "vault-test-1"
	passphrase  = "passphrase de integración"
	receiptIdx  = 2
)

func seed(b byte) []byte {
	s := make([]byte, ed25519.SeedSize)
	for i := range s {
		s[i] = b + byte(i)
	}
	return s
}

// clock determinista para que las cosignatures tengan tiempos controlados.
type clock struct{ t time.Time }

func (c *clock) now() time.Time          { return c.t }
func (c *clock) advance(d time.Duration) { c.t = c.t.Add(d) }

// sealAll cifra cada payload, lo guarda y sella su bloque.
func sealAll(t *testing.T, s *store.Store, v *vault.Vault,
	pub ed25519.PublicKey, priv ed25519.PrivateKey, payloads [][]byte, base time.Time) {
	t.Helper()
	for i, p := range payloads {
		last, err := s.LastBlock()
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			t.Fatal(err)
		}
		h, err := ledger.NewHeader(last, tenant, "sri.factura.v1", p, "blob://x", pub,
			base.Add(time.Duration(i)*time.Minute))
		if err != nil {
			t.Fatal(err)
		}
		ct, nonce, err := v.EncryptBlob(tenant, h.PayloadHash, p)
		if err != nil {
			t.Fatal(err)
		}
		if err := s.PutBlob(h.PayloadHash, ct, nonce); err != nil {
			t.Fatal(err)
		}
		b, err := ledger.Seal(h, priv)
		if err != nil {
			t.Fatal(err)
		}
		if err := s.AppendBlock(b); err != nil {
			t.Fatal(err)
		}
	}
}

// TestDurableCycleAcrossRestart es la demostración del sprint, comprobada en vez
// de narrada: el ledger se cierra, se reabre en frío y sigue siendo
// demostrablemente la misma historia para un testigo que ya la había avalado.
func TestDurableCycleAcrossRestart(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "nucleo.db")

	tenantPriv := ed25519.NewKeyFromSeed(seed(0))
	tenantPub := tenantPriv.Public().(ed25519.PublicKey)
	logPriv := ed25519.NewKeyFromSeed(seed(50))
	logPub := logPriv.Public().(ed25519.PublicKey)
	witnessPriv := ed25519.NewKeyFromSeed(seed(100))
	witnessPub := witnessPriv.Public().(ed25519.PublicKey)

	base := time.Date(2026, 9, 5, 9, 0, 0, 0, time.UTC)
	clk := &clock{t: base}

	// El testigo es una parte separada: NO se reinicia con el ledger.
	wit, err := witness.New(witnessName, witnessPriv, clk.now)
	if err != nil {
		t.Fatal(err)
	}
	if err := wit.AddLog(origin, logPub); err != nil {
		t.Fatal(err)
	}
	logSigner, err := checkpoint.NewSigner(origin, logPriv)
	if err != nil {
		t.Fatal(err)
	}

	// ---- Sesión 1 ----------------------------------------------------------
	s, _, err := store.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	v, err := vault.Create(s, vaultID, []byte(passphrase))
	if err != nil {
		t.Fatal(err)
	}
	payloads := [][]byte{
		[]byte(`{"tipo":"apertura"}`),
		[]byte(`<autorizacion>factura 1</autorizacion>`),
		[]byte(`{"cliente":"María Pérez","cedula":"1712345678"}`),
		[]byte(`<autorizacion>factura 2</autorizacion>`),
		[]byte(`{"acta":"junta"}`),
	}
	sealAll(t, s, v, tenantPub, tenantPriv, payloads, base)

	rootA, err := s.Root()
	if err != nil {
		t.Fatal(err)
	}
	noteA, err := checkpoint.Sign(checkpoint.Checkpoint{Origin: origin, Size: 5, RootHash: rootA}, logSigner)
	if err != nil {
		t.Fatal(err)
	}
	cosignedA, err := wit.Cosign(noteA, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.PutCheckpoint(cosignedA); err != nil {
		t.Fatal(err)
	}

	leavesA, err := s.LeafData()
	if err != nil {
		t.Fatal(err)
	}
	path, err := ledger.InclusionProof(leavesA, receiptIdx)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := proof.Format(proof.Receipt{
		Index: receiptIdx, InclusionProof: path, CheckpointNote: cosignedA,
	})
	if err != nil {
		t.Fatal(err)
	}
	entryHash := leavesA[receiptIdx]
	sensitiveBlocks, err := s.Blocks(receiptIdx, receiptIdx+1)
	if err != nil {
		t.Fatal(err)
	}
	sensitiveHash := sensitiveBlocks[0].Header.PayloadHash

	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	// ---- Sesión 2: reapertura en frío --------------------------------------
	s2, openState, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("la base no superó la verificación al reabrir: %v", err)
	}
	defer s2.Close()
	if !openState.Attested || openState.AttestedSize != 5 || openState.TreeSize != 5 {
		t.Fatalf("estado al reabrir = %+v, want atestiguada hasta 5 de 5", openState)
	}

	all, err := s2.AllBlocks()
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 5 {
		t.Fatalf("tras reabrir hay %d bloques, want 5", len(all))
	}
	if err := ledger.VerifyChain(all, tenantPub); err != nil {
		t.Fatalf("la cadena reabierta no verifica contra la clave del tenant: %v", err)
	}
	if root, err := s2.Root(); err != nil || !bytes.Equal(root, rootA) {
		t.Fatalf("la raíz cambió al reabrir: %x vs %x (%v)", root, rootA, err)
	}

	// El vault se reabre y descifra lo que cifró la sesión anterior.
	v2, err := vault.Unlock(s2, []byte(passphrase))
	if err != nil {
		t.Fatalf("Unlock tras reiniciar: %v", err)
	}
	blob, err := s2.GetBlob(sensitiveHash)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := v2.DecryptBlob(tenant, sensitiveHash, blob.Ciphertext, blob.Nonce)
	if err != nil {
		t.Fatalf("no descifra tras reiniciar: %v", err)
	}
	if !bytes.Equal(plain, payloads[receiptIdx]) {
		t.Errorf("payload descifrado = %q", plain)
	}

	// Tres bloques más sobre la cadena reabierta.
	sealAll(t, s2, v2, tenantPub, tenantPriv, [][]byte{
		[]byte(`{"tipo":"nota-credito"}`),
		[]byte(`<autorizacion>factura 3</autorizacion>`),
		[]byte(`{"tipo":"cierre"}`),
	}, base.Add(time.Hour))

	if n, err := s2.Count(); err != nil || n != 8 {
		t.Fatalf("Count = %d (%v), want 8", n, err)
	}

	rootB, err := s2.Root()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(rootB, rootA) {
		t.Fatal("la raíz no cambió tras añadir bloques")
	}
	noteB, err := checkpoint.Sign(checkpoint.Checkpoint{Origin: origin, Size: 8, RootHash: rootB}, logSigner)
	if err != nil {
		t.Fatal(err)
	}

	// LA COMPROBACIÓN DEL SPRINT: el testigo, que cosignó antes del reinicio y
	// no se reinició, acepta la extensión calculada sobre la cadena reabierta.
	leavesB, err := s2.LeafData()
	if err != nil {
		t.Fatal(err)
	}
	consistency, err := ledger.ConsistencyProof(leavesB, 5)
	if err != nil {
		t.Fatal(err)
	}
	clk.advance(30 * time.Minute)
	cosignedB, err := wit.Cosign(noteB, consistency)
	if err != nil {
		t.Fatalf("el testigo rechazó la extensión tras el reinicio: %v", err)
	}
	if err := s2.PutCheckpoint(cosignedB); err != nil {
		t.Fatal(err)
	}
	if last, ok := wit.Last(origin); !ok || last.Size != 8 {
		t.Errorf("el testigo no registró el checkpoint B: %+v", last)
	}

	// Control negativo: una historia reescrita NO habría pasado. Se construye
	// una cadena alterna del mismo tamaño y se comprueba que el testigo la
	// rechaza; sin esto, lo anterior podría pasar por un testigo permisivo.
	rewritten := make([][]byte, len(leavesB))
	copy(rewritten, leavesB)
	rewritten[1] = ledger.LeafHash([]byte("factura suplantada"))
	evilNote, err := checkpoint.Sign(checkpoint.Checkpoint{
		Origin: origin, Size: 8, RootHash: ledger.Root(rewritten),
	}, logSigner)
	if err != nil {
		t.Fatal(err)
	}
	evilProof, err := ledger.ConsistencyProof(rewritten, 5)
	if err != nil {
		t.Fatal(err)
	}
	clk.advance(time.Minute)
	// El testigo ya cosignó un árbol de 8 con OTRA raíz, así que este no es un
	// conflicto de extensión sino un checkpoint imposible de procesar: mismo
	// tamaño, raíz distinta. c2sp.org/tlog-witness lo clasifica como 422.
	if _, err := wit.Cosign(evilNote, evilProof); !errors.Is(err, witness.ErrUnprocessable) {
		t.Fatalf("el testigo aceptó una historia reescrita: %v", err)
	}

	// ---- Derecho de supresión ----------------------------------------------
	if err := vault.EraseBlob(s2, sensitiveHash); err != nil {
		t.Fatal(err)
	}
	if _, err := s2.GetBlob(sensitiveHash); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("el blob sigue accesible tras borrarlo: %v", err)
	}

	// El recibo emitido antes del borrado sigue verificando, offline.
	parsed, err := proof.Parse(receipt)
	if err != nil {
		t.Fatal(err)
	}
	res, err := parsed.Verify(entryHash, proof.Policy{
		Origin:    origin,
		LogKey:    logPub,
		Witnesses: map[string]ed25519.PublicKey{witnessName: witnessPub},
		Quorum:    1,
	})
	if err != nil {
		t.Fatalf("el recibo dejó de verificar tras el borrado: %v", err)
	}
	if res.Checkpoint.Size != 5 {
		t.Errorf("tamaño avalado = %d, want 5", res.Checkpoint.Size)
	}
	if len(res.Cosigners) != 1 || res.Cosigners[0] != witnessName {
		t.Errorf("cosignantes = %v", res.Cosigners)
	}
	if !res.ProvableTime.Equal(base) {
		t.Errorf("tiempo demostrable = %v, want %v", res.ProvableTime, base)
	}

	// Y la cadena completa sigue verificando con el dato ya borrado.
	final, err := s2.AllBlocks()
	if err != nil {
		t.Fatal(err)
	}
	if err := ledger.VerifyChain(final, tenantPub); err != nil {
		t.Errorf("la cadena dejó de verificar tras el borrado: %v", err)
	}
}

// TestReopenDetectsTamperingBetweenSessions comprueba que la manipulación del
// fichero ENTRE sesiones no pase desapercibida al reabrir.
func TestReopenDetectsTamperingBetweenSessions(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "nucleo.db")
	tenantPriv := ed25519.NewKeyFromSeed(seed(0))
	tenantPub := tenantPriv.Public().(ed25519.PublicKey)

	s, _, err := store.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	v, err := vault.Create(s, vaultID, []byte(passphrase))
	if err != nil {
		t.Fatal(err)
	}
	sealAll(t, s, v, tenantPub, tenantPriv, [][]byte{
		[]byte("uno"), []byte("dos"), []byte("tres"),
	}, time.Date(2026, 9, 5, 9, 0, 0, 0, time.UTC))
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	// Entre sesiones, alguien con acceso al fichero borra los disparadores y
	// altera un bloque.
	raw, err := openRaw(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, trg := range []string{"blocks_no_update", "blocks_no_delete"} {
		if _, err := raw.Exec("DROP TRIGGER IF EXISTS " + trg); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := raw.Exec(`UPDATE blocks SET signature = ? WHERE idx = 1`, "00"); err != nil {
		t.Fatal(err)
	}
	if err := raw.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, _, err := store.Open(dbPath)
	if err == nil {
		reopened.Close()
		t.Fatal("Open aceptó una base manipulada entre sesiones")
	}
	if !errors.Is(err, store.ErrIntegrity) {
		t.Errorf("err = %v, want que envuelva a store.ErrIntegrity", err)
	}
}
