// nucleo-poc2: prueba de concepto con persistencia real en disco.
//
//	go run ./cmd/nucleo-poc2
//
// Demuestra la continuidad tras un reinicio, que es lo que separa un demo de un
// producto: se crea un vault, se sellan 5 bloques con payloads cifrados, se
// emite un checkpoint cosignado, se CIERRA la base, se REABRE, se verifica su
// integridad, se sellan 3 bloques más y el mismo testigo acepta la prueba de
// consistencia entre los dos checkpoints A TRAVÉS del reinicio. Después se borra
// un payload —derecho de supresión— y el recibo de ese bloque sigue verificando.
package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/nucleoledger/nucleo/internal/checkpoint"
	"github.com/nucleoledger/nucleo/internal/keys"
	"github.com/nucleoledger/nucleo/internal/ledger"
	"github.com/nucleoledger/nucleo/internal/proof"
	"github.com/nucleoledger/nucleo/internal/store"
	"github.com/nucleoledger/nucleo/internal/vault"
	"github.com/nucleoledger/nucleo/internal/witness"
)

const (
	origin      = "nucleoledger.com/poc"
	witnessName = "witness.nucleoledger.com/w1"
	tenant      = "1790012345001"
	vaultID     = "vault-poc-1"
	passphrase  = "correcta caballo bateria grapa"
	receiptIdx  = 2

	tenantSeedHex  = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	logSeedHex     = "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
	witnessSeedHex = "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "ERROR:", err)
		os.Exit(1)
	}
}

func run() error {
	dir, err := os.MkdirTemp("", "nucleo-poc2-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	dbPath := filepath.Join(dir, "nucleo.db")

	tenantPriv, err := keys.PrivateKeyFromSeedHex(tenantSeedHex)
	if err != nil {
		return err
	}
	tenantPub := tenantPriv.Public().(ed25519.PublicKey)
	logPriv, err := keys.PrivateKeyFromSeedHex(logSeedHex)
	if err != nil {
		return err
	}
	logPub := logPriv.Public().(ed25519.PublicKey)
	witnessPriv, err := keys.PrivateKeyFromSeedHex(witnessSeedHex)
	if err != nil {
		return err
	}

	fmt.Println("== Identidades ==")
	fmt.Println("base de datos :", dbPath)
	fmt.Println("tenant        :", keys.PublicKeyHex(tenantPub))
	fmt.Println("log           :", origin)
	fmt.Println("testigo       :", witnessName)

	// El testigo es una parte SEPARADA: no se reinicia con el ledger. Eso es lo
	// que hace significativa la comprobación de más abajo.
	now := time.Date(2026, 9, 5, 9, 0, 0, 0, time.UTC)
	clock := &stepClock{t: now}
	wit, err := witness.New(witnessName, witnessPriv, clock.now)
	if err != nil {
		return err
	}
	if err := wit.AddLog(origin, logPub); err != nil {
		return err
	}

	logSigner, err := checkpoint.NewSigner(origin, logPriv)
	if err != nil {
		return err
	}

	// ---- SESIÓN 1 ---------------------------------------------------------
	fmt.Println("\n== Sesión 1: crear vault y sellar 5 bloques ==")
	s, openState0, err := store.Open(dbPath)
	if err != nil {
		return err
	}
	printAttestation(openState0)
	v, err := vault.Create(s, vaultID, []byte(passphrase))
	if err != nil {
		return err
	}
	fmt.Println("✔ vault creado (Argon2id t=3 m=64MiB p=4; DEK envuelta en vault_meta)")

	payloads := [][]byte{
		[]byte(`{"tipo":"apertura","periodo":"2026-09"}`),
		[]byte(`<autorizacion><numeroAutorizacion>2908202601179001234500110010010000000011234567811</numeroAutorizacion></autorizacion>`),
		[]byte(`{"cliente":"María Pérez","cedula":"1712345678","importe":"1250.00"}`),
		[]byte(`<autorizacion><numeroAutorizacion>2908202601179001234500110010010000000021234567822</numeroAutorizacion></autorizacion>`),
		[]byte(`{"acta":"junta-2026-09","acuerdos":3}`),
	}
	if err := sealAll(s, v, tenantPub, tenantPriv, payloads, now); err != nil {
		return err
	}
	fmt.Printf("✔ %d bloques sellados; sus payloads viven cifrados fuera del ledger\n", len(payloads))

	rootA, err := s.Root()
	if err != nil {
		return err
	}
	noteA, err := checkpoint.Sign(checkpoint.Checkpoint{
		Origin: origin, Size: 5, RootHash: rootA,
	}, logSigner)
	if err != nil {
		return err
	}
	cosignedA, err := wit.Cosign(noteA, nil)
	if err != nil {
		return err
	}
	if err := s.PutCheckpoint(cosignedA); err != nil {
		return err
	}
	fmt.Println("✔ checkpoint A (tamaño 5) firmado y cosignado por el testigo")
	fmt.Println("  raíz A:", hex.EncodeToString(rootA))

	// Recibo del bloque 2, emitido en la sesión 1.
	leaves, err := s.LeafHashes()
	if err != nil {
		return err
	}
	path, err := ledger.InclusionProof(leaves, receiptIdx)
	if err != nil {
		return err
	}
	receipt, err := proof.Format(proof.Receipt{
		Index: receiptIdx, InclusionProof: path, CheckpointNote: cosignedA,
	})
	if err != nil {
		return err
	}
	entryHash := leaves[receiptIdx]
	sensitive, err := s.Blocks(receiptIdx, receiptIdx+1)
	if err != nil {
		return err
	}
	sensitiveHash := sensitive[0].Header.PayloadHash
	fmt.Printf("✔ recibo del bloque %d emitido (%d bytes)\n", receiptIdx, len(receipt))

	if err := s.Close(); err != nil {
		return err
	}
	fmt.Println("✔ base CERRADA — aquí terminaría el proceso")

	// ---- SESIÓN 2 ---------------------------------------------------------
	fmt.Println("\n== Sesión 2: reabrir en frío ==")
	s2, openState, err := store.Open(dbPath)
	if err != nil {
		return fmt.Errorf("la base no superó la verificación al reabrir: %w", err)
	}
	defer s2.Close()
	fmt.Println("✔ Open verificó la integridad: encadenamiento, firmas y raíz")
	fmt.Println("  reconstruida contra el checkpoint guardado")
	printAttestation(openState)

	all, err := s2.AllBlocks()
	if err != nil {
		return err
	}
	if err := ledger.VerifyChain(all, tenantPub); err != nil {
		return fmt.Errorf("la cadena reabierta no verifica: %w", err)
	}
	fmt.Printf("✔ %d bloques verificados contra la clave esperada del tenant\n", len(all))

	v2, err := vault.Unlock(s2, []byte(passphrase))
	if err != nil {
		return err
	}
	blob, err := s2.GetBlob(sensitiveHash)
	if err != nil {
		return err
	}
	plain, err := v2.DecryptBlob(tenant, sensitiveHash, blob.Ciphertext, blob.Nonce)
	if err != nil {
		return err
	}
	fmt.Printf("✔ vault reabierto con la passphrase; payload del bloque %d descifrado:\n    %s\n",
		receiptIdx, plain)

	// Tres bloques más sobre la cadena reabierta.
	more := [][]byte{
		[]byte(`{"tipo":"nota-credito","importe":"120.00"}`),
		[]byte(`<autorizacion><numeroAutorizacion>2908202601179001234500110010010000000031234567833</numeroAutorizacion></autorizacion>`),
		[]byte(`{"tipo":"cierre","periodo":"2026-09","bloques":7}`),
	}
	if err := sealAll(s2, v2, tenantPub, tenantPriv, more, now.Add(time.Hour)); err != nil {
		return err
	}
	fmt.Printf("✔ %d bloques más sellados sobre la cadena reabierta (total %d)\n", len(more), len(all)+len(more))

	rootB, err := s2.Root()
	if err != nil {
		return err
	}
	noteB, err := checkpoint.Sign(checkpoint.Checkpoint{
		Origin: origin, Size: 8, RootHash: rootB,
	}, logSigner)
	if err != nil {
		return err
	}
	fmt.Println("  raíz B:", hex.EncodeToString(rootB))

	// ---- LA DEMOSTRACIÓN --------------------------------------------------
	leavesB, err := s2.LeafHashes()
	if err != nil {
		return err
	}
	consistency, err := ledger.ConsistencyProof(leavesB, 5)
	if err != nil {
		return err
	}
	clock.advance(30 * time.Minute)
	cosignedB, err := wit.Cosign(noteB, consistency)
	if err != nil {
		return fmt.Errorf("el testigo rechazó la extensión tras el reinicio: %w", err)
	}
	if err := s2.PutCheckpoint(cosignedB); err != nil {
		return err
	}

	fmt.Println("\n>>> CONTINUIDAD TRAS EL REINICIO <<<")
	fmt.Println("El testigo cosignó el checkpoint A ANTES de cerrar la base y no se")
	fmt.Println("reinició con ella: es una parte separada, con su propia memoria.")
	fmt.Printf("Aceptó el checkpoint B (tamaño 8) con una prueba de consistencia de %d\n", len(consistency))
	fmt.Println("nodos calculada sobre la cadena REABIERTA desde disco. Es decir:")
	fmt.Println("la base que se reabrió es demostrablemente la misma historia que el")
	fmt.Println("testigo ya había avalado, extendida, no reescrita.")
	fmt.Println("✔ checkpoint B cosignado y persistido")

	// ---- BORRADO LOPDP ----------------------------------------------------
	fmt.Println("\n== Derecho de supresión ==")
	fmt.Printf("payload del bloque %d (contiene cédula y nombre): %s\n", receiptIdx, sensitiveHash[:16]+"...")
	if err := vault.EraseBlob(s2, sensitiveHash); err != nil {
		return err
	}
	if _, err := s2.GetBlob(sensitiveHash); err == nil {
		return fmt.Errorf("el blob sigue en la base tras borrarlo")
	}
	fmt.Println("✔ payload borrado: el dato personal ya no está en el disco")

	// ---- EL RECIBO SIGUE VALIENDO -----------------------------------------
	policy := proof.Policy{
		Origin:    origin,
		LogKey:    logPub,
		Witnesses: map[string]ed25519.PublicKey{witnessName: witnessPriv.Public().(ed25519.PublicKey)},
		Quorum:    1,
	}
	parsed, err := proof.Parse(receipt)
	if err != nil {
		return err
	}
	res, err := parsed.Verify(entryHash, policy)
	if err != nil {
		return fmt.Errorf("el recibo dejó de verificar tras el borrado: %w", err)
	}
	fmt.Println("✔ el recibo del bloque borrado SIGUE VERIFICANDO, offline")
	fmt.Printf("  tamaño del árbol avalado: %d · testigos: %v\n", res.Checkpoint.Size, res.Cosigners)
	fmt.Println("  tiempo demostrable      :", res.ProvableTime.Format(time.RFC3339))
	fmt.Println("\nEl dato desapareció; la prueba de que existió y de cuándo se selló,")
	fmt.Println("no. Eso es la LOPDP satisfecha por construcción, no por promesa.")
	return nil
}

// sealAll cifra cada payload, lo guarda como blob y sella su bloque.
func sealAll(s *store.Store, v *vault.Vault, pub ed25519.PublicKey, priv ed25519.PrivateKey,
	payloads [][]byte, base time.Time) error {
	for i, p := range payloads {
		last, err := s.LastBlock()
		if err != nil && err != store.ErrNotFound {
			return err
		}
		h, err := ledger.NewHeader(last, tenant, "sri.factura.v1", p,
			"blob://"+shortHash(p), pub, base.Add(time.Duration(i)*time.Minute))
		if err != nil {
			return err
		}
		ct, nonce, err := v.EncryptBlob(tenant, h.PayloadHash, p)
		if err != nil {
			return err
		}
		if err := s.PutBlob(h.PayloadHash, ct, nonce); err != nil {
			return err
		}
		b, err := ledger.Seal(h, priv)
		if err != nil {
			return err
		}
		if err := s.AppendBlock(b); err != nil {
			return err
		}
	}
	return nil
}

func shortHash(p []byte) string {
	h := ledger.LeafHash(p)
	return hex.EncodeToString(h[:4])
}

// stepClock es un reloj determinista que el PoC hace avanzar a mano.
type stepClock struct{ t time.Time }

func (c *stepClock) now() time.Time          { return c.t }
func (c *stepClock) advance(d time.Duration) { c.t = c.t.Add(d) }

// printAttestation dice en voz alta qué respalda la historia recién abierta.
//
// La distinción importa: una base puede abrir sin un solo error y ser un
// PREFIJO de la historia real. Quien controle el fichero puede borrar los
// disparadores, vaciar la tabla de checkpoints y truncar los bloques a un
// prefijo que encadena y verifica perfectamente; nada dentro del fichero lo
// desmiente, porque el fichero entero es suyo. Lo que lo desmiente es la
// memoria del testigo que ya cosignó una raíz mayor.
func printAttestation(r store.OpenResult) {
	switch {
	case r.TreeSize == 0:
		fmt.Println("· ESTADO: base nueva, todavía sin historia que atestiguar")
		return
	case r.Attested:
		fmt.Printf("✔ ESTADO: historia atestiguada hasta %d de %d bloques\n", r.AttestedSize, r.TreeSize)
		return
	}
	fmt.Printf("⚠ ESTADO: SIN ATESTIGUAR (%d bloques) — la cadena es localmente válida,\n", r.TreeSize)
	fmt.Println("  pero que esté COMPLETA no está garantizado: sin un checkpoint cosignado,")
	fmt.Println("  un prefijo truncado es indistinguible de la historia entera.")
}
