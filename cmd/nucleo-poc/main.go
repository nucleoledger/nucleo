// nucleo-poc: prueba de concepto C2SP end-to-end.
//
//	go run ./cmd/nucleo-poc
//
// Sella una cadena de 5 bloques, emite un checkpoint firmado en formato
// c2sp.org/tlog-checkpoint, lo hace cosignar por un testigo local con una
// cosignature v1, produce el recibo del bloque 2 al estilo c2sp.org/tlog-proof y
// lo verifica SIN acceso al ledger. Después simula la reescritura total de la
// cadena y muestra las dos defensas: el testigo se niega a cosignar, y el recibo
// antiguo delata que la raíz cambió.
//
// Claves y relojes son deterministas a propósito: así la salida y el tamaño del
// recibo son reproducibles entre ejecuciones.
package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/nucleoledger/nucleo/internal/checkpoint"
	"github.com/nucleoledger/nucleo/internal/keys"
	"github.com/nucleoledger/nucleo/internal/ledger"
	"github.com/nucleoledger/nucleo/internal/proof"
	"github.com/nucleoledger/nucleo/internal/witness"
)

const (
	origin      = "nucleoledger.com/poc"
	witnessName = "witness.nucleoledger.com/w1"
	tenant      = "1790012345001" // RUC de ejemplo

	tenantSeedHex  = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	logSeedHex     = "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
	witnessSeedHex = "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f"

	receiptIndex = 2
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "ERROR:", err)
		os.Exit(1)
	}
}

func run() error {
	t0 := time.Date(2026, 9, 4, 15, 0, 0, 0, time.UTC)
	cosignedAt := t0.Add(10 * time.Minute)

	// ---- Identidades -------------------------------------------------------
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
	witnessPub := witnessPriv.Public().(ed25519.PublicKey)

	fmt.Println("== Identidades ==")
	fmt.Println("tenant  :", keys.PublicKeyHex(tenantPub))
	fmt.Println("log     :", origin, "→", keys.PublicKeyHex(logPub))
	fmt.Println("testigo :", witnessName, "→", keys.PublicKeyHex(witnessPub))

	// ---- 1. Cadena de 5 bloques -------------------------------------------
	chain, err := buildChain(tenantPub, tenantPriv, t0, nil)
	if err != nil {
		return err
	}
	if err := ledger.VerifyChain(chain, tenantPub); err != nil {
		return fmt.Errorf("la cadena legítima no verifica: %w", err)
	}
	leaves, err := leavesOf(chain)
	if err != nil {
		return err
	}
	root := ledger.Root(leaves)
	fmt.Printf("\n== 1. Cadena ==\n")
	fmt.Printf("✔ %d bloques sellados y verificados (hash, firma, prev_hash, orden temporal)\n", len(chain))
	fmt.Println("✔ raíz de Merkle:", hex.EncodeToString(root))

	// ---- 2. Checkpoint firmado --------------------------------------------
	logSigner, err := checkpoint.NewSigner(origin, logPriv)
	if err != nil {
		return err
	}
	log, err := checkpoint.NewLog(origin, logSigner)
	if err != nil {
		return err
	}
	ckNote, err := log.Sign(checkpoint.Checkpoint{
		Origin: origin, Size: uint64(len(leaves)), RootHash: root,
	})
	if err != nil {
		return err
	}
	fmt.Printf("\n== 2. Checkpoint (c2sp.org/tlog-checkpoint) ==\n%s", ckNote)

	// ---- 3. El testigo cosigna --------------------------------------------
	wit, err := witness.New(witnessName, witnessPriv, func() time.Time { return cosignedAt })
	if err != nil {
		return err
	}
	if err := wit.AddLog(origin, logPub); err != nil {
		return err
	}
	cosigned, err := wit.Cosign(ckNote, nil)
	if err != nil {
		return fmt.Errorf("el testigo rechazó un checkpoint legítimo: %w", err)
	}
	fmt.Printf("\n== 3. Cosignature v1 del testigo ==\n%s", cosigned)

	// ---- 4. Recibo del bloque 2 -------------------------------------------
	path, err := ledger.InclusionProof(leaves, receiptIndex)
	if err != nil {
		return err
	}
	receipt := proof.Receipt{
		Index:          receiptIndex,
		InclusionProof: path,
		CheckpointNote: cosigned,
	}
	encoded, err := proof.Format(receipt)
	if err != nil {
		return err
	}
	fmt.Printf("\n== 4. Recibo del bloque %d (c2sp.org/tlog-proof) ==\n%s", receiptIndex, encoded)
	fmt.Printf("\n>>> TAMAÑO DEL RECIBO: %d bytes (%d nodos en el camino de inclusión)\n",
		len(encoded), len(path))

	// ---- 5. Verificación offline ------------------------------------------
	// Solo se usan: los bytes del recibo, el hash de la entrada y la política.
	// Ni la cadena, ni el árbol, ni contacto con el emisor.
	policy := proof.Policy{
		Origin:    origin,
		LogKey:    logPub,
		Witnesses: map[string]ed25519.PublicKey{witnessName: witnessPub},
		Quorum:    1,
	}
	parsed, err := proof.Parse(encoded)
	if err != nil {
		return err
	}
	entryHash := leaves[receiptIndex]
	res, err := parsed.Verify(entryHash, policy)
	if err != nil {
		return fmt.Errorf("el recibo legítimo no verifica: %w", err)
	}
	declared, err := chain[receiptIndex].Header.Time()
	if err != nil {
		return err
	}
	fmt.Printf("\n== 5. Verificación offline (sin acceso al ledger) ==\n")
	fmt.Println("✔ recibo válido para la entrada", hex.EncodeToString(entryHash))
	fmt.Printf("✔ checkpoint: %s, tamaño %d, raíz %s\n",
		res.Checkpoint.Origin, res.Checkpoint.Size, hex.EncodeToString(res.Checkpoint.RootHash))
	fmt.Printf("✔ testigos que cosignaron: %v (quórum exigido: %d)\n", res.Cosigners, policy.Quorum)
	fmt.Println("  tiempo declarado por el tenant :", declared.Format(time.RFC3339))
	fmt.Println("  tiempo demostrable (testigo)   :", res.ProvableTime.Format(time.RFC3339))

	// ---- 6. Ataque: reescritura total de la cadena -------------------------
	fmt.Printf("\n== 6. Ataque: el operador reescribe la cadena entera ==\n")
	altered := []byte(`<?xml version="1.0"?><autorizacion>FACTURA ALTERADA</autorizacion>`)
	evilChain, err := buildChain(tenantPub, tenantPriv, t0, map[int][]byte{1: altered})
	if err != nil {
		return err
	}
	if err := ledger.VerifyChain(evilChain, tenantPub); err != nil {
		return fmt.Errorf("inesperado: la cadena reescrita debería verificar localmente: %w", err)
	}
	evilLeaves, err := leavesOf(evilChain)
	if err != nil {
		return err
	}
	evilRoot := ledger.Root(evilLeaves)
	fmt.Println("⚠ la cadena reescrita verifica localmente: hashes y firmas son coherentes")
	fmt.Println("  (esta es la falacia on-premise: quien tiene la llave puede rehacerlo todo)")
	fmt.Println("  raíz reescrita:", hex.EncodeToString(evilRoot))

	// (a) El testigo se niega.
	evilSigner, err := checkpoint.NewSigner(origin, logPriv)
	if err != nil {
		return err
	}
	evilLog, err := checkpoint.NewLog(origin, evilSigner) // Log nuevo: el operador manipuló su BD
	if err != nil {
		return err
	}
	evilNote, err := evilLog.Sign(checkpoint.Checkpoint{
		Origin: origin, Size: uint64(len(evilLeaves)), RootHash: evilRoot,
	})
	if err != nil {
		return err
	}
	evilProof, err := ledger.ConsistencyProof(evilLeaves, len(leaves))
	if err != nil && !errors.Is(err, ledger.ErrTreeSize) {
		return err
	}
	_, err = wit.Cosign(evilNote, evilProof)
	if err == nil {
		return errors.New("el testigo cosignó una historia reescrita")
	}
	var conflict *witness.ConflictError
	if !errors.As(err, &conflict) {
		return fmt.Errorf("se esperaba un conflicto del testigo, llegó: %w", err)
	}
	fmt.Printf("\n(a) ✔ el testigo RECHAZA cosignar (semántica 409)\n")
	fmt.Println("     motivo:", conflict.Reason)
	fmt.Printf("     último tamaño que este testigo cosignó: %d\n", conflict.LastSize)

	// (b) El recibo antiguo delata la nueva raíz.
	evilReceipt := proof.Receipt{
		Index:          receiptIndex,
		InclusionProof: mustPath(evilLeaves, receiptIndex),
		CheckpointNote: evilNote,
	}
	evilRes, err := evilReceipt.Verify(evilLeaves[receiptIndex], proof.Policy{
		Origin: origin, LogKey: logPub, Quorum: 0,
	})
	if err != nil {
		return fmt.Errorf("inesperado: el recibo del árbol falso debería ser coherente: %w", err)
	}
	fmt.Printf("\n(b) ✔ el recibo antiguo delata la reescritura\n")
	fmt.Println("     raíz firmada en el recibo del tenedor :", hex.EncodeToString(res.Checkpoint.RootHash))
	fmt.Println("     raíz que el log presenta ahora        :", hex.EncodeToString(evilRes.Checkpoint.RootHash))
	fmt.Println("     ¿coinciden?                           :",
		hex.EncodeToString(res.Checkpoint.RootHash) == hex.EncodeToString(evilRes.Checkpoint.RootHash))
	fmt.Println("     el log firmó dos raíces distintas para el mismo tamaño; el tenedor")
	fmt.Println("     del recibo conserva la primera, firmada y cosignada. Es la evidencia.")

	// El recibo original sigue sin verificar contra el checkpoint reescrito.
	stale := parsed
	stale.CheckpointNote = evilNote
	if _, err := stale.Verify(entryHash, proof.Policy{Origin: origin, LogKey: logPub, Quorum: 0}); err == nil {
		return errors.New("el camino antiguo no debería validar contra la raíz nueva")
	} else {
		fmt.Println("\n(c) ✔ el camino de inclusión antiguo tampoco encaja en la raíz nueva:")
		fmt.Println("     ", err)
	}
	return nil
}

// buildChain sella una cadena de 5 bloques. overrides permite sustituir el
// payload de un índice concreto para simular la reescritura.
func buildChain(pub ed25519.PublicKey, priv ed25519.PrivateKey, t0 time.Time, overrides map[int][]byte) ([]*ledger.Block, error) {
	type entry struct {
		typ     string
		payload []byte
		cid     string
	}
	entries := []entry{
		{"ledger.genesis.v1", []byte(`{"tenant":"1790012345001","razon_social":"EJEMPLO S.A.S."}`), "local://manifest"},
		{"sri.factura.v1", []byte(`<?xml version="1.0"?><autorizacion><numeroAutorizacion>2908202601179001234500110010010000000011234567811</numeroAutorizacion></autorizacion>`), "blob://c4f3"},
		{"sri.factura.v1", []byte(`<?xml version="1.0"?><autorizacion><numeroAutorizacion>2908202601179001234500110010010000000021234567822</numeroAutorizacion></autorizacion>`), "blob://a91d"},
		{"sas.acta.v1", []byte(`{"acta":"junta-2026-09","acuerdos":3}`), "blob://9a1b"},
		{"ledger.cierre.v1", []byte(`{"periodo":"2026-09","bloques":4}`), "local://cierre"},
	}

	chain := make([]*ledger.Block, 0, len(entries))
	var prev *ledger.Block
	for i, e := range entries {
		payload := e.payload
		if alt, ok := overrides[i]; ok {
			payload = alt
		}
		h, err := ledger.NewHeader(prev, tenant, e.typ, payload, e.cid, pub, t0.Add(time.Duration(i)*time.Minute))
		if err != nil {
			return nil, err
		}
		b, err := ledger.Seal(h, priv)
		if err != nil {
			return nil, err
		}
		chain = append(chain, b)
		prev = b
	}
	return chain, nil
}

// leavesOf extrae los hashes de bloque, que son las hojas del árbol (PROTOCOL.md §2).
func leavesOf(chain []*ledger.Block) ([][]byte, error) {
	leaves := make([][]byte, 0, len(chain))
	for _, b := range chain {
		hb, err := b.HashBytes()
		if err != nil {
			return nil, err
		}
		leaves = append(leaves, hb)
	}
	return leaves, nil
}

func mustPath(leaves [][]byte, index int) [][]byte {
	p, err := ledger.InclusionProof(leaves, index)
	if err != nil {
		panic(err)
	}
	return p
}
