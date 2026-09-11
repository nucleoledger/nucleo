// nucleo-demo: ejercicio end-to-end del core criptográfico.
//
//	go run ./cmd/nucleo-demo
//
// Genera claves del tenant, construye génesis + dos eventos (factura SRI y acta
// SAS), verifica la cadena, calcula la raíz de Merkle, produce y verifica una
// prueba de inclusión, y finalmente altera un bloque para demostrar la detección.
package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/nucleoledger/nucleo/internal/keys"
	"github.com/nucleoledger/nucleo/internal/ledger"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "ERROR:", err)
		os.Exit(1)
	}
}

func run() error {
	pub, priv, err := keys.Generate()
	if err != nil {
		return err
	}
	fmt.Println("tenant pubkey:", keys.PublicKeyHex(pub))

	const tenant = "1790012345001" // RUC de ejemplo
	t0 := time.Date(2026, 8, 29, 15, 0, 0, 0, time.UTC)

	// Bloque 0: génesis. Su payload es el propio manifiesto del tenant.
	genesisPayload := []byte(`{"tenant":"1790012345001","razon_social":"EJEMPLO S.A.S."}`)
	h0, err := ledger.NewHeader(nil, tenant, "ledger.genesis.v1", genesisPayload, "local://manifest", pub, t0)
	if err != nil {
		return err
	}
	b0, err := ledger.Seal(h0, priv)
	if err != nil {
		return err
	}

	// Bloque 1: bytes exactos del XML ya autorizado por el SRI (no se canonicaliza XML;
	// se hashea tal cual se conserva, que es lo que exige el SRI).
	factura := []byte(`<?xml version="1.0"?><autorizacion><numeroAutorizacion>2908202601179001234500110010010000000011234567811</numeroAutorizacion></autorizacion>`)
	h1, err := ledger.NewHeader(b0, tenant, "sri.factura.v1", factura, "blob://c4f3...", pub, t0.Add(2*time.Minute))
	if err != nil {
		return err
	}
	b1, err := ledger.Seal(h1, priv)
	if err != nil {
		return err
	}

	// Bloque 2: acta de junta de una SAS. Montos como strings, nunca números.
	acta := []byte(`{"tipo":"junta_general","fecha":"2026-08-29","capital_suscrito":"1000.00"}`)
	h2, err := ledger.NewHeader(b1, tenant, "sas.acta.v1", acta, "blob://9a1b...", pub, t0.Add(5*time.Minute))
	if err != nil {
		return err
	}
	b2, err := ledger.Seal(h2, priv)
	if err != nil {
		return err
	}

	chain := []*ledger.Block{b0, b1, b2}

	canon, _ := b1.Header.Canonical()
	fmt.Printf("\nJCS(header bloque 1):\n%s\n", canon)

	pretty, _ := json.MarshalIndent(b1, "", "  ")
	fmt.Printf("\nBloque 1 completo:\n%s\n", pretty)

	if err := ledger.VerifyChain(chain, pub); err != nil {
		return fmt.Errorf("la cadena legítima no verifica: %w", err)
	}
	fmt.Println("\n✔ cadena de 3 bloques verificada (hash, firma, prev_hash, orden temporal)")

	// Raíz de Merkle: esto es lo que se ancla en anchor.nucleo.ec.
	leaves := make([][]byte, 0, len(chain))
	for _, b := range chain {
		hb, err := b.LeafData()
		if err != nil {
			return err
		}
		leaves = append(leaves, hb)
	}
	root := ledger.Root(leaves)
	fmt.Println("✔ raíz de Merkle (n=3):", hex.EncodeToString(root))

	proof, err := ledger.InclusionProof(leaves, 1)
	if err != nil {
		return err
	}
	if err := ledger.VerifyInclusion(leaves[1], 1, len(leaves), proof, root); err != nil {
		return fmt.Errorf("prueba de inclusión falló: %w", err)
	}
	fmt.Printf("✔ prueba de inclusión del bloque 1 verificada (%d nodos hermanos)\n", len(proof))

	// Ataque: el tenant edita un campo de un bloque ya sellado.
	tampered := *b1
	tampered.Header.Tenant = "9999999999001"
	badChain := []*ledger.Block{b0, &tampered, b2}
	err = ledger.VerifyChain(badChain, pub)
	if err == nil {
		return errors.New("la alteración NO fue detectada")
	}
	fmt.Println("✔ alteración detectada:", err)

	// Ataque 2: refirma el bloque alterado con la clave correcta pero no
	// actualiza el siguiente bloque → rompe prev_hash.
	resealed, err := ledger.Seal(tampered.Header, priv)
	if err != nil {
		return err
	}
	err = ledger.VerifyChain([]*ledger.Block{b0, resealed, b2}, pub)
	if err == nil {
		return errors.New("la refirma NO fue detectada")
	}
	fmt.Println("✔ refirma detectada:", err)

	// Ataque 3: reconstruye toda la cadena desde el bloque alterado. Internamente
	// es válida; solo la raíz anclada externamente la delata.
	h2b, _ := ledger.NewHeader(resealed, tenant, "sas.acta.v1", acta, "blob://9a1b...", pub, t0.Add(5*time.Minute))
	b2b, _ := ledger.Seal(h2b, priv)
	rewritten := []*ledger.Block{b0, resealed, b2b}
	if err := ledger.VerifyChain(rewritten, pub); err != nil {
		return fmt.Errorf("inesperado: %w", err)
	}
	leaves2 := make([][]byte, 0, 3)
	for _, b := range rewritten {
		hb, _ := b.LeafData()
		leaves2 = append(leaves2, hb)
	}
	root2 := ledger.Root(leaves2)
	fmt.Println("⚠ cadena reescrita verifica localmente (esto es la falacia on-premise)")
	fmt.Println("✔ pero su raíz difiere de la anclada:", hex.EncodeToString(root2) != hex.EncodeToString(root))
	return nil
}
