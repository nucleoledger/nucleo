package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/nucleoledger/nucleo/internal/ledger"
	"github.com/nucleoledger/nucleo/internal/store"
	"github.com/nucleoledger/nucleo/internal/vault"
)

// Volver a sellar: lo que pasa cuando el contenido, o la clave de idempotencia, ya
// estaban (ADR-020).
//
// Las tres situaciones son distintas y hasta el Sprint 8 se confundían en un mismo
// volcado del motor SQLite:
//
//	mismo contenido, mismo tenant   → bloque NUEVO, y se dice de cuál es duplicado
//	mismo contenido, otro tenant    → se rechaza, porque su copia cifrada no se puede
//	                                  descifrar con el AAD del otro tenant
//	misma clave de idempotencia     → no-op: se contesta lo del sellado original

// contenidoParaSellar decide qué blob entra en la transacción del sellado.
//
// Devuelve un blob nil —sin error— cuando el contenido cifrado ya está guardado y es
// REUTILIZABLE, que es lo que hace que la transacción no lo reescriba: mismo
// tenant y mismo payload_hash dan el mismo AAD (PROTOCOL §5), así que la fila que hay es
// exactamente la que se escribiría. Antes de reutilizarla se descifra y se compara con
// el contenido en mano; si no cuadra, no es un duplicado, es otra cosa, y se dice cuál.
func contenidoParaSellar(v *vault.Vault, s *store.Store, tenant, payloadHash string, data []byte, duplicados []uint64) (*store.Blob, error) {
	existente, err := s.GetBlob(payloadHash)
	switch {
	case errors.Is(err, store.ErrNotFound):
		ct, nonce, err := v.EncryptBlob(tenant, payloadHash, data)
		if err != nil {
			return nil, err
		}
		return &store.Blob{
			PayloadHash: payloadHash,
			Ciphertext:  ct,
			Nonce:       nonce,
			CreatedAt:   now().UTC().Format("2006-01-02T15:04:05Z07:00"),
		}, nil
	case err != nil:
		return nil, err
	}

	pt, err := v.DecryptBlob(tenant, payloadHash, existente.Ciphertext, existente.Nonce)
	if err != nil {
		return nil, errContenidoAjeno(s, tenant, payloadHash, duplicados)
	}
	if !bytes.Equal(pt, data) {
		// Dos contenidos distintos con el mismo SHA-256 y el mismo AAD. Si esto sale
		// alguna vez, la noticia no es este ledger.
		return nil, verifyErr("el contenido guardado bajo %s no es el que se está sellando", payloadHash)
	}
	return nil, nil
}

// errContenidoAjeno explica por qué no se puede sellar un contenido cuya copia cifrada
// no descifra con el AAD de este tenant, y nombra al dueño si hay un bloque que lo diga.
func errContenidoAjeno(s *store.Store, tenant, payloadHash string, duplicados []uint64) error {
	dueño := ""
	for _, idx := range duplicados {
		b, err := bloqueEnIndice(s, idx)
		if err != nil || b.Header.Tenant == tenant {
			continue
		}
		dueño = b.Header.Tenant
		return usageErr("ese contenido ya está sellado por el tenant %q (bloque %d), y su copia cifrada\n"+
			"  está atada a ese tenant: %q no podría descifrarla.\n"+
			"  Sella con --no-encrypt (solo el hash entra en el ledger) o usa un despliegue\n"+
			"  propio para ese tenant. Ver ADR-020 §B.", dueño, idx, tenant)
	}
	// Ningún bloque lo referencia: es el resto de un sellado interrumpido de ANTES de
	// ADR-020, cuando el blob se escribía fuera de la transacción del bloque.
	return usageErr("hay contenido guardado bajo %s que este tenant no puede descifrar y que\n"+
		"  ningún bloque referencia: es el resto de un sellado interrumpido de otro tenant.\n"+
		"  Sella con --no-encrypt, o borra ese contenido huérfano antes de reintentar.", payloadHash)
}

// bloqueEnIndice lee un bloque por su índice.
func bloqueEnIndice(s *store.Store, idx uint64) (*ledger.Block, error) {
	bs, err := s.Blocks(idx, idx+1)
	if err != nil {
		return nil, err
	}
	if len(bs) == 0 {
		return nil, store.ErrNotFound
	}
	return bs[0], nil
}

// printDuplicados dice de qué bloques es duplicado el registro que se acaba de sellar.
func printDuplicados(e *env, duplicados []uint64) {
	if len(duplicados) == 0 {
		return
	}
	e.printf("\n  ⚠ Este contenido ya estaba sellado en %s. El bloque nuevo es un\n",
		listaBloques(duplicados))
	e.printf("    registro NUEVO del mismo contenido, que es lo que se pidió; si lo que\n")
	e.printf("    querías era no duplicar un reintento, usa --idempotency-key.\n")
}

// listaBloques compone "el bloque 3" o "los bloques 3, 7 y 9".
func listaBloques(idx []uint64) string {
	switch len(idx) {
	case 0:
		return ""
	case 1:
		return fmt.Sprintf("el bloque %d", idx[0])
	}
	s := "los bloques "
	for i, v := range idx {
		switch {
		case i == 0:
			s += fmt.Sprintf("%d", v)
		case i == len(idx)-1:
			s += fmt.Sprintf(" y %d", v)
		default:
			s += fmt.Sprintf(", %d", v)
		}
	}
	return s
}

// sealIdempotente contesta a un reintento con la misma clave: no escribe nada y
// devuelve lo que devolvió el sellado original.
//
// Las tres comprobaciones no son ceremonia. log_state NO está firmado: quien pueda
// escribir el fichero intentaría que un reintento diera por sellado un documento que no
// está. Por eso el bloque se LEE del ledger y se compara con el documento en mano.
func sealIdempotente(e *env, s *store.Store, res store.OpenResult, withPolicy bool, previo idemRecord, payloadHash, typ string, prof *profileResult) error {
	if previo.PayloadHash != payloadHash {
		return usageErr("la clave de idempotencia %q ya se usó para otro documento:\n"+
			"  bloque %d, contenido %s.\n"+
			"  Una clave nombra un sellado concreto, así que reutilizarla para otro documento\n"+
			"  no puede ser un reintento. Usa otra clave, o sella sin clave si de verdad\n"+
			"  quieres un registro nuevo.",
			previo.Key, previo.Block, previo.PayloadHash)
	}
	if previo.Type != typ {
		return usageErr("la clave de idempotencia %q se usó con --type %q y ahora se pide %q\n"+
			"  (bloque %d). Mismo contenido y distinto tipo son dos registros distintos.",
			previo.Key, previo.Type, typ, previo.Block)
	}

	b, err := bloqueEnIndice(s, previo.Block)
	if errors.Is(err, store.ErrNotFound) {
		return verifyErr("la clave de idempotencia %q dice que este documento se selló en el bloque %d,\n"+
			"  y ese bloque NO está en el ledger. El registro y el bloque se escriben juntos,\n"+
			"  así que esto no es un sellado a medias: alguien ha tocado el fichero.", previo.Key, previo.Block)
	}
	if err != nil {
		return err
	}
	if b.Header.PayloadHash != payloadHash || b.Header.Tenant != previo.Tenant {
		return verifyErr("la clave de idempotencia %q apunta al bloque %d, que sella otro contenido\n"+
			"  (%s, tenant %q). El registro de idempotencia no coincide con el ledger.",
			previo.Key, previo.Block, b.Header.PayloadHash, b.Header.Tenant)
	}

	salida := map[string]any{
		"index":           b.Header.Index,
		"hash":            b.Hash,
		"payload_hash":    payloadHash,
		"encrypted":       b.Header.PayloadCID != "none://",
		"idempotent":      true,
		"idempotency_key": previo.Key,
	}
	commitments, err := commitmentsGuardados(s, payloadHash)
	if err != nil {
		return err
	}
	if prof != nil {
		salida["profile"] = prof.name
		salida["metadata"] = prof.plain
		salida["commitments"] = commitments
	}

	st, err := sealTail(e, s, res, withPolicy, b.Header.Index+1, salida)
	if err != nil {
		return err
	}
	st.warnRollback(e)

	e.out(salida, func() {
		e.printf("✔ este registro ya estaba sellado (reintento idempotente)\n")
		e.printf("  bloque       : %d\n", b.Header.Index)
		e.printf("  hash bloque  : %s\n", b.Hash)
		e.printf("  hash contenido: %s\n", payloadHash)
		e.printf("  clave        : %s\n", previo.Key)
		e.printf("\n  No se ha escrito nada: el sellado original es del %s.\n", previo.SealedAt)
		if prof != nil {
			printProfile(e, prof, commitments)
		}
		if st.Stale {
			printFreshness(e, st)
		}
	})
	return nil
}

// commitmentsGuardados lee los compromisos que dejó el sellado original.
func commitmentsGuardados(s *store.Store, payloadHash string) (map[string]string, error) {
	raw, err := s.GetMeta(metaCommitPrefix + payloadHash)
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out map[string]string
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, verifyErr("los compromisos de %s están ilegibles: %v", payloadHash, err)
	}
	return out, nil
}

// sealTail añade a la salida lo que el sellado dice del estado del ledger —frescura,
// atestación y firmante— y avisa si la atestación está vieja.
//
// Lo comparten el sellado y el reintento idempotente a propósito: un integrador que
// reintenta tiene que ver exactamente los mismos campos, o su código tendría dos
// caminos donde el contrato promete uno (docs/CLI-JSON.md).
func sealTail(e *env, s *store.Store, res store.OpenResult, withPolicy bool, treeSize uint64, salida map[string]any) (staleness, error) {
	st, err := checkStaleness(s, res, withPolicy, now(), e.staleAfter, treeSize)
	if err != nil {
		return staleness{}, err
	}
	salida["freshness"] = st.json()
	if rb := st.rollbackJSON(); rb != nil {
		salida["rollback"] = rb
	}
	salida["attestation"] = res.Attestation.String()
	salida["attested"] = res.Attested()
	// Con treeSize y no con res.TreeSize: `seal` juzga DESPUÉS de escribir su bloque, y
	// ese bloque no lo atestigua nadie todavía. Comparar con el tamaño de antes diría
	// que la cabeza está atestiguada justo cuando acaba de dejar de estarlo.
	salida["attested_head"] = res.Attested() && res.AttestedSize == treeSize
	salida["attested_size"] = res.AttestedSize
	salida["signer"] = signerJSON(res)
	// La alarma se registra en el ledger y se publica: el aviso de stderr de abajo no
	// lo lee nadie en el hosting donde vive este producto (ADR-028).
	salida["alert"] = registraAlarma(e, s, st).json()
	st.warn(e)
	return st, nil
}
