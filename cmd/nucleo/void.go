package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"

	"github.com/nucleoledger/nucleo/internal/erasure"
	"github.com/nucleoledger/nucleo/internal/ledger"
	"github.com/nucleoledger/nucleo/internal/store"
	"github.com/nucleoledger/nucleo/internal/void"
)

// La anulación (ADR-035): el emisor declara anulada una emisión, que se queda intacta.
//
// No borra nada y no disculpa nada. Sella un bloque más, nucleo.void.v1, que apunta a la
// emisión por su índice y su payload_hash; reconcile lo enseña en voided, y la emisión se
// sigue cotejando como cualquier otro registro: si el ERP la borra, sigue faltando. Por
// eso basta la passphrase, como seal: sin tarjetas y sin la clave de supresión.
//
// Lo que esta orden NO sabe es si el SRI la anuló de verdad. Es la declaración del emisor
// (L24): el ERP la sella cuando el SRI devuelve «ANULADO», nunca en «PENDIENTE DE ANULAR».

func cmdVoid(e *env, args []string) error {
	fs := flag.NewFlagSet("void", flag.ContinueOnError)
	fs.SetOutput(e.stderr)
	block := fs.Int64("block", -1, "índice del bloque que se anula (el camino principal: el ERP ya lo guarda)")
	payload := fs.String("payload", "", "fichero con el contenido sellado (p. ej. el XML); busca el bloque por su SHA-256")
	tenant := fs.String("tenant", "", "si se da, tiene que ser el tenant del bloque")
	passFile := fs.String("passphrase-file", "", "fichero con la passphrase")
	pf := registerPolicyFlags(fs)
	maxPayload := fs.Int64("max-payload", DefaultMaxPayload, "tamaño máximo del fichero de --payload, en bytes")
	if err := fs.Parse(args); err != nil {
		return usageErr("%v", err)
	}
	switch {
	case *block >= 0 && *payload != "":
		return usageErr("void lleva --block N o --payload F, no los dos")
	case *block < 0 && *payload == "":
		return usageErr("void necesita --block N (el índice que el ERP guarda de cada factura)\n" +
			"  o --payload F (el contenido sellado; se busca por su SHA-256)")
	}
	var data []byte
	if *payload != "" {
		if *maxPayload <= 0 {
			return usageErr("--max-payload debe ser positivo")
		}
		var err error
		if data, err = readLimited(*payload, *maxPayload, "el documento"); err != nil {
			return err
		}
	}

	wp, pol, err := pf.resolve(e)
	if err != nil {
		return err
	}
	s, res, err := e.openStoreWith(wp)
	if err != nil {
		return err
	}
	defer s.Close()

	idx := uint64(*block)
	if data != nil {
		if idx, err = bloqueDelContenido(s, data); err != nil {
			return err
		}
	}
	b, err := bloqueEnIndice(s, idx)
	if errors.Is(err, store.ErrNotFound) {
		return usageErr("el ledger no tiene el bloque %d (tiene %d)", idx, res.TreeSize)
	}
	if err != nil {
		return err
	}
	// R4 y R5 de PROTOCOL §5.2, antes de abrir nada: la CLI no sella lo que reconcile daría
	// por inválido.
	if erasure.Reserved(b.Header.Type) {
		return usageErr("el bloque %d es un evento de Núcleo (%s): no se anula (ADR-035, R4)", idx, b.Header.Type)
	}
	if *tenant != "" && *tenant != b.Header.Tenant {
		return usageErr("--tenant dice %q y el bloque %d es de %q: no se anula", *tenant, idx, b.Header.Tenant)
	}

	// Ya anulado: no se sella otra (R6). Las anulaciones de este bloque, válidas o no, son
	// los bloques con el payload_hash que tendría la suya; con el bloque y ellas basta para
	// aplicar las reglas, porque R1–R6 no miran nada más.
	eh, err := void.EventPayloadHash(idx, b.Header.PayloadHash)
	if err != nil {
		return err
	}
	previas, err := bloquesConPayload(s, eh)
	if err != nil {
		return err
	}
	if previa := void.Evaluate(append([]*ledger.Block{b}, previas...)).VoidOf(idx); previa != nil {
		ev := previa.Event
		e.out(map[string]any{
			"voided_index":        idx,
			"voided_payload_hash": b.Header.PayloadHash,
			"already_voided":      true,
			"index":               ev.Header.Index,
			"hash":                ev.Hash,
		}, func() {
			e.printf("✔ el bloque %d ya estaba anulado (evento en el bloque %d)\n", idx, ev.Header.Index)
			e.printf("  No se ha escrito ningún bloque.\n")
		})
		return nil
	}

	v, id, err := e.unlock(s, *passFile, "Passphrase del vault: ")
	if err != nil {
		return err
	}
	defer v.Close()
	if err := checkChainSigner(res, id, "anula"); err != nil {
		return err
	}
	if err := cotejaLogMLDSAKey(pol, id); err != nil {
		return err
	}

	contenido, err := void.Payload(idx, b.Header.PayloadHash)
	if err != nil {
		return err
	}
	var ev *ledger.Block
	intento := func() error {
		prev, err := s.LastBlock()
		if err != nil {
			return err
		}
		// A nombre del tenant de la emisión (R5), sin copia del contenido: se reconstruye
		// del índice y el hash, que el payload_cid y la cadena ya llevan.
		hd, err := ledger.NewHeader(prev, b.Header.Tenant, void.Type, contenido, void.CID(idx), id.TenantPublic(), now())
		if err != nil {
			return usageErr("%v", err)
		}
		if err := relojCoherente(e, prev, hd); err != nil {
			return err
		}
		ev, err = ledger.Seal(hd, id.Tenant)
		if err != nil {
			return err
		}
		return s.AppendRecord(store.Record{Block: ev})
	}
	if err := sellarConReintentos(intento); err != nil {
		return err
	}

	salida := map[string]any{
		"index":               ev.Header.Index,
		"hash":                ev.Hash,
		"voided_index":        idx,
		"voided_payload_hash": b.Header.PayloadHash,
		"already_voided":      false,
	}
	st, err := sealTail(e, s, res, wp != nil, ev.Header.Index+1, salida)
	if err != nil {
		return err
	}
	st.warnRollback(e)

	e.out(salida, func() {
		e.printf("✔ bloque %d anulado\n", idx)
		e.printf("  hash sellado   : %s\n", b.Header.PayloadHash)
		e.printf("  evento sellado : bloque %d\n", ev.Header.Index)
		e.printf("\n  La emisión sigue en la cadena y su recibo sigue verificando. reconcile la\n")
		e.printf("  enseña como anulada y la sigue cotejando: no la borres de tu sistema.\n")
		e.printf("  Esto es tu declaración, no el estado del SRI (L24).\n")
		e.printf("\n  Ejecuta `nucleo sync` para que un testigo vea el evento.\n")
		if st.Stale {
			printFreshness(e, st)
		}
	})
	return nil
}

// bloqueDelContenido busca el bloque que selló exactamente estos bytes. Ninguno es un
// error; más de uno también, de uso: elegir uno sería adivinar cuál quiere anular el ERP.
func bloqueDelContenido(s *store.Store, data []byte) (uint64, error) {
	sum := sha256.Sum256(data)
	h := hex.EncodeToString(sum[:])
	idx, err := s.BlocksWithPayload(h)
	if err != nil {
		return 0, err
	}
	switch len(idx) {
	case 0:
		return 0, usageErr("ningún bloque selló ese contenido (SHA-256 %s): no hay nada que anular.\n"+
			"  Comprueba que es el fichero exacto que se selló, byte a byte", h)
	case 1:
		return idx[0], nil
	}
	return 0, usageErr("ese contenido está sellado en %s: elige cuál se anula con --block N\n"+
		"  (anular es de un registro concreto, ADR-035)", listaBloques(idx))
}

// bloquesConPayload devuelve, en orden, los bloques cuyo payload_hash es h.
func bloquesConPayload(s *store.Store, h string) ([]*ledger.Block, error) {
	idx, err := s.BlocksWithPayload(h)
	if err != nil {
		return nil, err
	}
	out := make([]*ledger.Block, 0, len(idx))
	for _, i := range idx {
		b, err := bloqueEnIndice(s, i)
		if err != nil {
			return nil, fmt.Errorf("bloque %d: %w", i, err)
		}
		out = append(out, b)
	}
	return out, nil
}
