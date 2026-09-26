package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/nucleoledger/nucleo/internal/ledger"
	"github.com/nucleoledger/nucleo/internal/proof"
	"github.com/nucleoledger/nucleo/internal/receipt"
	"github.com/nucleoledger/nucleo/internal/store"
)

func cmdSeal(e *env, args []string) error {
	fs := flag.NewFlagSet("seal", flag.ContinueOnError)
	fs.SetOutput(e.stderr)
	tenant := fs.String("tenant", "", "identificador del emisor, p. ej. el RUC")
	typ := fs.String("type", "", "tipo de registro, p. ej. sri.factura.v1")
	payload := fs.String("payload", "", "fichero con el contenido a sellar")
	profile := fs.String("profile", "", "perfil que interpreta el documento, p. ej. ecuador.sri.factura")
	xmlFile := fs.String("xml", "", "fichero XML del comprobante (equivale a --payload con un perfil)")
	passFile := fs.String("passphrase-file", "", "fichero con la passphrase")
	clear := fs.Bool("no-encrypt", false, "no guarda el contenido cifrado; solo sella su hash")
	// Desactivado por omisión a propósito (ADR-028 §A): un registro que no se sella se
	// pierde, y una atestación atrasada se recupera en el siguiente sync.
	failOnStale := fs.Bool("fail-on-stale", false, "no sella si la atestación está vieja: sale con 3 sin escribir, para quien tenga cola y pueda reintentar")
	// optString y no fs.String por lo mismo que --policy-file: un cron con la variable
	// vacía pasaría --idempotency-key "" y sellaría un duplicado creyendo lo contrario.
	idemKey := &optString{}
	fs.Var(idemKey, "idempotency-key", "clave del integrador para que un reintento no duplique el registro")
	pf := registerPolicyFlags(fs)
	maxPayload := fs.Int64("max-payload", DefaultMaxPayload, "tamaño máximo del documento a sellar, en bytes")
	if err := fs.Parse(args); err != nil {
		return usageErr("%v", err)
	}
	if *xmlFile != "" {
		if *payload != "" {
			return usageErr("--xml y --payload son la misma cosa; usa uno")
		}
		*payload = *xmlFile
	}
	if *profile != "" && *typ == "" {
		*typ = strings.TrimPrefix(*profile, "ecuador.")
		*typ = "ecuador." + *typ + ".v1"
	}
	switch {
	case *typ == "":
		return usageErr("seal necesita --type (o --profile)")
	case *payload == "":
		return usageErr("seal necesita --payload <archivo> (o --xml)")
	}
	if *maxPayload <= 0 {
		return usageErr("--max-payload debe ser positivo")
	}
	data, err := readLimited(*payload, *maxPayload, "el documento")
	if err != nil {
		return err
	}

	// El perfil interpreta el documento ANTES de sellar nada. Si la clave de
	// acceso no cuadra, más vale saberlo ahora que dejar en el ledger, para
	// siempre, un comprobante que el SRI no reconoce.
	var prof *profileResult
	if *profile != "" {
		prof, err = applyProfile(*profile, data)
		if err != nil {
			return usageErr("%v", err)
		}
		if *tenant == "" {
			*tenant = prof.tenant
		} else if *tenant != prof.tenant {
			return usageErr("--tenant dice %q y el documento dice %q", *tenant, prof.tenant)
		}
	}
	if *tenant == "" {
		return usageErr("seal necesita --tenant")
	}

	wp, _, err := pf.resolve(e)
	if err != nil {
		return err
	}
	s, res, err := e.openStoreWith(wp)
	if err != nil {
		return err
	}
	defer s.Close()

	v, id, err := e.unlock(s, *passFile, "Passphrase del vault: ")
	if err != nil {
		return err
	}
	defer v.Close()
	if err := checkChainSigner(res, id, "sella"); err != nil {
		return err
	}

	sum := sha256.Sum256(data)
	payloadHash := hex.EncodeToString(sum[:])

	// El reintento se resuelve ANTES de construir el bloque, y después de comprobar el
	// firmante: un reintento contra un ledger secuestrado no puede contestar "todo en
	// orden" (ADR-020 §D).
	if idemKey.set {
		if err := validarClaveIdem(idemKey.v); err != nil {
			return usageErr("%v", err)
		}
		previo, hay, err := leerIdem(s, *tenant, idemKey.v)
		if err != nil {
			return err
		}
		if hay {
			return sealIdempotente(e, s, res, wp != nil, previo, payloadHash, *typ, prof)
		}
	}

	// --fail-on-stale: se juzga ANTES de construir nada, con el ledger tal como se abrió.
	// Va después del reintento idempotente, que no escribe y por eso no hay nada que
	// rechazar. La alarma se registra igual: negarse a sellar no la hace menos cierta.
	if *failOnStale {
		st, err := checkStaleness(s, res, wp != nil, now(), e.staleAfter, res.TreeSize)
		if err != nil {
			return err
		}
		if st.Stale && !st.Empty {
			alarma := registraAlarma(e, s, st)
			st.warn(e)
			return syncErr("no se ha sellado: la atestación está vieja y se pidió --fail-on-stale.\n"+
				"  No se ha escrito ningún bloque. Ejecuta `nucleo sync` y, cuando salga bien,\n"+
				"  reintenta con la MISMA --idempotency-key. Si prefieres sellar igualmente —el\n"+
				"  registro quedará sin atestiguar hasta el próximo sync—, quita --fail-on-stale.").
				conClase(claseTransitoria).conExtra("alert", alarma.json())
		}
	}

	// Un intento de sellado: leer el último bloque, construir el siguiente, firmarlo y
	// escribirlo todo en una transacción. Va en un bucle porque entre la lectura y la
	// escritura puede colarse OTRO proceso —el ERP con dos workers— y entonces el bloque
	// que acabamos de firmar ya no sigue a nadie. Ver intentosDeSellado.
	var (
		b           *ledger.Block
		duplicados  []uint64
		commitments map[string]string
	)
	intento := func() error {
		// La clave de idempotencia se vuelve a mirar en CADA intento: si el proceso que
		// nos ganó la carrera era nuestro propio reintento con la misma clave, el
		// registro ya está y sellar otra vez lo duplicaría.
		if idemKey.set {
			previo, hay, err := leerIdem(s, *tenant, idemKey.v)
			if err != nil {
				return err
			}
			if hay {
				return sealIdempotente(e, s, res, wp != nil, previo, payloadHash, *typ, prof)
			}
		}

		prev, err := s.LastBlock()
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return err
		}
		if errors.Is(err, store.ErrNotFound) {
			prev = nil
		}

		// Los bloques que ya sellaron ESTE contenido. Se leen antes de escribir nada
		// para poder NOMBRAR el duplicado: re-sellar es legítimo (ADR-020 §A), pero
		// silencioso no, porque un duplicado accidental es mucho más frecuente que uno
		// deliberado.
		duplicados, err = s.BlocksWithPayload(payloadHash)
		if err != nil {
			return err
		}

		cid := "blob://" + payloadHash
		if *clear {
			cid = "none://"
		}

		h, err := ledger.NewHeader(prev, *tenant, *typ, data, cid, id.TenantPublic(), now())
		if err != nil {
			return usageErr("%v", err)
		}
		if err := relojCoherente(e, prev, h); err != nil {
			return err
		}
		b, err = ledger.Seal(h, id.Tenant)
		if err != nil {
			return err
		}

		// El contenido cifrado, los compromisos y la clave de idempotencia se escriben
		// en la MISMA transacción que el bloque (ADR-020 §C). Antes eran tres escrituras
		// sueltas, y un fallo entre la primera y la segunda dejaba un blob huérfano que
		// bloqueaba el reintento de ese documento para siempre.
		rec := store.Record{Block: b}
		if !*clear {
			blob, err := contenidoParaSellar(v, s, *tenant, payloadHash, data, duplicados)
			if err != nil {
				return err
			}
			// nil significa que la fila que ya hay es exactamente la que se escribiría.
			rec.Blob = blob
		}

		// Los compromisos van referidos al payload_hash, que sí está firmado, y NO al
		// header: son metadatos del perfil.
		if prof != nil {
			var meta map[string][]byte
			commitments, meta, err = commitmentsDe(v, *tenant, payloadHash, prof)
			if err != nil {
				return err
			}
			rec.Meta = meta
		}

		if idemKey.set {
			k, val, err := entradaIdem(idemRecord{
				Tenant:      *tenant,
				Key:         idemKey.v,
				Type:        *typ,
				Block:       b.Header.Index,
				PayloadHash: payloadHash,
				SealedAt:    b.Header.Timestamp,
			})
			if err != nil {
				return err
			}
			rec.State = map[string]string{k: val}
		}
		return s.AppendRecord(rec)
	}

	if err := sellarConReintentos(intento); err != nil {
		return err
	}
	if b == nil {
		// sealIdempotente ya contestó: el reintento no escribió nada.
		return nil
	}

	salida := map[string]any{
		"index":        b.Header.Index,
		"hash":         b.Hash,
		"payload_hash": payloadHash,
		"encrypted":    !*clear,
		"idempotent":   false,
	}
	if len(duplicados) > 0 {
		salida["duplicate_of"] = duplicados
	}
	if idemKey.set {
		salida["idempotency_key"] = idemKey.v
	}
	if prof != nil {
		salida["profile"] = prof.name
		salida["metadata"] = prof.plain
		salida["commitments"] = commitments
	}

	// Sellar es el momento en que alguien está CONFIANDO en esto: acaba de meter
	// un registro que va a dar por protegido. Si la última atestación lleva días
	// muerta, es aquí donde tiene que enterarse, no la próxima vez que alguien se
	// acuerde de mirar `status`. El sellado no falla por ello —el bloque queda
	// escrito y firmado, que es lo que se pidió— pero deja de ser silencioso.
	// La atestación y el firmante van en la misma cola que el reintento idempotente,
	// con la misma semántica que status: el bloque recién sellado NO está cubierto por
	// ellos —eso lo dice el texto—, pero quien automatiza el sellado tiene que poder
	// ver en la misma salida qué respaldaba la historia sobre la que acaba de escribir.
	st, err := sealTail(e, s, res, wp != nil, b.Header.Index+1, salida)
	if err != nil {
		return err
	}
	// El sellado no se prohíbe con un rollback registrado —lo que se pidió fue sellar—
	// pero se dice donde ocurre y en cada bloque: cada uno se aparta más de la historia
	// que un tercero atestiguó.
	st.warnRollback(e)

	e.out(salida, func() {
		e.printf("✔ registro sellado\n")
		e.printf("  bloque       : %d\n", b.Header.Index)
		e.printf("  hash bloque  : %s\n", b.Hash)
		e.printf("  hash contenido: %s\n", payloadHash)
		if *clear {
			e.printf("  el contenido NO se guardó: solo queda su hash en el ledger\n")
		}
		printDuplicados(e, duplicados)
		if prof != nil {
			printProfile(e, prof, commitments)
		}
		e.printf("\n  El bloque aún no está atestiguado. Ejecuta `nucleo sync` para que\n")
		e.printf("  un testigo lo vea; hasta entonces solo lo respalda esta máquina.\n")
		if st.Stale {
			printFreshness(e, st)
		}
	})
	return nil
}

func cmdReceipt(e *env, args []string) error {
	fs := flag.NewFlagSet("receipt", flag.ContinueOnError)
	fs.SetOutput(e.stderr)
	block := fs.Int64("block", -1, "índice del bloque")
	recipient := fs.String("recipient", "", "a quién se entrega el recibo")
	out := fs.String("out", "", "fichero de salida (por defecto, la pantalla)")
	pf := registerPolicyFlags(fs)
	passFile := fs.String("passphrase-file", "", "fichero con la passphrase")
	if err := fs.Parse(args); err != nil {
		return usageErr("%v", err)
	}
	switch {
	case *block < 0:
		return usageErr("receipt necesita --block N")
	case *recipient == "":
		return usageErr("receipt necesita --recipient \"Nombre\"")
	}

	wp, file, err := pf.resolve(e)
	if err != nil {
		return err
	}
	if wp == nil {
		return usageErr("receipt necesita la política del testigo: --policy-file, o --witness-name y --witness-key")
	}
	s, _, err := e.openStoreWith(wp)
	if err != nil {
		return err
	}
	defer s.Close()

	// La política del emisor. Origin y clave del log salen del propio ledger; los
	// testigos, de la política; la clave del firmante, del vault que se abre abajo.
	pol, err := issuerPolicy(s, wp)
	if err != nil {
		return err
	}

	// Emitir un recibo pasa a exigir la passphrase, y conviene decir por qué: desde
	// ADR-015 el emisor FIRMA el recibo entero, destinatario incluido, y esa clave
	// vive cifrada en el vault. Antes `receipt` solo leía, así que no hacía falta.
	// El precio es real —una passphrase más en el cron que emite recibos— y compra
	// que la línea del destinatario deje de ser reescribible por cualquiera que
	// tenga el fichero.
	v, id, err := e.unlock(s, *passFile, "Passphrase del vault: ")
	if err != nil {
		return err
	}
	defer v.Close()
	// La clave del firmante de la política del EMISOR sale del vault que acaba de
	// abrir, no de vault_meta ni del ledger: es la única fuente que el propio
	// emisor no puede haberse dejado manipular sin la passphrase (ADR-017).
	pol.SignerKey = id.TenantPublic()
	// Si la política vino en fichero, tiene que ser la de ESTE ledger y ESTE vault.
	if file != nil {
		if err := checkPolicyMatchesLedger(file, pol.Origin, pol.LogKey, pol.SignerKey); err != nil {
			return err
		}
	}

	r, err := receipt.Issue(s, *recipient, uint64(*block), pol, id.Tenant)
	if err != nil {
		if errors.Is(err, receipt.ErrNotAttested) {
			// Clase TRANSITORIA aunque el código sea 1 (ADR-027 §B): no hay nada mal
			// en la llamada, solo hace falta que un testigo cubra ese bloque. Es el
			// caso que encontró el ejemplo de integración: un ERP tiene que
			// sincronizar y reintentar, no arreglar su código.
			return usageErr("%v\n  Ejecuta `nucleo sync` para que un testigo cubra ese bloque.", err).conClase(claseTransitoria)
		}
		return usageErr("%v", err)
	}
	data, err := receipt.Format(r, pol)
	if err != nil {
		return err
	}

	if *out != "" {
		if err := os.WriteFile(*out, data, 0o600); err != nil {
			return usageErr("no se pudo escribir %q: %v", *out, err)
		}
	}

	res, err := r.Verify(pol)
	if err != nil {
		return verifyErr("el recibo recién emitido no verifica: %v", err)
	}
	provable := ""
	if len(res.Cosigners) > 0 {
		provable = res.ProvableTime.UTC().Format("2006-01-02T15:04:05Z07:00")
	}

	e.out(map[string]any{
		"block":         *block,
		"recipient":     *recipient,
		"bytes":         len(data),
		"cosigners":     res.Cosigners,
		"provable_time": provable,
		"receipt":       string(data),
		"out":           *out,
	}, func() {
		if *out != "" {
			e.printf("✔ recibo escrito en %s (%d bytes)\n\n", *out, len(data))
		}
		fmt.Fprint(e.stdout, receipt.Text(data))
		e.printf("\n\n")
		if len(res.Cosigners) == 0 {
			e.printf("  ⚠ Este recibo NO tiene tiempo demostrable: ningún testigo aceptado\n")
			e.printf("    ha cosignado el checkpoint que lo respalda. Prueba que el registro\n")
			e.printf("    está en el log, no CUÁNDO existía.\n")
		}
	})
	return nil
}

// issuerPolicy arma la política con la que se emite y se comprueba el recibo.
func issuerPolicy(s *store.Store, wp *store.WitnessPolicy) (proof.Policy, error) {
	noteBytes, err := s.LastCheckpoint()
	if err != nil {
		// TRANSITORIA, como el bloque sin cubrir: no falta nada en la llamada, falta
		// que un testigo haya visto este log (ADR-027 §B). Es el mismo caso con un
		// paso menos de historia, y el ejemplo de integración tropieza primero aquí.
		return proof.Policy{}, usageErr("el ledger no tiene ningún checkpoint todavía; ejecuta `nucleo sync`").conClase(claseTransitoria)
	}
	c, err := checkpointOf(noteBytes)
	if err != nil {
		return proof.Policy{}, err
	}
	pol := proof.Policy{Origin: c.Origin}

	logKey, err := s.GetMeta(metaLogPubKey)
	if err != nil {
		return proof.Policy{}, fmt.Errorf("no se encontró la clave pública del log en el ledger: %w", err)
	}
	pol.LogKey = logKey

	pol.Witnesses = wp.Witnesses
	pol.Quorum = wp.Quorum
	return pol, nil
}

// metaLogPubKey guarda la pública del log en claro, para poder verificar sin
// abrir el vault. Es pública: no hay nada que proteger y sí mucho que ganar en
// que un verificador no necesite la passphrase.
const metaLogPubKey = store.MetaLogPubKey

// metaOriginKey guarda el origin del log, también en claro y por lo mismo:
// configurar un testigo o una política no debería exigir abrir el vault.
const metaOriginKey = store.MetaOriginKey
