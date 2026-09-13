package main

import (
	"encoding/hex"
	"flag"
	"time"

	"github.com/nucleoledger/nucleo/internal/store"
)

func cmdStatus(e *env, args []string) error {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	fs.SetOutput(e.stderr)
	pf := registerPolicyFlags(fs)
	if err := fs.Parse(args); err != nil {
		return usageErr("%v", err)
	}
	wp, _, err := pf.resolve()
	if err != nil {
		return err
	}
	s, res, err := e.openStoreWith(wp)
	if err != nil {
		return err
	}
	defer s.Close()

	root, err := s.Root()
	if err != nil {
		return err
	}
	// El origin y la clave pública del log salen aquí porque son lo primero que
	// hace falta para configurar un testigo o una política de verificación, y
	// obligar a sacarlos de la base con SQL sería empujar a la gente a hurgar
	// en el fichero que este programa existe para proteger.
	origin, logPub := logIdentity(s)
	st, err := checkStaleness(s, res, now(), e.staleAfter, res.TreeSize)
	if err != nil {
		return err
	}
	// La regla de hoja se publica porque PROTOCOL.md §2.1 exige que sea legible por
	// una máquina: es lo que permite que una migración futura por segmentos sepa qué
	// está mirando sin deducirlo del tamaño de una hoja.
	leafRule, err := s.LeafRule()
	if err != nil {
		return err
	}
	data := map[string]any{
		"dir":           e.dir,
		"leaf_rule":     leafRule,
		"origin":        origin,
		"log_pubkey":    logPub,
		"tree_size":     res.TreeSize,
		"attested":      res.Attested(),
		"attestation":   res.Attestation.String(),
		"attested_size": res.AttestedSize,
		"root":          hex.EncodeToString(root),
		"freshness":     st.json(),
		"signer":        signerJSON(res),
		// La clave del firmante de bloques, para construir una política. Sale de
		// la propia cadena cuando hay bloques —la continuidad garantiza que es una
		// sola— y de vault_meta en un ledger vacío.
		"signer_pubkey": signerPubkey(s, res),
	}
	// El aviso sale ANTES del volcado, y sale también en modo --json: va por
	// stderr, así que no contamina la salida que alguien parsea. Es lo que hace
	// que un cron con stdout a un fichero y stderr al correo avise solo.
	st.warn(e)
	e.out(data, func() {
		e.printf("ledger    : %s\n", e.dbPath())
		if origin != "" {
			e.printf("origin    : %s\n", origin)
			e.printf("clave log : %s\n", logPub)
		}
		e.printf("regla hoja: %s\n", leafRule)
		e.printf("clave firma: %s\n", signerPubkey(s, res))
		e.printf("bloques   : %d\n", res.TreeSize)
		e.printf("raíz      : %s\n", hex.EncodeToString(root))
		printAttestation(e, res)
		printFreshness(e, st)
	})
	return nil
}

// printFreshness añade la línea de frescura a la salida humana.
//
// Es distinta de printAttestation y las dos hacen falta: aquella dice si la
// historia está amparada por alguna raíz cosignada; esta, si eso ocurrió hace
// poco. Un ledger puede estar perfectamente atestiguado hasta el bloque 4.000 y
// llevar dos meses sin sincronizar, y las dos frases serían verdad.
//
// Y la frescura está subordinada a la atestación: la marca ✔ solo sale cuando la
// fecha viene de la cosignature que la apertura VERIFICÓ. Si lo único que hay es el
// registro local de sync, la línea lo dice en la misma frase —"registro local, NO
// verificado"—, porque ese registro lo escribe quien tenga la base y la segunda
// auditoría lo escribió.
func printFreshness(e *env, st staleness) {
	switch {
	case st.Empty:
		// Nada que decir: no hay historia.
	case !st.Known:
		e.printf("frescura  : ⚠ ninguna atestación verificada, ni registro de haberla tenido\n")
	case st.Stale:
		e.printf("frescura  : ⚠ la última atestación es de hace %s (umbral %s)%s\n",
			humanDuration(st.Age), humanDuration(st.Threshold), st.qualifier())
		e.printf("            %s, %s, %d bloques\n",
			st.Record.Witness, st.Record.At.UTC().Format(time.RFC3339), st.Record.Size)
	case st.Verified:
		e.printf("frescura  : ✔ atestación verificada de hace %s, por %s\n",
			humanDuration(st.Age), st.Record.Witness)
	default:
		e.printf("frescura  : ◐ registro local de hace %s, por %s — NO verificado\n",
			humanDuration(st.Age), st.Record.Witness)
		e.printf("            Lo escribió el último `sync` en este disco; abre con --policy-file\n")
		e.printf("            para que la frescura salga de la cosignature verificada.\n")
	}
}

// logIdentity lee el origin y la clave pública del log, que se guardan en claro
// justamente para poder leerlos sin la passphrase.
func logIdentity(s *store.Store) (origin, pubHex string) {
	if raw, err := s.GetMeta(metaLogPubKey); err == nil {
		pubHex = hex.EncodeToString(raw)
	}
	if note, err := s.LastCheckpoint(); err == nil {
		if c, err := checkpointOf(note); err == nil {
			return c.Origin, pubHex
		}
	}
	if raw, err := s.GetMeta(metaOriginKey); err == nil {
		return string(raw), pubHex
	}
	return "", pubHex
}

func cmdVerify(e *env, args []string) error {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	fs.SetOutput(e.stderr)
	full := fs.Bool("full", false, "recomputa TODAS las firmas, sin apoyarse en ningún checkpoint")
	pf := registerPolicyFlags(fs)
	if err := fs.Parse(args); err != nil {
		return usageErr("%v", err)
	}
	wp, _, err := pf.resolve()
	if err != nil {
		return err
	}
	s, res, err := e.openStoreWith(wp)
	if err != nil {
		return err
	}
	defer s.Close()

	mode := "apertura"
	if *full {
		res, err = s.VerifyFull()
		if err != nil {
			return verifyErr("%v", err)
		}
		mode = "exhaustiva"
	}

	st, err := checkStaleness(s, res, now(), e.staleAfter, res.TreeSize)
	if err != nil {
		return err
	}
	// verify REPORTA la frescura, pero no falla por ella: son dos preguntas
	// distintas y mezclarlas haría inútil el código de salida. "Las firmas
	// cuadran" y "alguien de fuera lo vio hace poco" pueden tener respuestas
	// opuestas, y quien llama necesita distinguirlas.
	st.warn(e)
	e.out(map[string]any{
		"mode":          mode,
		"tree_size":     res.TreeSize,
		"attested":      res.Attested(),
		"attestation":   res.Attestation.String(),
		"attested_size": res.AttestedSize,
		"freshness":     st.json(),
		"signer":        signerJSON(res),
	}, func() {
		if *full {
			e.printf("✔ verificación EXHAUSTIVA superada: %d bloques, todas las firmas recomputadas\n", res.TreeSize)
		} else {
			e.printf("✔ verificación superada: %d bloques\n", res.TreeSize)
			if res.Attested() {
				e.printf("  (las firmas anteriores al bloque %d están amparadas por un\n", res.AttestedSize)
				e.printf("   checkpoint cosignado; `verify --full` las recomprueba todas)\n")
			}
		}
		printAttestation(e, res)
		printFreshness(e, st)
	})
	return nil
}

// printAttestation dice en voz alta qué respalda la historia, con el mismo
// lenguaje del PoC: la distinción entre "íntegra" y "completa" es la que cuesta
// entender y la que más importa.
func printAttestation(e *env, r store.OpenResult) {
	printSigner(e, r)
	switch {
	case r.TreeSize == 0:
		e.printf("estado    : base nueva, todavía sin historia que atestiguar\n")
	case r.Attestation == store.AttestationVerified:
		e.printf("estado    : ✔ historia atestiguada hasta %d de %d bloques\n", r.AttestedSize, r.TreeSize)
	case r.Attestation == store.AttestationUnverified:
		// Hay un checkpoint cosignado y su firma de log verifica, pero nadie ha
		// aportado la clave del testigo, así que no se sabe si un tercero lo
		// avala. Se dice así, y no "atestiguada": la auditoría adversarial
		// fabricó una nota con forma de cosignada y el programa la daba por buena.
		e.printf("estado    : ◐ checkpoint presente hasta el bloque %d, NO verificado\n", r.AttestedSize)
		e.printf("            %s.\n", r.Reason)
		e.printf("            Para comprobar que un testigo lo avala, pasa --policy-file (o\n")
		e.printf("            --witness-name y --witness-key): la prueba tiene que venir de\n")
		e.printf("            fuera de este fichero.\n")
	default:
		e.printf("estado    : ⚠ SIN ATESTIGUAR (%d bloques)\n", r.TreeSize)
		e.printf("            La cadena es localmente válida, pero que esté COMPLETA no\n")
		e.printf("            está garantizado: sin un checkpoint cosignado por un testigo,\n")
		e.printf("            un prefijo truncado es indistinguible de la historia entera.\n")
		e.printf("            Ejecuta `nucleo sync` contra un testigo.\n")
	}
}

// printSigner dice qué se sabe del firmante de los bloques (ADR-017).
//
// La continuidad —una sola clave en toda la cadena— ya se comprobó al abrir, o
// no se habría llegado aquí. Lo que aquí se dice es si esa clave es la que quien
// abre esperaba, y eso solo se sabe con una política. Una cadena reescrita ENTERA
// por otra clave es autoconsistente: sin la clave esperada, lo honesto es decir
// "no verificado" y publicar la clave, para que alguien la compare.
func printSigner(e *env, r store.OpenResult) {
	switch r.Signer {
	case store.SignerVerified:
		e.printf("firmante  : ✔ verificado contra la política\n")
	case store.SignerUnverified:
		e.printf("firmante  : ◐ una sola clave en toda la cadena, NO verificada contra ninguna política\n")
		e.printf("            Pasa --signer-key o --policy-file para comprobar que es la tuya.\n")
	}
}

// signerJSON es el objeto "signer" de --json.
func signerJSON(r store.OpenResult) map[string]any {
	return map[string]any{
		"state":    r.Signer.String(),
		"verified": r.Signer == store.SignerVerified,
		"pubkey":   r.SignerKey,
	}
}

// signerPubkey devuelve la clave del firmante: la de la cadena si hay bloques, la
// de vault_meta si no.
func signerPubkey(s *store.Store, r store.OpenResult) string {
	if r.SignerKey != "" {
		return r.SignerKey
	}
	if raw, err := s.GetMeta(store.MetaSignerPubKey); err == nil {
		return hex.EncodeToString(raw)
	}
	return ""
}
