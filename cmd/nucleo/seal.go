package main

import (
	"crypto/ed25519"
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
	data, err := os.ReadFile(*payload)
	if err != nil {
		return usageErr("no se pudo leer %q: %v", *payload, err)
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

	s, _, err := e.openStore()
	if err != nil {
		return err
	}
	defer s.Close()

	v, id, err := e.unlock(s, *passFile, "Passphrase del vault: ")
	if err != nil {
		return err
	}
	defer v.Close()

	prev, err := s.LastBlock()
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return err
	}
	if errors.Is(err, store.ErrNotFound) {
		prev = nil
	}

	sum := sha256.Sum256(data)
	payloadHash := hex.EncodeToString(sum[:])
	cid := "blob://" + payloadHash
	if *clear {
		cid = "none://"
	}

	h, err := ledger.NewHeader(prev, *tenant, *typ, data, cid, id.TenantPublic(), now())
	if err != nil {
		return usageErr("%v", err)
	}
	b, err := ledger.Seal(h, id.Tenant)
	if err != nil {
		return err
	}

	// El contenido cifrado se guarda ANTES del bloque. Si el proceso muere entre
	// las dos escrituras, sobra un blob sin bloque —inofensivo— en vez de faltar
	// el blob de un bloque ya sellado, que sería un registro sin contenido.
	if !*clear {
		ct, nonce, err := v.EncryptBlob(*tenant, payloadHash, data)
		if err != nil {
			return err
		}
		if err := s.PutBlob(payloadHash, ct, nonce); err != nil {
			return err
		}
	}
	if err := s.AppendBlock(b); err != nil {
		return err
	}

	// Los compromisos se guardan DESPUÉS del bloque y referidos a su
	// payload_hash: son metadatos del registro, no parte de lo firmado.
	var commitments map[string]string
	if prof != nil {
		commitments, err = storeCommitments(s, v, *tenant, payloadHash, prof)
		if err != nil {
			return err
		}
	}

	salida := map[string]any{
		"index":        b.Header.Index,
		"hash":         b.Hash,
		"payload_hash": payloadHash,
		"encrypted":    !*clear,
	}
	if prof != nil {
		salida["profile"] = prof.name
		salida["metadata"] = prof.plain
		salida["commitments"] = commitments
	}
	e.out(salida, func() {
		e.printf("✔ registro sellado\n")
		e.printf("  bloque       : %d\n", b.Header.Index)
		e.printf("  hash bloque  : %s\n", b.Hash)
		e.printf("  hash contenido: %s\n", payloadHash)
		if *clear {
			e.printf("  el contenido NO se guardó: solo queda su hash en el ledger\n")
		}
		if prof != nil {
			printProfile(e, prof, commitments)
		}
		e.printf("\n  El bloque aún no está atestiguado. Ejecuta `nucleo sync` para que\n")
		e.printf("  un testigo lo vea; hasta entonces solo lo respalda esta máquina.\n")
	})
	return nil
}

func cmdReceipt(e *env, args []string) error {
	fs := flag.NewFlagSet("receipt", flag.ContinueOnError)
	fs.SetOutput(e.stderr)
	block := fs.Int64("block", -1, "índice del bloque")
	recipient := fs.String("recipient", "", "a quién se entrega el recibo")
	out := fs.String("out", "", "fichero de salida (por defecto, la pantalla)")
	witnessName := fs.String("witness-name", "", "nombre del testigo aceptado")
	witnessKey := fs.String("witness-key", "", "clave pública del testigo, en hexadecimal")
	if err := fs.Parse(args); err != nil {
		return usageErr("%v", err)
	}
	switch {
	case *block < 0:
		return usageErr("receipt necesita --block N")
	case *recipient == "":
		return usageErr("receipt necesita --recipient \"Nombre\"")
	}

	s, _, err := e.openStore()
	if err != nil {
		return err
	}
	defer s.Close()

	// La política del emisor. Las claves del log salen del propio ledger: el
	// checkpoint guardado dice qué origin es, y el recibo se emite contra él.
	pol, err := issuerPolicy(s, *witnessName, *witnessKey)
	if err != nil {
		return err
	}

	r, err := receipt.Issue(s, *recipient, uint64(*block))
	if err != nil {
		if errors.Is(err, receipt.ErrNotAttested) {
			return usageErr("%v\n  Ejecuta `nucleo sync` para que un testigo cubra ese bloque.", err)
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
func issuerPolicy(s *store.Store, witnessName, witnessKey string) (proof.Policy, error) {
	noteBytes, err := s.LastCheckpoint()
	if err != nil {
		return proof.Policy{}, usageErr("el ledger no tiene ningún checkpoint todavía; ejecuta `nucleo sync`")
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

	if witnessName != "" || witnessKey != "" {
		if witnessName == "" || witnessKey == "" {
			return proof.Policy{}, usageErr("--witness-name y --witness-key van juntos")
		}
		pub, err := hexKey(witnessKey)
		if err != nil {
			return proof.Policy{}, err
		}
		pol.Witnesses = map[string]ed25519.PublicKey{witnessName: pub}
	}
	return pol, nil
}

// metaLogPubKey guarda la pública del log en claro, para poder verificar sin
// abrir el vault. Es pública: no hay nada que proteger y sí mucho que ganar en
// que un verificador no necesite la passphrase.
const metaLogPubKey = "log/pubkey/v1"

// metaOriginKey guarda el origin del log, también en claro y por lo mismo:
// configurar un testigo o una política no debería exigir abrir el vault.
const metaOriginKey = "log/origin/v1"
