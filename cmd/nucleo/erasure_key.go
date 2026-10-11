package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/nucleoledger/nucleo/internal/erasure"
	"github.com/nucleoledger/nucleo/internal/vault"
	"golang.org/x/term"
)

// La clave de supresión (ADR-032): la que decide si una supresión cuenta.
//
// No es ninguna de las claves del despliegue. No la abre la passphrase, no la
// reconstruyen las tarjetas del vault, y no está en el servidor: la custodia quien
// responde de las solicitudes de supresión, repartida en sus propias tarjetas
// SLIP-0039. Su parte pública va en la política, como erasureKey, y la reconciliación
// solo acepta una supresión si su autorización verifica con ella.
//
// Ninguno de los dos subcomandos abre un ledger: se ejecutan en el equipo de la
// custodia, que puede no tener red.

func cmdErasureKey(e *env, args []string) error {
	if len(args) == 0 {
		return usageErr("uso: nucleo erasure-key init [--shares N --threshold K] | " +
			"nucleo erasure-key authorize --policy-file F --payload-hash H --through K")
	}
	switch args[0] {
	case "init":
		return cmdErasureKeyInit(e, args[1:])
	case "authorize":
		return cmdErasureKeyAuthorize(e, args[1:])
	default:
		return usageErr("erasure-key: subcomando desconocido %q; son `init` y `authorize`", args[0])
	}
}

// cmdErasureKeyInit genera la clave de supresión, la reparte en tarjetas y enseña su
// clave pública. La semilla no toca el disco: lo único que queda son las tarjetas.
func cmdErasureKeyInit(e *env, args []string) error {
	fs := flag.NewFlagSet("erasure-key init", flag.ContinueOnError)
	fs.SetOutput(e.stderr)
	shares := fs.Int("shares", defaultShares, "número de tarjetas de la clave de supresión")
	threshold := fs.Int("threshold", defaultThreshold, "tarjetas necesarias para autorizar una supresión")
	yes := fs.Bool("assume-confirmed", false, "salta la confirmación tecleada de la tarjeta (solo automatización)")
	if err := fs.Parse(args); err != nil {
		return usageErr("%v", err)
	}
	// Como init: en --json no hay a quién pedirle que teclee la palabra.
	if e.json && !*yes {
		return usageErr("erasure-key init --json no puede pedir que se teclee la confirmación de las tarjetas: " +
			"pasa --assume-confirmed explícitamente (y guarda las tarjetas que salen en el JSON)")
	}

	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		return err
	}
	defer vault.Wipe(seed)
	// El reparto es el mismo que el de la KEK —SLIP-0039 de un secreto de 32 bytes,
	// comprobado antes de devolverlo—; lo que cambia es qué secreto se reparte.
	cards, err := vault.BackupKEK(seed, *shares, *threshold)
	if err != nil {
		return usageErr("%v", err)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := hex.EncodeToString(priv.Public().(ed25519.PublicKey))
	vault.Wipe(priv)

	if e.json {
		e.printJSON(map[string]any{
			"erasure_key": pub,
			"shares":      cards,
			"threshold":   *threshold,
		})
		return nil
	}
	printCardsDeSupresion(e, cards, *threshold)
	e.printf("  CLAVE PÚBLICA DE SUPRESIÓN — va en la política de quien reconcilia:\n\n")
	e.printf("    \"erasureKey\": \"%s\"\n\n", pub)
	e.printf("  Sin ella en la política, ninguna supresión cuenta: reconcile sigue\n")
	e.printf("  señalando el registro como faltante (ADR-032).\n\n")
	if *yes {
		return nil
	}
	ok, err := tecleaLaPalabra(e, cards)
	if err != nil {
		return err
	}
	if !ok {
		return usageErr("la palabra no coincide.\n\n" +
			"  La clave de supresión no se ha guardado en ningún sitio: las tarjetas de esta\n" +
			"  pantalla son lo único que existe. Si no las has copiado, no pongas esa clave\n" +
			"  pública en la política y vuelve a ejecutar `nucleo erasure-key init`.")
	}
	e.printf("✔ confirmado. Guarda las tarjetas como se ha explicado.\n")
	return nil
}

// printCardsDeSupresion enseña las tarjetas con su custodia, que no es la del vault.
func printCardsDeSupresion(e *env, cards []string, threshold int) {
	e.printf("\n")
	e.printf("═══════════════════════════════════════════════════════════════\n")
	e.printf("  TARJETAS DE LA CLAVE DE SUPRESIÓN — SLIP-0039\n")
	e.printf("═══════════════════════════════════════════════════════════════\n")
	e.printf("\n")
	e.printf("  Son %d tarjetas y hacen falta %d para autorizar una supresión.\n", len(cards), threshold)
	e.printf("  NO son las tarjetas del vault, y no abren nada del servidor.\n\n")
	for i, c := range cards {
		e.printf("  ── TARJETA DE SUPRESIÓN %d de %d ──\n", i+1, len(cards))
		for _, line := range wrapWords(c, 6) {
			e.printf("     %s\n", line)
		}
		e.printf("\n")
	}
	e.printf("  QUIÉN LAS GUARDA\n")
	e.printf("  · Quien responde de las solicitudes de supresión —el responsable del\n")
	e.printf("    tratamiento o su delegado de protección de datos—, en papel.\n")
	e.printf("  · NADIE que opere el servidor debe poder reunir %d. Si quien\n", threshold)
	e.printf("    administra el servidor tiene también estas tarjetas, la clave de\n")
	e.printf("    supresión no separa nada.\n")
	e.printf("  · Mejor en manos distintas de las que tienen las tarjetas del vault.\n")
	e.printf("  · Perderlas no pierde datos: impide suprimir. Se genera otra clave\n")
	e.printf("    y se cambia erasureKey en la política.\n")
	e.printf("\n")
}

// cmdErasureKeyAuthorize firma la autorización de una supresión con las tarjetas de la
// clave de supresión. Lo que devuelve es una línea de texto que no es secreta: va a ir
// en el payload_cid del evento, en la cadena.
func cmdErasureKeyAuthorize(e *env, args []string) error {
	fs := flag.NewFlagSet("erasure-key authorize", flag.ContinueOnError)
	fs.SetOutput(e.stderr)
	policyFile := fs.String("policy-file", "", "la política de ese log: da el origin y la erasureKey que las tarjetas tienen que reconstruir")
	payloadHash := fs.String("payload-hash", "", "hash del contenido que se suprime (64 hexadecimales)")
	through := fs.Int64("through", -1, "último bloque con ese contenido que la autorización cubre")
	if err := fs.Parse(args); err != nil {
		return usageErr("%v", err)
	}
	if *policyFile == "" || *payloadHash == "" || *through < 0 {
		return usageErr("erasure-key authorize necesita --policy-file, --payload-hash y --through:\n" +
			"  `nucleo erase` los dice, con la orden exacta, cuando le falta la autorización")
	}
	f, err := loadPolicyFile(e, *policyFile)
	if err != nil {
		return err
	}
	origin, key := f.ErasureAuthority()
	if key == nil {
		return usageErr("la política %q no trae erasureKey: sin ella ninguna supresión cuenta, y no hay\n"+
			"  clave que comprobar. Genera la clave con `nucleo erasure-key init` y pon su clave\n"+
			"  pública en la política (ADR-032).", *policyFile)
	}
	if _, err := erasure.AuthorizationText(origin, *payloadHash, uint64(*through)); err != nil {
		return usageErr("%v", err)
	}

	fmt.Fprintf(e.stderr, "Se va a AUTORIZAR la supresión, SIN VUELTA ATRÁS, del contenido\n"+
		"  %s\nen el log %q, en los bloques con ese contenido hasta el %d.\n"+
		"Comprueba que es lo que te han pedido antes de teclear las tarjetas.\n",
		*payloadHash, origin, *through)
	cards, ok := hookCards()
	if !ok {
		// Como las tarjetas del vault en la enmienda de ADR-031: no es la frontera —la
		// frontera es que estas tarjetas no estén en el servidor—; es lo que evita que
		// alguien las deje en un fichero para automatizar lo que no debe automatizarse.
		if !term.IsTerminal(int(os.Stdin.Fd())) {
			return usageErr("erasure-key authorize pide las tarjetas de la clave de supresión tecleadas en una\n" +
				"  consola, y aquí no hay consola. Ejecútalo desde un terminal interactivo, con las\n" +
				"  tarjetas a mano. No se aceptan de un fichero ni por una tubería (ADR-032).")
		}
		fmt.Fprintln(e.stderr, "Teclea las tarjetas de la CLAVE DE SUPRESIÓN (no las del vault).")
		if cards, err = readShares(e, ""); err != nil {
			return err
		}
	}
	seed, err := vault.RestoreKEK(cards)
	if err != nil {
		return usageErr("no se pudo reconstruir la clave con esas tarjetas: %v", err)
	}
	defer vault.Wipe(seed)
	priv := ed25519.NewKeyFromSeed(seed)
	defer vault.Wipe(priv)
	if !priv.Public().(ed25519.PublicKey).Equal(key) {
		return usageErr("las tarjetas reconstruyen una clave, pero NO es la erasureKey de la política %q.\n"+
			"  ¿Son las tarjetas del vault? Esas no autorizan supresiones: hacen falta las de la\n"+
			"  clave de supresión, las que dio `nucleo erasure-key init`.", *policyFile)
	}
	cid, err := erasure.Authorize(priv, origin, *payloadHash, uint64(*through))
	if err != nil {
		return err
	}
	e.out(map[string]any{
		"authorization":       cid,
		"origin":              origin,
		"erased_payload_hash": *payloadHash,
		"through":             *through,
	}, func() {
		e.printf("✔ supresión autorizada\n")
		e.printf("  log               : %s\n", origin)
		e.printf("  hash del contenido: %s\n", *payloadHash)
		e.printf("  hasta el bloque   : %d\n", *through)
		e.printf("\n  La autorización —no es secreta: irá en la cadena—:\n\n    %s\n\n", cid)
		e.printf("  Quien opera el servidor la pasa a `nucleo erase --authorization`.\n")
	})
	return nil
}

// ordenAutorizar es la orden que tiene que ejecutar la custodia, con los valores ya
// puestos. La imprime erase cuando le falta la autorización.
func ordenAutorizar(policyFile, payloadHash string, through uint64) string {
	return strings.Join([]string{"nucleo erasure-key authorize",
		"--policy-file", argShell(policyFile),
		"--payload-hash", payloadHash,
		"--through", fmt.Sprint(through)}, " ")
}
