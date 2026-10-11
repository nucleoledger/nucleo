package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/nucleoledger/nucleo/internal/erasure"
	"github.com/nucleoledger/nucleo/internal/identity"
	"github.com/nucleoledger/nucleo/internal/ledger"
	"github.com/nucleoledger/nucleo/internal/store"
	"github.com/nucleoledger/nucleo/internal/vault"
	"golang.org/x/term"
)

// La supresión (ADR-031): borrar el contenido de un registro cuando su titular lo
// pide, sin tocar la cadena.
//
// Lo que se borra: la copia cifrada del contenido y sus compromisos. Lo que queda: el
// bloque, con su payload_hash, y todo lo que demuestra —firma, inclusión, recibos—. Y
// lo que se añade: un evento sellado, sin datos personales, que dice que el contenido
// de ese hash se suprimió, para que la reconciliación no confunda una supresión
// legítima con un registro que alguien hizo desaparecer.

// prefijoConfirmacion es cuántos caracteres del hash hay que teclear para confirmar.
const prefijoConfirmacion = 8

func cmdErase(e *env, args []string) error {
	fs := flag.NewFlagSet("erase", flag.ContinueOnError)
	fs.SetOutput(e.stderr)
	block := fs.Int64("block", -1, "índice del bloque cuyo contenido se suprime")
	// --passphrase-file se declara solo para rechazarlo con su porqué: sin esto, quien lo
	// pase recibiría «flag provided but not defined», que no dice qué hace falta.
	passFile := fs.String("passphrase-file", "", "NO se acepta: erase exige dos tarjetas de respaldo (ADR-031, enmienda)")
	yes := fs.Bool("assume-confirmed", false, "salta la confirmación tecleada del hash (las tarjetas se teclean igual)")
	pf := registerPolicyFlags(fs)
	if err := fs.Parse(args); err != nil {
		return usageErr("%v", err)
	}
	if *passFile != "" {
		return usageErr("erase no acepta la passphrase: suprimir exige DOS TARJETAS de respaldo SLIP-0039,\n" +
			"  tecleadas en una consola (ADR-031, enmienda). La passphrase vive en el servidor para\n" +
			"  sellar, y quien comprometa el servidor la tiene; las tarjetas no deberían estar ahí.")
	}
	if *block < 0 {
		return usageErr("erase necesita --block N")
	}
	// Como init y restore: en --json no hay a quién pedirle que teclee, y saltarse la
	// confirmación en silencio sería decidir por quien llama. Lo tiene que decir él.
	if e.json && !*yes {
		return usageErr("erase --json no puede pedir que se teclee la confirmación: " +
			"pasa --assume-confirmed explícitamente")
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

	b, err := bloqueEnIndice(s, uint64(*block))
	if errors.Is(err, store.ErrNotFound) {
		return usageErr("el ledger no tiene el bloque %d (tiene %d)", *block, res.TreeSize)
	}
	if err != nil {
		return err
	}
	if b.Header.Type == erasure.Type {
		return usageErr("el bloque %d es un evento de supresión: no tiene contenido que suprimir", *block)
	}
	h := b.Header.PayloadHash

	hayBlob, err := existe(s.GetBlob(h))
	if err != nil {
		return err
	}
	hayCompromisos, err := existe(s.GetMeta(metaCommitPrefix + h))
	if err != nil {
		return err
	}
	afectados, err := s.BlocksWithPayload(h)
	if err != nil {
		return err
	}

	if !hayBlob && !hayCompromisos {
		previo, err := eventoDeSupresion(s, h, b.Header.Index)
		if err != nil {
			return err
		}
		if previo == nil {
			return usageErr("no hay nada guardado del contenido del bloque %d: se selló con --no-encrypt\n"+
				"  y sin perfil, así que Núcleo solo tiene su hash, que está en la cadena y no se puede\n"+
				"  borrar sin romperla. El contenido vive solo en tu sistema: es ahí donde se suprime.", *block)
		}
		// Ya está suprimido: no se sella otro evento. Volver a pedirlo es un reintento, y
		// es lo que se aconseja cuando el WAL no se pudo vaciar: por eso se vuelve a
		// intentar aquí.
		walVacio, err := s.PurgeWAL()
		if err != nil {
			return err
		}
		e.out(map[string]any{
			"erased_payload_hash": h,
			"blocks":              afectados,
			"already_erased":      true,
			"index":               previo.Header.Index,
			"hash":                previo.Hash,
			"wal_purged":          walVacio,
		}, func() {
			e.printf("✔ el contenido del bloque %d ya estaba suprimido (evento en el bloque %d)\n",
				*block, previo.Header.Index)
			e.printf("  No se ha escrito ningún bloque.\n")
		})
		avisaWAL(e, walVacio)
		return nil
	}

	v, id, err := abreConTarjetas(e, s)
	if err != nil {
		return err
	}
	defer v.Close()
	if err := checkChainSigner(res, id, "suprime"); err != nil {
		return err
	}

	if !*yes {
		ok, err := tecleaElHash(e, h, afectados)
		if err != nil {
			return err
		}
		if !ok {
			return usageErr("los caracteres no coinciden: no se ha suprimido nada")
		}
	}

	payload, err := erasure.Payload(h)
	if err != nil {
		return err
	}
	var ev *ledger.Block
	intento := func() error {
		prev, err := s.LastBlock()
		if err != nil {
			return err
		}
		// El evento va a nombre del mismo tenant que el registro, y sin copia del
		// contenido: no hace falta, se reconstruye a partir del hash (ADR-031 §C).
		hd, err := ledger.NewHeader(prev, b.Header.Tenant, erasure.Type, payload, "none://", id.TenantPublic(), now())
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
		// Lo que el evento no dice —qué contenido, qué bloques— va a log_state en la misma
		// transacción, para la alarma de supresión. La alarma no depende de ello: se
		// abre por el evento, esté o no el detalle.
		detalle, err := marshalJSON(detalleSupresion{ErasedPayloadHash: h, Blocks: afectados})
		if err != nil {
			return err
		}
		rec := store.Record{
			Block:      ev,
			DeleteMeta: []string{metaCommitPrefix + h},
			State:      map[string]string{metaSupresionDetalle + ev.Hash: string(detalle)},
		}
		if hayBlob {
			rec.EraseBlob = h
		}
		return s.AppendRecord(rec)
	}
	if err := sellarConReintentos(intento); err != nil {
		return err
	}

	// Lo borrado ya tiene ceros en el fichero principal (secure_delete); falta que no
	// quede una copia reciente en el WAL. Si otro proceso lo está leyendo no se puede
	// vaciar entero, y se dice: la supresión está hecha, pero no del todo en el disco.
	walVacio, err := s.PurgeWAL()
	if err != nil {
		return err
	}

	salida := map[string]any{
		"index":               ev.Header.Index,
		"hash":                ev.Hash,
		"erased_payload_hash": h,
		"blocks":              afectados,
		"already_erased":      false,
		"wal_purged":          walVacio,
	}
	st, err := sealTail(e, s, res, wp != nil, ev.Header.Index+1, salida)
	if err != nil {
		return err
	}
	st.warnRollback(e)
	avisaWAL(e, walVacio)

	e.out(salida, func() {
		e.printf("✔ contenido suprimido\n")
		e.printf("  hash del contenido: %s\n", h)
		e.printf("  bloques afectados : %s\n", strings.TrimPrefix(listaBloques(afectados), "el "))
		e.printf("  evento sellado    : bloque %d\n", ev.Header.Index)
		e.printf("\n  La cadena y los recibos ya emitidos siguen verificando: demuestran el hash,\n")
		e.printf("  no el contenido. Las copias de seguridad del ledger hechas antes de hoy aún\n")
		e.printf("  lo contienen, cifrado: destrúyelas o déjalas fuera del alcance de quien tenga\n")
		e.printf("  la passphrase. El registro en tu propio sistema lo suprimes tú.\n")
		e.printf("\n  Ejecuta `nucleo sync` para que un testigo vea el evento.\n")
		if st.Stale {
			printFreshness(e, st)
		}
	})
	return nil
}

// avisaWAL dice, si hace falta, que una copia del contenido suprimido puede seguir en
// el WAL. Repetir la orden vuelve a intentar el vaciado sin sellar otro evento.
func avisaWAL(e *env, walVacio bool) {
	if walVacio {
		return
	}
	fmt.Fprintf(e.stderr, "⚠ otro proceso estaba leyendo el ledger y el WAL no se pudo vaciar: una copia\n"+
		"  del contenido suprimido puede seguir en %s-wal hasta que SQLite lo vacíe.\n"+
		"  Vuelve a ejecutar esta misma orden cuando no haya otro proceso usando el ledger.\n", e.dbPath())
}

// abreConTarjetas abre el vault con dos tarjetas SLIP-0039 —las que reconstruyen la KEK,
// como en restore— y carga la identidad (ADR-031, enmienda).
//
// Las tarjetas solo se aceptan tecleadas en una consola: no hay bandera de fichero, y
// una entrada que no es un terminal se rechaza. No es la frontera de seguridad —quien
// tenga las tarjetas puede simular una consola—; la frontera es que las tarjetas no
// estén en el servidor. Esto evita que nadie las deje en un fichero junto a la
// passphrase para automatizar lo que no debe automatizarse.
func abreConTarjetas(e *env, s *store.Store) (*vault.Vault, *identity.Identity, error) {
	cards, ok := hookCards()
	if !ok {
		if !term.IsTerminal(int(os.Stdin.Fd())) {
			return nil, nil, usageErr("erase pide dos tarjetas de respaldo tecleadas en una consola, y aquí no hay\n" +
				"  consola. Ejecútalo desde un terminal interactivo, con las tarjetas a mano.\n" +
				"  No se aceptan de un fichero ni por una tubería (ADR-031, enmienda).")
		}
		fmt.Fprintln(e.stderr, "Suprimir exige dos tarjetas de respaldo SLIP-0039.")
		var err error
		cards, err = readShares(e, "")
		if err != nil {
			return nil, nil, err
		}
	}
	kek, err := vault.RestoreKEK(cards)
	if err != nil {
		return nil, nil, usageErr("no se pudo reconstruir la clave con esas tarjetas: %v", err)
	}
	defer vault.Wipe(kek)
	v, err := vault.UnlockKEK(s, kek)
	if errors.Is(err, vault.ErrUnwrap) {
		return nil, nil, verifyErr("las tarjetas reconstruyen una clave, pero NO es la de este vault, o son tarjetas\n" +
			"  de antes de un cambio de passphrase: esas quedaron sin valor (ADR-029)")
	}
	if err != nil {
		return nil, nil, usageErr("no se pudo abrir el vault: %v", err)
	}
	id, err := identity.Load(v, s)
	if err != nil {
		v.Close()
		return nil, nil, err
	}
	return v, id, nil
}

// existe convierte el resultado de una lectura en «está» o «no está».
func existe[T any](_ T, err error) (bool, error) {
	if errors.Is(err, store.ErrNotFound) {
		return false, nil
	}
	return err == nil, err
}

// eventoDeSupresion devuelve el primer evento posterior al bloque desde que suprime el
// contenido h, o nil.
func eventoDeSupresion(s *store.Store, h string, desde uint64) (*ledger.Block, error) {
	eh, err := erasure.EventPayloadHash(h)
	if err != nil {
		return nil, err
	}
	idx, err := s.BlocksWithPayload(eh)
	if err != nil {
		return nil, err
	}
	for _, i := range idx {
		if i <= desde {
			continue
		}
		b, err := bloqueEnIndice(s, i)
		if err != nil {
			return nil, err
		}
		if b.Header.Type == erasure.Type {
			return b, nil
		}
	}
	return nil, nil
}

// tecleaElHash enseña lo que se va a suprimir y pide teclear el principio del hash.
// No es un trámite: suprimir no tiene vuelta atrás, y el bloque equivocado —un dígito
// mal copiado en --block— es el error que esto detiene.
func tecleaElHash(e *env, h string, afectados []uint64) (bool, error) {
	fmt.Fprintf(e.stderr, "Se va a suprimir, SIN VUELTA ATRÁS, el contenido %s\n", h)
	fmt.Fprintf(e.stderr, "de %s. La cadena no cambia; el contenido no se podrá recuperar.\n", listaBloques(afectados))
	fmt.Fprintf(e.stderr, "Para confirmar, escribe los %d primeros caracteres de ese hash: ", prefijoConfirmacion)
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		return false, usageErr("no se pudo leer la confirmación: %v\n"+
			"  Sin una consola que teclee, pasa --assume-confirmed.", err)
	}
	return strings.TrimSpace(line) == h[:prefijoConfirmacion], nil
}
