package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/nucleoledger/nucleo/internal/erasure"
	"github.com/nucleoledger/nucleo/internal/ledger"
	"github.com/nucleoledger/nucleo/internal/store"
)

// La supresión (ADR-031): borrar el contenido de un registro cuando su titular lo
// pide, sin tocar la cadena.
//
// Lo que se borra: la copia cifrada del contenido y sus compromisos. Lo que queda: el
// bloque, con su payload_hash, y todo lo que demuestra —firma, inclusión, recibos—. Y
// lo que se añade: un evento sellado, sin datos personales, que dice que el contenido
// de ese hash se suprimió, para que la reconciliación no confunda una supresión
// legítima con un registro que alguien hizo desaparecer.
//
// Lo que hace legítima una supresión no es este comando: es la autorización de la
// clave de supresión, que no está en el servidor (ADR-032). erase la comprueba antes de
// tocar nada y la sella en el evento; sin ella no borra, y un evento sin ella no cuenta.

// prefijoConfirmacion es cuántos caracteres del hash hay que teclear para confirmar.
const prefijoConfirmacion = 8

func cmdErase(e *env, args []string) error {
	fs := flag.NewFlagSet("erase", flag.ContinueOnError)
	fs.SetOutput(e.stderr)
	block := fs.Int64("block", -1, "índice del bloque cuyo contenido se suprime")
	passFile := fs.String("passphrase-file", "", "fichero con la passphrase")
	autorizacion := fs.String("authorization", "", "la autorización de la clave de supresión (la da `nucleo erasure-key authorize`)")
	yes := fs.Bool("assume-confirmed", false, "salta la confirmación tecleada del hash")
	pf := registerPolicyFlags(fs)
	if err := fs.Parse(args); err != nil {
		return usageErr("%v", err)
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

	wp, pol, err := pf.resolve(e)
	if err != nil {
		return err
	}
	// Sin la clave de supresión no hay contra qué comprobar la autorización, y una
	// supresión sin autorización comprobable no cuenta: borrar el contenido sería
	// convertir el registro en un faltante. Mejor no empezar.
	auth := erasure.Authority{}
	if pol != nil {
		auth.Origin, auth.Key = pol.ErasureAuthority()
	}
	if auth.Key == nil {
		return usageErr("erase necesita --policy-file con una política que traiga erasureKey: la clave de\n" +
			"  supresión, que es la que autoriza cada supresión (ADR-032). Sin ella, ninguna supresión\n" +
			"  cuenta y reconcile seguiría señalando el registro como faltante. La clave se genera,\n" +
			"  fuera del servidor, con `nucleo erasure-key init`.")
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
		previo, err := eventoDeSupresion(s, auth, h, b.Header.Index)
		if err != nil {
			return err
		}
		if previo != nil {
			// Ya está suprimido: no se sella otro evento. Volver a pedirlo es un reintento,
			// y es lo que se aconseja cuando el WAL no se pudo vaciar: por eso se vuelve a
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
		// Nada guardado y ninguna supresión autorizada. Si hay un evento sin autorización
		// válida, el contenido ya no está y lo que falta es la autorización: se sella un
		// evento que la lleve, sin nada que borrar. Si no lo hay, nunca se guardó nada.
		sinAutorizar, err := hayEventoSinAutorizar(s, h, b.Header.Index)
		if err != nil {
			return err
		}
		if !sinAutorizar {
			return usageErr("no hay nada guardado del contenido del bloque %d: se selló con --no-encrypt\n"+
				"  y sin perfil, así que Núcleo solo tiene su hash, que está en la cadena y no se puede\n"+
				"  borrar sin romperla. El contenido vive solo en tu sistema: es ahí donde se suprime.", *block)
		}
	}

	// Lo que queda por hacer: o borrar el contenido, o —si ya no está pero el evento que
	// lo dice no lleva autorización válida— sellar el evento que sí la lleva. En los dos
	// casos hace falta la autorización, y se comprueba antes de abrir el vault.
	through := afectados[len(afectados)-1]
	if *autorizacion == "" {
		return usageErr("suprimir exige la autorización de la clave de supresión (ADR-032). Quien la custodia\n"+
			"  la firma en su equipo, con su copia de la política y sus tarjetas:\n\n"+
			"    %s\n\n"+
			"  y te da una línea, que no es secreta. Vuelve a ejecutar esta orden con\n"+
			"  --authorization <esa línea>. No se ha borrado nada.",
			ordenAutorizar(pf.file.v, h, through))
	}
	cubre, err := erasure.VerifyCID(auth.Key, auth.Origin, h, *autorizacion)
	if err != nil {
		return usageErr("esa autorización no sirve para este contenido: %v\n"+
			"  No se ha borrado nada. La orden que tiene que ejecutar la custodia es:\n\n    %s",
			err, ordenAutorizar(pf.file.v, h, through))
	}
	if cubre != through {
		return usageErr("la autorización llega hasta el bloque %d, y el último bloque con ese contenido es el %d:\n"+
			"  si el contenido se volvió a sellar después de autorizarlo, la autorización no cubre la\n"+
			"  copia nueva. No se ha borrado nada. Pide una autorización nueva:\n\n    %s",
			cubre, through, ordenAutorizar(pf.file.v, h, through))
	}

	v, id, err := e.unlock(s, *passFile, "Passphrase del vault: ")
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
		// contenido: no hace falta, se reconstruye a partir del hash (ADR-031 §C). Su
		// payload_cid lleva la autorización, que es lo que hace que cuente (ADR-032).
		hd, err := ledger.NewHeader(prev, b.Header.Tenant, erasure.Type, payload, *autorizacion, id.TenantPublic(), now())
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
		e.printf("\n  reconcile lo informa como suprimido con una política que traiga esta erasureKey.\n")
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

// existe convierte el resultado de una lectura en «está» o «no está».
func existe[T any](_ T, err error) (bool, error) {
	if errors.Is(err, store.ErrNotFound) {
		return false, nil
	}
	return err == nil, err
}

// eventoDeSupresion devuelve el primer evento AUTORIZADO posterior al bloque desde que
// suprime el contenido h y llega hasta ese bloque, o nil. Un evento sin autorización
// válida no cuenta (ADR-032): no es una supresión hecha, es un hallazgo.
func eventoDeSupresion(s *store.Store, auth erasure.Authority, h string, desde uint64) (*ledger.Block, error) {
	eventos, err := eventosDe(s, h, desde)
	if err != nil {
		return nil, err
	}
	for _, ev := range eventos {
		if through, err := auth.Check(ev, h); err == nil && through >= desde {
			return ev, nil
		}
	}
	return nil, nil
}

// hayEventoSinAutorizar dice si después del bloque desde hay algún evento de
// supresión del contenido h, autorizado o no.
func hayEventoSinAutorizar(s *store.Store, h string, desde uint64) (bool, error) {
	eventos, err := eventosDe(s, h, desde)
	return len(eventos) > 0, err
}

// eventosDe devuelve los eventos de supresión del contenido h posteriores al bloque
// desde, en orden.
func eventosDe(s *store.Store, h string, desde uint64) ([]*ledger.Block, error) {
	eh, err := erasure.EventPayloadHash(h)
	if err != nil {
		return nil, err
	}
	idx, err := s.BlocksWithPayload(eh)
	if err != nil {
		return nil, err
	}
	var out []*ledger.Block
	for _, i := range idx {
		if i <= desde {
			continue
		}
		b, err := bloqueEnIndice(s, i)
		if err != nil {
			return nil, err
		}
		if b.Header.Type == erasure.Type {
			out = append(out, b)
		}
	}
	return out, nil
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
