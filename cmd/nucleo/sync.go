package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/nucleoledger/nucleo/internal/logsync"
	"github.com/nucleoledger/nucleo/internal/store"
	"github.com/nucleoledger/nucleo/internal/witness"
)

func cmdSync(e *env, args []string) error {
	fs := flag.NewFlagSet("sync", flag.ContinueOnError)
	fs.SetOutput(e.stderr)
	url := fs.String("witness", "", "URL del testigo")
	pf := registerPolicyFlags(fs)
	passFile := fs.String("passphrase-file", "", "fichero con la passphrase")
	timeout := fs.Duration("timeout", 30*time.Second, "tiempo máximo de espera")
	if err := fs.Parse(args); err != nil {
		return usageErr("%v", err)
	}
	if *url == "" {
		return usageErr("sync necesita --witness URL")
	}
	// La URL se comprueba ANTES de tocar la red: una errata es un error de uso (código
	// 1) y no un incidente del testigo (código 3). Con el código 3, un cron que
	// reintenta ante incidentes reintentaría para siempre una URL que nunca va a
	// funcionar (ensayo de operación del Sprint 10, escenario 3).
	if err := validaURLDeTestigo(*url); err != nil {
		return err
	}
	wp, file, err := pf.resolve(e)
	if err != nil {
		return err
	}
	if wp == nil {
		return usageErr("sync necesita el testigo: --policy-file, o --witness-name y --witness-key")
	}
	// sync habla con UN testigo. Con un fichero de varios habría que elegir, y
	// elegir en silencio es peor que pedirlo.
	if len(wp.Witnesses) != 1 {
		return usageErr("sync necesita exactamente un testigo en la política; este fichero trae %d", len(wp.Witnesses))
	}
	var name string
	var pub ed25519.PublicKey
	for n, k := range wp.Witnesses {
		name, pub = n, k
	}
	client, err := witness.NewClient(*url, name, pub)
	if err != nil {
		return usageErr("%v", err)
	}

	s, apertura, err := e.openStoreWith(wp)
	if err != nil {
		return err
	}
	defer s.Close()

	v, id, err := e.unlock(s, *passFile, "Passphrase del vault: ")
	if err != nil {
		return err
	}
	// Antes de hablar con el testigo: una vez cosignada, su memoria protege la
	// historia que se le enseñó, sea la propia o una ajena.
	if err := checkChainSigner(apertura, id, "sincroniza"); err != nil {
		v.Close()
		return err
	}
	if file != nil {
		if err := checkPolicyMatchesLedger(file, id.Origin, id.LogPublic(), id.TenantPublic()); err != nil {
			return err
		}
	}
	defer v.Close()

	lg, err := id.NewLog()
	if err != nil {
		return err
	}
	adapter, err := logsync.NewStoreLog(s, lg)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	res, err := logsync.SyncWithWitness(ctx, adapter, client)
	if err != nil {
		// Un rollback detectado NO es un fallo de sincronización: es un
		// resultado, y de los graves. Sale por el código 2, el de verificación,
		// porque lo que ha fallado es la integridad de la historia local.
		var rb *logsync.RollbackError
		if errors.As(err, &rb) {
			// La alarma se GUARDA antes de imprimirla. En el ensayo de operación del
			// Sprint 10 se restauró un respaldo viejo, sync lo cazó… y el siguiente
			// `status` decía "✔ historia atestiguada hasta 1322 de 1322": la única
			// alarma vivía en la salida de un cron que nadie lee. Ahora dura lo que
			// dure el problema (store.RollbackKey).
			if errGuardar := s.PutRollback(store.RollbackRecord{
				At:          now().UTC().Format(time.RFC3339),
				LocalSize:   rb.LocalSize,
				WitnessSize: rb.WitnessSize,
				Witness:     name,
			}); errGuardar != nil {
				fmt.Fprintf(e.stderr, "AVISO: no se pudo dejar constancia del rollback: %v\n", errGuardar)
			}
			if !e.json {
				e.printf("\n")
			}
			e.out(map[string]any{
				"ok": false, "rollback": true,
				"local_size": rb.LocalSize, "witness_size": rb.WitnessSize,
			}, func() {
				e.printf("✘ ROLLBACK LOCAL DETECTADO\n")
				e.printf("    en disco          : %d bloques\n", rb.LocalSize)
				e.printf("    el testigo cosignó: %d bloques\n", rb.WitnessSize)
				e.printf("    faltan            : %d bloques\n\n", rb.WitnessSize-rb.LocalSize)
				e.printf("  El testigo conserva su cosignature de un árbol mayor que el que\n")
				e.printf("  hay en este disco. Una de las dos cosas es mentira, y la que está\n")
				e.printf("  firmada por un tercero no es la que se puede reescribir aquí.\n\n")
				e.printf("  QUÉ HACER\n")
				e.printf("  · Si acabas de restaurar un respaldo: ese respaldo es ANTERIOR a lo que el\n")
				e.printf("    testigo ya vio. Busca una copia más reciente del ledger; la que tienes\n")
				e.printf("    delante le faltan %d bloques.\n", rb.WitnessSize-rb.LocalSize)
				e.printf("  · NO sigas sellando en este fichero: cada bloque nuevo se aparta más de la\n")
				e.printf("    historia que el testigo atestiguó, y luego no hay forma de juntarlas.\n")
				e.printf("  · Si no restauraste nada, alguien reescribió este fichero. Guarda una copia\n")
				e.printf("    tal como está antes de tocar nada: es la evidencia.\n")
				e.printf("  · Queda constancia en el propio ledger, así que `status` y `verify` lo\n")
				e.printf("    seguirán diciendo hasta que una sincronización vuelva a cuadrar.\n")
			})
			return &exitError{code: exitVerify, err: rb, reported: true}
		}
		// El testigo no contesta, y este es EL momento de la alarma de frescura: el
		// cron que lo intenta suele tirar stderr y el código de salida. Se juzga con lo
		// que se abrió —antes de hablar con el testigo, que no ha cambiado nada— y la
		// alarma viaja en el propio objeto de error (ADR-028 §C y §D).
		ee := errorDeTestigo(*url, err)
		if st, errSt := checkStaleness(s, apertura, wp != nil, now(), e.staleAfter, apertura.TreeSize); errSt == nil {
			ee = ee.conExtra("alert", registraAlarma(e, s, st).json())
		}
		return ee
	}

	// Aquí, y solo aquí, se graba cuándo avaló un tercero este log: es el único
	// punto del programa que acaba de VERIFICAR una cosignature contra la clave
	// del testigo. Guardarlo es lo que permite que `status` y `seal` respondan
	// "hace cuánto" sin volver a pedir la clave en cada invocación, que es la
	// razón por la que ese chequeo no se haría nunca.
	// Una cosignature que el testigo emitió hace mucho no prueba contacto con él
	// AHORA (H2 de la cuarta auditoría): con el log parado, reproducir la respuesta
	// del POST da una sincronización que termina en ✔ sin que nadie haya hablado con
	// el testigo. Lo único que la delata es este instante, que no avanza. Aquí se
	// dice, en vez de esperar a que la frescura lo note en el siguiente status: es lo
	// que convierte un ataque silencioso en uno ruidoso.
	umbral := umbralDeReplay(e.staleAfter)
	edad := now().Sub(res.AttestedAt)
	vieja := res.Attested && edad > umbral
	if vieja {
		fmt.Fprintf(e.stderr,
			"AVISO: el testigo devolvió una cosignature de hace %s (umbral: %s).\n"+
				"       Una cosignature vieja no prueba contacto con el testigo ahora: una\n"+
				"       respuesta reproducida por la red se ve exactamente así mientras el\n"+
				"       log no crezca. Comprueba que llegas al testigo de verdad.\n",
			humanDuration(edad), humanDuration(umbral))
	}
	// Una sincronización que sale bien es la ÚNICA forma de resolver un rollback
	// registrado: significa que este ledger ya no es un prefijo truncado de lo que el
	// testigo atestiguó. Se borra aquí y no en ningún otro sitio, para que la alarma no
	// se pueda apagar sin arreglar el problema.
	if previo, hay, err := s.Rollback(); err == nil && hay && res.LocalSize >= previo.WitnessSize {
		if err := s.ClearRollback(); err != nil {
			fmt.Fprintf(e.stderr, "AVISO: no se pudo borrar el registro de rollback ya resuelto: %v\n", err)
		} else if !e.json {
			e.printf("  (el rollback que constaba del %s queda resuelto: %d bloques cubren los %d que el testigo recordaba)\n",
				previo.At, res.LocalSize, previo.WitnessSize)
		}
	}

	if res.Attested {
		// La nota entera como evidencia verificable de contacto reciente (H6): el
		// checkpoint guardado es el PRIMERO de su tamaño —el tiempo demostrable es el
		// mínimo— y con el log parado no avanza nunca.
		if err := s.PutLastCosignature(res.Cosigned); err != nil {
			return err
		}
		if err := s.PutLastAttested(store.AttestationRecord{
			Witness:    name,
			At:         res.AttestedAt,
			Size:       res.LocalSize,
			RecordedAt: now(),
		}); err != nil {
			return err
		}
	}

	// Una cosignature verificada y que no nace vieja es atestación fresca: la alarma, si
	// la había, deja de tener motivo y se cierra aquí (ADR-028 §C). Una que ya nacía vieja
	// no cierra nada: es justo la que un replay por la red devolvería.
	alarma := leeAlarma(e, s)
	cerrada := store.StaleAlarm{}
	if res.Attested && !vieja && alarma.Estado != alarmaNinguna {
		cerrada = alarma.Registro
		alarma = cierraAlarma(e, s, alarma.Registro)
	}

	e.out(map[string]any{
		"origin":       res.Origin,
		"local_size":   res.LocalSize,
		"witness_size": res.WitnessSize,
		"attested":     res.Attested,
		"attested_at":  res.AttestedAt.UTC().Format(time.RFC3339),
		"first_time":   res.Fresh,
		// replay_suspect: la cosignature que devolvió el testigo ya nacía vieja.
		"replay_suspect": vieja,
		// La política lista para guardar: lo que hace falta para volver a abrir
		// este ledger con atestación verificada, y lo mismo que la contraparte
		// necesita para verificar sus recibos (ADR-017 c).
		"policy": jsonPolicy(id.Origin, id.LogPublic(), id.TenantPublic(), name, pub),
		"alert":  alarma.json(),
	}, func() {
		e.printf("✔ atestación obtenida del testigo %s\n", name)
		e.printf("  origin  : %s\n", res.Origin)
		e.printf("  bloques : %d\n", res.LocalSize)
		e.printf("  tiempo  : %s (lo afirma el testigo, no este reloj)\n",
			res.AttestedAt.UTC().Format(time.RFC3339))
		if cerrada.EmittedAt != "" && alarma.Estado == alarmaNinguna {
			e.printf("  (la alarma de frescura, abierta el %s, queda cerrada)\n", cerrada.EmittedAt)
		}
		if res.Fresh {
			e.printf("  (era el primer checkpoint de este log para ese testigo)\n")
		} else if res.WitnessSize < res.LocalSize {
			e.printf("  (extensión de %d a %d, con prueba de consistencia)\n", res.WitnessSize, res.LocalSize)
		}
		// Si ya vino de fichero, quien lo invocó ya lo tiene; si no, se le da hecho.
		if file == nil {
			policySnippet(e, id.Origin, id.LogPublic(), id.TenantPublic(), name, pub)
		}
	})
	return nil
}

// MaxEdadCosignature es el umbral del aviso de replay: cuánto puede tener la
// cosignature que un testigo acaba de devolver antes de resultar sospechosa.
//
// Nació igual al umbral de frescura (72 h por omisión) y eso era 288 veces demasiado
// holgado: un testigo vivo firma en el momento, así que lo que vuelve de un POST tiene
// segundos. Lo único que justifica una diferencia es el desfase de reloj entre el
// testigo y quien sella —minutos en máquinas sin NTP— más la red. Quince minutos deja
// pasar ese desfase y cierra la ventana en la que un replay pasaba callado: antes,
// reproducir una respuesta de hace un día no decía nada hasta el siguiente status.
//
// No es criptografía, es operación, y por eso el operador puede apretarlo con
// --stale-after: si su umbral de frescura es MENOR que este, manda el suyo.
const MaxEdadCosignature = 15 * time.Minute

// umbralDeReplay devuelve el menor entre el umbral fijo y el de frescura.
func umbralDeReplay(staleAfter time.Duration) time.Duration {
	if staleAfter < MaxEdadCosignature {
		return staleAfter
	}
	return MaxEdadCosignature
}

func cmdWitness(e *env, args []string) error {
	if len(args) > 0 && args[0] == "key" {
		return cmdWitnessKey(e, args[1:])
	}
	if len(args) == 0 || args[0] != "serve" {
		return usageErr("uso:\n" +
			"  nucleo witness serve --addr :8080 --db testigo.db --name w --log-origin O --log-key HEX\n" +
			"  nucleo witness key --db testigo.db")
	}
	fs := flag.NewFlagSet("witness serve", flag.ContinueOnError)
	fs.SetOutput(e.stderr)
	addr := fs.String("addr", "127.0.0.1:8080", "dirección donde escuchar")
	db := fs.String("db", "", "base de datos del testigo (su memoria)")
	logOrigin := fs.String("log-origin", "", "origin del log al que sirve")
	logKey := fs.String("log-key", "", "clave pública de ese log, en hexadecimal")
	name := fs.String("name", "", "nombre de este testigo, p. ej. witness.example/w1")
	if err := fs.Parse(args[1:]); err != nil {
		return usageErr("%v", err)
	}
	switch {
	case *db == "":
		return usageErr("witness serve necesita --db")
	case *name == "":
		return usageErr("witness serve necesita --name")
	case *logOrigin == "" || *logKey == "":
		return usageErr("witness serve necesita --log-origin y --log-key")
	}
	pub, err := hexKey(*logKey)
	if err != nil {
		return err
	}
	st, err := witness.OpenState(*db)
	if err != nil {
		return err
	}
	defer st.Close()

	priv, created, err := witnessKey(*db + ".key")
	if err != nil {
		return err
	}
	w, err := witness.NewWithState(*name, priv, now, st)
	if err != nil {
		return err
	}
	if err := w.AddLog(*logOrigin, pub); err != nil {
		return err
	}

	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		return usageErr("no se pudo escuchar en %q: %v", *addr, err)
	}
	defer ln.Close()

	e.printf("testigo %s escuchando en http://%s\n", *name, ln.Addr())
	e.printf("  memoria    : %s\n", *db)
	e.printf("  clave      : %s\n", hexOf(priv.Public().(ed25519.PublicKey)))
	if created {
		e.printf("  (clave nueva, guardada junto a la memoria; si la pierdes, tus\n")
		e.printf("   cosignatures anteriores dejan de poder verificarse)\n")
	}
	e.printf("  log servido: %s\n", *logOrigin)
	e.printf("\nCtrl-C para parar.\n")

	srv := &http.Server{Handler: witness.NewServer(w).Handler()}
	done := make(chan os.Signal, 1)
	signal.Notify(done, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-done
		srv.Close()
	}()
	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	e.printf("testigo detenido\n")
	return nil
}

// witnessKey carga la clave del testigo o la crea la primera vez.
//
// Vive junto a su memoria porque las dos cosas son la identidad del testigo: sin
// la clave, las cosignatures que ya emitió no se pueden verificar, y sin la
// memoria no sabe qué avaló. Perder cualquiera de las dos lo inutiliza.
//
// Es una CLAVE PRIVADA en un fichero, así que se trata como tal:
//
//   - Se crea con O_EXCL. No hay leer-y-después-escribir: entre esas dos
//     operaciones cabe otro proceso creando el fichero, y el segundo en escribir
//     dejaría al testigo con una clave distinta de la que el primero ya usó para
//     cosignar. Con O_EXCL, el que llega tarde recibe un error en vez de pisar.
//   - Se crea con permisos 0600 y se comprueba que un fichero YA EXISTENTE no
//     sea legible por otros. Un testigo cuya clave privada puede leer cualquier
//     usuario de la máquina no atestigua nada: quien la lea puede firmar en su
//     nombre.
func witnessKey(path string) (ed25519.PrivateKey, bool, error) {
	// Primero se intenta CREAR en exclusiva. Si el fichero ya está, se lee; si
	// no, se acaba de crear y nadie más pudo ganarnos la carrera.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	switch {
	case err == nil:
		defer f.Close()
		seed := make([]byte, ed25519.SeedSize)
		if s, ok := hookSeed(); ok {
			copy(seed, s)
		} else if _, err := rand.Read(seed); err != nil {
			return nil, false, err
		}
		if _, err := f.Write([]byte(hex.EncodeToString(seed))); err != nil {
			return nil, false, err
		}
		if err := f.Sync(); err != nil {
			return nil, false, err
		}
		return ed25519.NewKeyFromSeed(seed), true, nil

	case !errors.Is(err, os.ErrExist):
		return nil, false, usageErr("no se pudo crear la clave del testigo en %q: %w", path, err)
	}

	// El fichero ya existe: se comprueban sus permisos antes de usarlo.
	if err := checkKeyPerms(path); err != nil {
		return nil, false, err
	}
	raw, err := readLimited(path, maxKeyFile, "la clave del testigo")
	if err != nil {
		return nil, false, err
	}
	seed, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, false, usageErr("la clave del testigo en %q no es válida: se esperan %d bytes en hexadecimal",
			path, ed25519.SeedSize)
	}
	return ed25519.NewKeyFromSeed(seed), false, nil
}

// cmdWitnessKey imprime la clave pública del testigo.
//
// Existe porque la alternativa era leerla del stdout de `witness serve` con
// awk, y un dato que hace falta para configurar a la otra parte no puede vivir
// solo en un mensaje de arranque. Un testigo que no puede publicar su clave de
// forma legible no sirve de nada: sin ella, nadie puede verificar lo que firma.
func cmdWitnessKey(e *env, args []string) error {
	fs := flag.NewFlagSet("witness key", flag.ContinueOnError)
	fs.SetOutput(e.stderr)
	db := fs.String("db", "", "base de datos del testigo")
	if err := fs.Parse(args); err != nil {
		return usageErr("%v", err)
	}
	if *db == "" {
		return usageErr("witness key necesita --db")
	}
	priv, created, err := witnessKey(*db + ".key")
	if err != nil {
		return err
	}
	pub := hexOf(priv.Public().(ed25519.PublicKey))
	e.out(map[string]any{"public_key": pub, "created": created}, func() {
		e.printf("%s\n", pub)
	})
	return nil
}
