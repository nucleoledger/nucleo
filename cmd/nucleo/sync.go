package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/nucleoledger/nucleo/internal/logsync"
	"github.com/nucleoledger/nucleo/internal/witness"
)

func cmdSync(e *env, args []string) error {
	fs := flag.NewFlagSet("sync", flag.ContinueOnError)
	fs.SetOutput(e.stderr)
	url := fs.String("witness", "", "URL del testigo")
	name := fs.String("witness-name", "", "nombre del testigo")
	key := fs.String("witness-key", "", "clave pública del testigo, en hexadecimal")
	passFile := fs.String("passphrase-file", "", "fichero con la passphrase")
	timeout := fs.Duration("timeout", 30*time.Second, "tiempo máximo de espera")
	if err := fs.Parse(args); err != nil {
		return usageErr("%v", err)
	}
	switch {
	case *url == "":
		return usageErr("sync necesita --witness URL")
	case *name == "":
		return usageErr("sync necesita --witness-name")
	case *key == "":
		return usageErr("sync necesita --witness-key HEX")
	}
	pub, err := hexKey(*key)
	if err != nil {
		return err
	}
	client, err := witness.NewClient(*url, *name, pub)
	if err != nil {
		return usageErr("%v", err)
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
				e.printf("  firmada por un tercero no es la que se puede reescribir aquí.\n")
			})
			return &exitError{code: exitVerify, err: rb, reported: true}
		}
		return syncErr("%v", err)
	}

	e.out(map[string]any{
		"origin":       res.Origin,
		"local_size":   res.LocalSize,
		"witness_size": res.WitnessSize,
		"attested":     res.Attested,
		"first_time":   res.Fresh,
	}, func() {
		e.printf("✔ atestación obtenida del testigo %s\n", *name)
		e.printf("  origin  : %s\n", res.Origin)
		e.printf("  bloques : %d\n", res.LocalSize)
		if res.Fresh {
			e.printf("  (era el primer checkpoint de este log para ese testigo)\n")
		} else if res.WitnessSize < res.LocalSize {
			e.printf("  (extensión de %d a %d, con prueba de consistencia)\n", res.WitnessSize, res.LocalSize)
		}
	})
	return nil
}

func cmdWitness(e *env, args []string) error {
	if len(args) == 0 || args[0] != "serve" {
		return usageErr("uso: nucleo witness serve --addr :8080 --db testigo.db")
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
func witnessKey(path string) (ed25519.PrivateKey, bool, error) {
	raw, err := os.ReadFile(path)
	if err == nil {
		seed, err := hex.DecodeString(string(raw[:min(len(raw), 64)]))
		if err != nil || len(seed) != ed25519.SeedSize {
			return nil, false, usageErr("la clave del testigo en %q no es válida", path)
		}
		return ed25519.NewKeyFromSeed(seed), false, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, false, err
	}
	seed := make([]byte, ed25519.SeedSize)
	if s, ok := testSeed(); ok {
		copy(seed, s)
	} else if _, err := rand.Read(seed); err != nil {
		return nil, false, err
	}
	if err := os.WriteFile(path, []byte(hex.EncodeToString(seed)), 0o600); err != nil {
		return nil, false, err
	}
	return ed25519.NewKeyFromSeed(seed), true, nil
}
