//go:build testhooks

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"
)

// H1 de la revisión adversarial del 2026-11-25: dos `nucleo void --block N` a la vez.
//
// La primera comprobación de R6 se hacía antes de desbloquear el vault —Argon2id, el paso
// lento— y no se repetía al sellar. Dos órdenes que pasaran las dos esa comprobación antes
// de que ninguna sellara dejaban DOS anulaciones del mismo bloque: la segunda, para siempre
// en una cadena append-only, y reconcile la denunciaría como «anulación repetida» con
// código 2. G62 promete una sola.

// voidEnSubproceso lanza `nucleo --dir DIR --json void --block N` como proceso aparte, con
// las variables de entorno extra dadas.
func voidEnSubproceso(t *testing.T, dir string, block int, extra ...string) (*exec.Cmd, *strings.Builder) {
	t.Helper()
	args, _ := json.Marshal([]string{"--dir", dir, "--json", "void", "--block", fmt.Sprint(block)})
	cmd := exec.Command(os.Args[0], "-test.run=^TestSubprocesoCLI$")
	cmd.Env = append(append(os.Environ(), envSubprocesoCLI+"="+string(args)), extra...)
	var salida strings.Builder
	cmd.Stdout = &salida
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	return cmd, &salida
}

// TestVoidCarreraDeterminista fija la intercalación de H1 con el gancho void:comprobado:
// la orden A pasa la primera comprobación de R6 y se detiene; la B anula el bloque entera;
// A sigue. A tiene que contestar already_voided con el evento de B, sin sellar otro.
func TestVoidCarreraDeterminista(t *testing.T) {
	c := newCLI(t)
	c.initLedger()
	c.sealFile(facturaA)
	c.sealFile(facturaB)

	barrera := t.TempDir() + "/sigue"
	a, salidaA := voidEnSubproceso(t, c.dir, 1, envPauseAt+"=void:comprobado="+barrera)
	for i := 0; ; i++ {
		if _, err := os.Stat(barrera + ".llego"); err == nil {
			break
		}
		if i > 3000 {
			t.Fatalf("la orden A no llegó a void:comprobado:\n%s", salidaA.String())
		}
		time.Sleep(20 * time.Millisecond)
	}

	b := leeSalidaVoid(t, c.mustRun("--json", "void", "--block", "1"))
	if *b.AlreadyVoided || b.Index != 2 {
		t.Fatalf("la orden B tenía que sellar el evento en el bloque 2: %+v", b)
	}

	if err := os.WriteFile(barrera, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := a.Wait(); err != nil {
		t.Fatalf("la orden A falló (%v):\n%s", err, salidaA.String())
	}
	ra := leeSalidaVoid(t, salidaA.String())
	if !*ra.AlreadyVoided || ra.Index != 2 || ra.Hash != b.Hash {
		t.Errorf("la orden A, tras la de B: %+v; want already_voided con el evento del bloque 2", ra)
	}
	if n := bloques(t, c.dir); n != 3 {
		t.Errorf("%d bloques, want 3: dos anulaciones del mismo bloque (H1)", n)
	}

	// Y reconcile lo confirma: una anulación, ningún hallazgo, código 0.
	out, _ := c.runWant(t, 0, "--json", "reconcile", "--source", vivosDe(t, c.dir, map[uint64]string{0: facturaA, 1: facturaB}))
	var inf informeVoided
	if err := json.Unmarshal([]byte(out), &inf); err != nil {
		t.Fatal(err)
	}
	if !inf.OK || len(inf.Findings) != 0 || len(inf.Voided) != 1 {
		t.Errorf("reconcile tras la carrera: %+v", inf)
	}
}

// TestVoidCarreraConcurrente: dos procesos de verdad lanzan `void --block N` a la vez, sin
// gancho que los ordene, sobre cincuenta facturas. En cada una, exactamente un evento
// sellado; la otra orden contesta already_voided con ese mismo evento.
func TestVoidCarreraConcurrente(t *testing.T) {
	if testing.Short() {
		t.Skip("cien procesos: no en -short")
	}
	const n = 50
	c := newCLI(t)
	c.initLedger()
	for i := 0; i < n; i++ {
		c.sealFile(fmt.Sprintf(`{"factura":"%03d"}`, i))
	}

	selladasPorA := 0
	for i := 0; i < n; i++ {
		var wg sync.WaitGroup
		var cmds [2]*exec.Cmd
		var salidas [2]*strings.Builder
		var errs [2]error
		for k := range cmds {
			cmds[k], salidas[k] = voidEnSubproceso(t, c.dir, i)
		}
		for k := range cmds {
			wg.Add(1)
			go func(k int) { defer wg.Done(); errs[k] = cmds[k].Wait() }(k)
		}
		wg.Wait()
		var rs [2]salidaVoid
		for k := range cmds {
			if errs[k] != nil {
				t.Fatalf("factura %d, orden %d: %v\n%s", i, k, errs[k], salidas[k].String())
			}
			rs[k] = leeSalidaVoid(t, salidas[k].String())
		}
		nuevas := 0
		for k, r := range rs {
			if !*r.AlreadyVoided {
				nuevas++
				if k == 0 {
					selladasPorA++
				}
			}
		}
		if nuevas != 1 || rs[0].Hash != rs[1].Hash || rs[0].VoidedIndex != uint64(i) {
			t.Fatalf("factura %d: %d anulaciones selladas, want 1: %+v / %+v", i, nuevas, rs[0], rs[1])
		}
	}
	if got := bloques(t, c.dir); got != 2*n {
		t.Errorf("%d bloques, want %d: %d facturas y una anulación de cada una", got, 2*n, n)
	}
	t.Logf("%d carreras: un evento en cada una; la primera orden lanzada selló %d veces y la segunda %d", n, selladasPorA, n-selladasPorA)
}
