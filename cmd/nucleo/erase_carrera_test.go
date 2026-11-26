//go:build testhooks

package main

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// El patrón de H1 (revisión del 2026-11-25) en `erase` (Sprint 40): lo que erase decide con
// el estado del ledger —la última copia del contenido, si ya está suprimido, qué
// regulariza— lo decide ANTES de desbloquear el vault y de la confirmación tecleada, y otro
// proceso puede sellar entretanto. Cada test fija una intercalación con el gancho
// erase:desbloqueado.

// ordenEnSubproceso lanza `nucleo --dir DIR <args>` como proceso aparte, con las variables
// de entorno extra dadas; stdout y stderr van juntos a la salida devuelta.
func ordenEnSubproceso(t *testing.T, dir string, args []string, extra ...string) (*exec.Cmd, *strings.Builder) {
	t.Helper()
	raw, _ := json.Marshal(append([]string{"--dir", dir}, args...))
	cmd := exec.Command(os.Args[0], "-test.run=^TestSubprocesoCLI$")
	cmd.Env = append(append(os.Environ(), envSubprocesoCLI+"="+string(raw)), extra...)
	var salida strings.Builder
	cmd.Stdout, cmd.Stderr = &salida, &salida
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	return cmd, &salida
}

// eraseDetenido lanza el erase dado y espera a que llegue a erase:desbloqueado. Devuelve
// el proceso, su salida y la función que lo deja seguir.
func eraseDetenido(t *testing.T, dir string, args ...string) (*exec.Cmd, *strings.Builder, func()) {
	t.Helper()
	barrera := t.TempDir() + "/sigue"
	cmd, salida := ordenEnSubproceso(t, dir, append([]string{"erase"}, args...), envPauseAt+"=erase:desbloqueado="+barrera)
	for i := 0; ; i++ {
		if _, err := os.Stat(barrera + ".llego"); err == nil {
			break
		}
		if i > 3000 {
			t.Fatalf("erase no llegó a erase:desbloqueado:\n%s", salida.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
	return cmd, salida, func() {
		if err := os.WriteFile(barrera, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// codigoDe es el código de salida de un proceso que ya terminó.
func codigoDe(err error) int {
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode()
	}
	if err != nil {
		return -1
	}
	return 0
}

// TestEraseCarreraConUnaCopiaNueva: mientras erase desbloquea, otro proceso vuelve a sellar
// el mismo contenido (bloque 1, que comparte la copia cifrada). La autorización llega hasta
// el bloque 0: borrar la copia suprimiría la del bloque 1 sin autorización. erase tiene que
// negarse, sin escribir, como se niega en secuencia (TestLaAutorizacionNoCubreUnaCopiaPosterior).
func TestEraseCarreraConUnaCopiaNueva(t *testing.T) {
	c := newCLI(t)
	sp := c.initConSupresion(t)
	const venta = `{"venta":"001","cliente":"María Pérez"}`
	c.sealFile(venta)
	h0, _ := contenidoDe(t, c.dir, 0)
	auth := c.autoriza(t, sp, h0, 0)

	cmd, salida, sigue := eraseDetenido(t, c.dir, "--block", "0", "--policy-file", sp.politica,
		"--authorization", auth, "--assume-confirmed")
	c.sealFile(venta) // la misma, otra vez: bloque 1, con la copia cifrada compartida
	sigue()
	if code := codigoDe(cmd.Wait()); code != exitUsage {
		t.Fatalf("erase con una copia nueva sin autorizar: código %d, want %d\n%s", code, exitUsage, salida.String())
	}
	if !strings.Contains(salida.String(), "volvió a sellar este contenido") || !strings.Contains(salida.String(), "--through 1") {
		t.Errorf("no explica la copia nueva ni qué pedir:\n%s", salida.String())
	}
	if _, ct := contenidoDe(t, c.dir, 1); ct == nil {
		t.Error("la copia cifrada de la venta ya no está: se suprimió sin autorización para el bloque 1")
	}
	if n := bloques(t, c.dir); n != 2 {
		t.Errorf("%d bloques, want 2: se selló un evento", n)
	}
}

// TestEraseCarreraDosSupresiones: dos erase del mismo bloque con la misma autorización. El
// segundo, detenido mientras el primero termina, contesta already_erased con el evento del
// primero, sin sellar un evento redundante.
func TestEraseCarreraDosSupresiones(t *testing.T) {
	c := newCLI(t)
	sp := c.initConSupresion(t)
	c.sealFile(`{"venta":"001"}`)
	h0, _ := contenidoDe(t, c.dir, 0)
	args := []string{"--json", "erase", "--block", "0", "--policy-file", sp.politica,
		"--authorization", c.autoriza(t, sp, h0, 0), "--assume-confirmed"}

	cmd, salida, sigue := eraseDetenido(t, c.dir, args[2:]...)
	var primero struct {
		Index         uint64 `json:"index"`
		Hash          string `json:"hash"`
		AlreadyErased bool   `json:"already_erased"`
	}
	if err := json.Unmarshal([]byte(c.mustRun(args...)), &primero); err != nil || primero.AlreadyErased || primero.Index != 1 {
		t.Fatalf("el primer erase: %+v (%v)", primero, err)
	}
	sigue()
	if err := cmd.Wait(); err != nil {
		t.Fatalf("el segundo erase falló (%v):\n%s", err, salida.String())
	}
	if !strings.Contains(salida.String(), "ya estaba suprimido (evento en el bloque 1)") {
		t.Errorf("el segundo erase no dice que ya estaba suprimido:\n%s", salida.String())
	}
	if n := bloques(t, c.dir); n != 2 {
		t.Errorf("%d bloques, want 2: dos eventos de supresión del mismo contenido", n)
	}
}

// TestEraseCarreraNoRegularizaSinAvisar: mientras erase desbloquea con la política de la
// clave A —y sin nada que regularizar, así que no avisó de nada—, otro proceso suprime el
// mismo contenido con una autorización de la clave B. Para la política de A ese evento no
// está autorizado, y el evento de A lo regularizaría: ratificar un borrado que nadie avisó
// (ADR-033, decisión 4). erase tiene que negarse, sin escribir; repetido, lo avisa y sella.
func TestEraseCarreraNoRegularizaSinAvisar(t *testing.T) {
	c := newCLI(t)
	sp := c.initConSupresion(t) // las tarjetas del entorno son las de la clave A
	c.sealFile(`{"venta":"001"}`)
	h0, _ := contenidoDe(t, c.dir, 0)
	authA := c.autoriza(t, sp, h0, 0)

	claveB, tarjetasB := nuevaClaveDeSupresion(t, c)
	raw, _ := os.ReadFile(sp.politica)
	var p map[string]any
	if err := json.Unmarshal(raw, &p); err != nil {
		t.Fatal(err)
	}
	p["erasureKey"] = claveB
	raw, _ = json.Marshal(p)
	spB := *sp
	spB.politica = filepath.Join(c.dir, "politica-b.json")
	if err := os.WriteFile(spB.politica, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(envCards, tarjetasB[0]+"|"+tarjetasB[1])
	authB := c.autoriza(t, &spB, h0, 0)

	cmd, salida, sigue := eraseDetenido(t, c.dir, "--block", "0", "--policy-file", sp.politica,
		"--authorization", authA, "--assume-confirmed")
	c.mustRun("erase", "--block", "0", "--policy-file", spB.politica, "--authorization", authB, "--assume-confirmed")
	sigue()
	if code := codigoDe(cmd.Wait()); code != exitUsage {
		t.Fatalf("erase que regularizaría sin avisar: código %d, want %d\n%s", code, exitUsage, salida.String())
	}
	if !strings.Contains(salida.String(), "lo regularizaría sin haberlo avisado") {
		t.Errorf("no explica la regularización sin aviso:\n%s", salida.String())
	}
	if n := bloques(t, c.dir); n != 2 {
		t.Fatalf("%d bloques, want 2: se selló el evento que regulariza", n)
	}
	// Repetida, la orden avisa de lo que regulariza antes de sellar, y sella.
	_, errOut := c.runWant(t, exitOK, "erase", "--block", "0", "--policy-file", sp.politica,
		"--authorization", authA, "--assume-confirmed")
	if !strings.Contains(errOut, "esto REGULARIZA la supresión no autorizada del evento 1") {
		t.Errorf("la orden repetida no avisa de lo que regulariza:\n%s", errOut)
	}
}
