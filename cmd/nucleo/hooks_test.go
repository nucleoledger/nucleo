package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestProductionBinaryRefusesHooks compila un binario SIN el tag `testhooks`
// —exactamente como lo hace goreleaser— y comprueba dos cosas distintas:
//
//  1. Que el código que honra los ganchos NO está dentro. Se busca una cadena
//     que solo existe en hooks_on.go.
//  2. Que definir un gancho ABORTA en vez de avisar.
//
// La segunda importa más de lo que parece. Un aviso por stderr deja al usuario
// creyendo que puso una semilla determinista y que funcionó, cuando ha hecho lo
// contrario de lo que cree: el binario generaría claves aleatorias y el aviso se
// perdería en un log. Abortar convierte una confusión silenciosa en un error que
// hay que resolver.
//
// Nótese lo que este test NO exige: que los NOMBRES de las variables estén
// ausentes del binario. No pueden estarlo. Para rechazar una variable hay que
// conocer su nombre, así que las constantes viven fuera del build tag a
// propósito. Lo que no está es el código que las obedece.
func TestProductionBinaryRefusesHooks(t *testing.T) {
	if testing.Short() {
		t.Skip("compila un binario; se salta en -short")
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "nucleo-prod"+exeSuffix())

	build := exec.Command("go", "build", "-trimpath", "-ldflags", "-s -w", "-o", bin, ".")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("no se pudo compilar el binario de producción: %v\n%s", err, out)
	}
	// Que el fichero esté DONDE se pidió no es obvio en Windows, y darlo por
	// hecho costó un CI en rojo: ver exeSuffix.
	if _, err := os.Stat(bin); err != nil {
		t.Fatalf("go build no dejó el binario en %q: %v", bin, err)
	}

	raw, err := os.ReadFile(bin)
	if err != nil {
		t.Fatal(err)
	}
	// Cadena exclusiva de hooks_on.go. Si aparece, el tag se coló.
	const marcaDeGanchos = "HONRA los ganchos de prueba"
	if strings.Contains(string(raw), marcaDeGanchos) {
		t.Errorf("el binario de producción contiene el código de los ganchos (%q)", marcaDeGanchos)
	}
	// Control: la cadena del RECHAZO sí tiene que estar, o el test de arriba
	// pasaría también con un binario que no comprueba nada.
	const marcaDeRechazo = "este binario no lo admite"
	if !strings.Contains(string(raw), marcaDeRechazo) {
		t.Fatalf("el binario no contiene el mensaje de rechazo (%q): el test no prueba nada", marcaDeRechazo)
	}

	for _, v := range hookVars {
		t.Run(v, func(t *testing.T) {
			cmd := exec.Command(bin, "--dir", dir, "status")
			cmd.Env = append(os.Environ(), v+"=x")
			out, err := cmd.CombinedOutput()
			// Primero: que el proceso HAYA ARRANCADO. Si no arranca,
			// ProcessState es nil y ExitCode() devuelve -1 en vez de entrar en
			// pánico, así que el test fallaría con "código = -1, want 1" y con
			// una salida vacía: tres errores confusos que no señalan la causa.
			// Este mensaje sí la señala.
			if cmd.ProcessState == nil {
				t.Fatalf("el binario ni siquiera arrancó (%v). No es un fallo de la comprobación de ganchos: es que %q no se pudo ejecutar.", err, bin)
			}
			if err == nil {
				t.Fatalf("el binario de producción aceptó %s:\n%s", v, out)
			}
			if code := cmd.ProcessState.ExitCode(); code != exitUsage {
				t.Errorf("código = %d, want %d", code, exitUsage)
			}
			if !strings.Contains(string(out), "no lo admite") {
				t.Errorf("el mensaje no explica el rechazo:\n%s", out)
			}
		})
	}

	// Y sin ganchos definidos, el mismo binario funciona.
	cmd := exec.Command(bin, "help")
	cmd.Env = filterHookVars(os.Environ())
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Errorf("el binario de producción falla sin ganchos: %v\n%s", err, out)
	}
}

// filterHookVars quita del entorno cualquier variable de gancho, para que el
// entorno del propio test no contamine al subproceso.
func filterHookVars(env []string) []string {
	var out []string
	for _, kv := range env {
		esGancho := false
		for _, v := range hookVars {
			if strings.HasPrefix(kv, v+"=") {
				esGancho = true
			}
		}
		if !esGancho {
			out = append(out, kv)
		}
	}
	return out
}

// exeSuffix devuelve ".exe" en Windows y "" en el resto.
//
// `go build -o <nombre>` toma el nombre LITERALMENTE: cmd/go solo añade el
// sufijo del ejecutable cuando NO se pasa -o. En Windows eso deja un fichero sin
// extensión que os/exec no encuentra, porque su búsqueda prueba <nombre>.com,
// .exe, .bat y .cmd y ninguno existe. El proceso no llega a arrancar.
//
// Cuesta verlo porque el fallo no se parece a su causa: exec devuelve un error,
// ProcessState queda en nil, ExitCode() responde -1 sin entrar en pánico, y el
// test se queja de un código de salida equivocado sobre un proceso que nunca
// existió.
func exeSuffix() string {
	if runtime.GOOS == "windows" {
		return ".exe"
	}
	return ""
}
