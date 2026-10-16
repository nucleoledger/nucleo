package main

import (
	"bufio"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

// La consola de verdad (Sprint 20b, H2/H3 de la revisión del 2026-10-11). El modelo de
// comillas_test.go dice cómo partiría la orden una consola; aquí la parte la consola: las
// órdenes impresas se ejecutan tal cual en PowerShell (Windows) o en sh (POSIX), y el
// programa que reciben, un nucleo de mentira que solo apunta su argv, dice qué llegó.

// envEcoArgv convierte el binario de los tests en ese nucleo de mentira: si está, en
// vez de correr los tests añade su argv, como una línea JSON, al fichero que nombra.
const envEcoArgv = "NUCLEO_TEST_ECO_ARGV"

func TestMain(m *testing.M) {
	if f := os.Getenv(envEcoArgv); f != "" {
		os.Exit(ecoArgv(f))
	}
	os.Exit(m.Run())
}

func ecoArgv(fichero string) int {
	raw, err := json.Marshal(os.Args[1:])
	if err != nil {
		return 9
	}
	f, err := os.OpenFile(fichero, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return 9
	}
	defer f.Close()
	if _, err := f.Write(append(raw, '\n')); err != nil {
		return 9
	}
	return 0
}

// rutasConTrampa son las rutas que han roto, o podrían romper, una orden pegada: las de
// H2 ($HOME, `n) y H3 (%USERNAME%, !x!), las comillas simples recta y tipográfica, lo que
// cmd y sh interpretan, un directorio con la barra final y un nombre no ASCII. En Windows,
// además, los bordes de filepath.Clean (H10 de la revisión del 2026-10-14): la unidad
// sola, una raíz UNC con espacio y \ final —Clean la deja con la \, y es justo la \ que
// antes de una comilla de cierre rompía el argv en PowerShell 5.1—, una ruta relativa con
// .\, y componentes que acaban en espacio y en punto, que Windows recorta al abrir el
// fichero pero que la orden tiene que pasar tal cual.
func rutasConTrampa() []string {
	if runtime.GOOS == "windows" {
		return []string{
			`C:`,
			`\\servidor\mi recurso\`,
			`.\x`,
			`C:\acaba en espacio \p.json`,
			`C:\acaba en punto.\p.json`,
			`C:\con espacio\p.json`,
			`C:\$HOME\p.json`,
			"C:\\foo`nbar\\p.json",
			`C:\it's\p.json`,
			"C:\\it\u2019s\\p.json",
			`C:\%USERNAME%\p.json`,
			`C:\!x!\p.json`,
			`C:\a&b\p.json`,
			`C:\a^b\p.json`,
			`C:\a;b\p.json`,
			`C:\(x)\p.json`,
			`C:\termina en barra\`,
			`C:\año\ñandú\p.json`,
		}
	}
	return []string{
		`/tmp/con espacio/p.json`,
		`/tmp/$HOME/p.json`,
		"/tmp/foo`nbar/p.json",
		`/tmp/it's/p.json`,
		"/tmp/it\u2019s/p.json",
		`/tmp/%USERNAME%/p.json`,
		`/tmp/!x!/p.json`,
		`/tmp/a&b/p.json`,
		`/tmp/a^b/p.json`,
		`/tmp/a;b/p.json`,
		`/tmp/(x)/p.json`,
		`/tmp/termina en barra\`,
		`/tmp/año/ñandú/p.json`,
	}
}

// ordenImpresa es una orden tal como la imprime la CLI y el argv que tiene que llegarle a
// nucleo cuando se pega.
type ordenImpresa struct {
	linea string
	argv  []string
}

// ordenesCon son las órdenes con ruta que imprime la CLI, con ruta en cada sitio donde
// va una. La de erase y la del cron salen de sus funciones; las de init, backup, restore
// y el ledger que no existe se escriben con un printf en su sitio, y aquí se rehacen
// igual: "nucleo --dir " + argShell(dir) + el resto.
func ordenesCon(ruta string) []ordenImpresa {
	// La ruta que llega: en Windows argShell la limpia (la \ final), y es la misma ruta.
	// Por eso el argv esperado es el de la ruta DESPUÉS de filepath.Clean, y no la ruta
	// tal cual: "C:" llega como "C:." (el directorio actual de la unidad C, lo mismo),
	// ".\x" como "x". La raíz UNC, que Clean deja con su \ final porque sin ella no es una
	// raíz, llega con un . detrás: con la \ sola, PowerShell 5.1 partía el argv
	// (rutaWindowsParaImprimir). Lo que este test fija es que la consola entrega a nucleo,
	// byte a byte, lo que argShell quiso entregar; que es la misma ruta lo fija
	// TestRutaWindowsParaImprimir, con los valores escritos a mano.
	llega := ruta
	if runtime.GOOS == "windows" {
		llega = filepath.Clean(ruta)
		if strings.HasSuffix(llega, `\`) {
			llega += "."
		}
	}
	hash := strings.Repeat("ab", 32)
	cron := ordenesProgramadas(ruta)
	return []ordenImpresa{
		{ordenAutorizar(ruta, hash, 7),
			[]string{"erasure-key", "authorize", "--policy-file", llega, "--payload-hash", hash, "--through", "7"}},
		{cron[0], []string{"--dir", llega, "sync", "--witness", "URL", "--policy-file", "politica.json",
			"--passphrase-file", filepath.Clean(rutaPassphraseEjemplo())}},
		{cron[1], []string{"--dir", llega, "status", "--policy-file", "politica.json"}},
		{"nucleo --dir " + argShell(ruta) + " restore --new-passphrase",
			[]string{"--dir", llega, "restore", "--new-passphrase"}},
		{"nucleo init --dir " + argShell(ruta), []string{"init", "--dir", llega}},
		{"nucleo backup --dir " + argShell(ruta), []string{"backup", "--dir", llega}},
	}
}

// consolas son las consolas donde se pegan las órdenes en esta plataforma, como el
// prefijo de la orden que ejecuta una línea. En Windows, powershell.exe (5.1) siempre, y
// pwsh (7) si está: el CI corre en windows-2025, que trae los dos, y allí falta no vale.
func consolas(t *testing.T) map[string][]string {
	t.Helper()
	if runtime.GOOS != "windows" {
		return map[string][]string{"sh": {"sh", "-c"}}
	}
	cs := map[string][]string{}
	if _, err := exec.LookPath("powershell.exe"); err != nil {
		t.Fatalf("no hay powershell.exe, la consola para la que se imprimen las órdenes: %v", err)
	}
	cs["powershell.exe"] = []string{"powershell.exe", "-NoProfile", "-NonInteractive", "-Command"}
	if _, err := exec.LookPath("pwsh"); err == nil {
		cs["pwsh"] = []string{"pwsh", "-NoProfile", "-NonInteractive", "-Command"}
	} else if os.Getenv("CI") != "" {
		t.Errorf("no hay pwsh, y windows-2025 lo trae: %v", err)
	} else {
		t.Log("pwsh no está en esta máquina: solo se prueba powershell.exe")
	}
	return cs
}

// TestLasOrdenesImpresasFuncionanEnLaConsolaDeVerdad: cada orden con ruta que imprime la
// CLI, pegada tal cual en la consola de la plataforma, le llega a nucleo con el argv
// exacto. Ningún $HOME, `n, %USERNAME% ni !x! se expande, ninguna comilla se queda dentro.
func TestLasOrdenesImpresasFuncionanEnLaConsolaDeVerdad(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	bin := t.TempDir()
	nombre := "nucleo"
	if runtime.GOOS == "windows" {
		nombre += ".exe"
	}
	copiaEjecutable(t, exe, filepath.Join(bin, nombre))

	var ordenes []ordenImpresa
	for _, r := range rutasConTrampa() {
		ordenes = append(ordenes, ordenesCon(r)...)
	}
	for _, o := range ordenes {
		// Si una orden empezara por una ruta entre comillas, PowerShell la tomaría por
		// texto y no la ejecutaría sin un «& » delante (comillas.go).
		if !strings.HasPrefix(o.linea, "nucleo ") {
			t.Fatalf("la orden no empieza por la palabra nucleo: %s", o.linea)
		}
	}

	for nombreConsola, prefijo := range consolas(t) {
		t.Run(nombreConsola, func(t *testing.T) {
			eco := filepath.Join(t.TempDir(), "argv.jsonl")
			// Todas en una invocación —arrancar PowerShell cuesta un segundo—, separadas
			// por «;», que separa órdenes en las dos consolas. Una comilla mal cerrada se
			// come las siguientes y el recuento lo dice.
			lineas := make([]string, len(ordenes))
			for i, o := range ordenes {
				lineas[i] = o.linea
			}
			cmd := exec.Command(prefijo[0], append(prefijo[1:], strings.Join(lineas, " ; "))...)
			cmd.Env = append(os.Environ(),
				envEcoArgv+"="+eco,
				"PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"))
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("%s: %v\n%s", nombreConsola, err, out)
			}
			got := leerEcos(t, eco)
			if len(got) != len(ordenes) {
				t.Fatalf("%s: %d órdenes, y nucleo se ejecutó %d veces", nombreConsola, len(ordenes), len(got))
			}
			for i, o := range ordenes {
				if !reflect.DeepEqual(got[i], o.argv) {
					t.Errorf("%s:\n  orden: %s\n  llegó: %q\n  debía: %q", nombreConsola, o.linea, got[i], o.argv)
				}
			}
			if !t.Failed() {
				t.Logf("%s: %d órdenes, cada una con su argv exacto", nombreConsola, len(ordenes))
			}
		})
	}
}

func copiaEjecutable(t *testing.T, de, a string) {
	t.Helper()
	src, err := os.Open(de)
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()
	dst, err := os.OpenFile(a, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(dst, src); err != nil {
		dst.Close()
		t.Fatal(err)
	}
	if err := dst.Close(); err != nil {
		t.Fatal(err)
	}
}

func leerEcos(t *testing.T, fichero string) [][]string {
	t.Helper()
	f, err := os.Open(fichero)
	if err != nil {
		t.Fatalf("nucleo no se ejecutó ni una vez: %v", err)
	}
	defer f.Close()
	var out [][]string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var argv []string
		if err := json.Unmarshal(sc.Bytes(), &argv); err != nil {
			t.Fatal(err)
		}
		out = append(out, argv)
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// TestRutaWindowsParaImprimir: la ruta que se imprime en Windows, con los valores
// escritos a mano (filepath.Clean de Windows solo se ejecuta en Windows).
func TestRutaWindowsParaImprimir(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("filepath.Clean de Windows: solo en Windows (lo corre el job windows-2025 del CI)")
	}
	for _, c := range []struct{ ruta, quiero string }{
		{`C:`, `C:.`},
		{`C:\`, `C:\.`},
		{`\\servidor\mi recurso\`, `\\servidor\mi recurso\.`},
		{`\\servidor\mi recurso`, `\\servidor\mi recurso`},
		{`.\x`, `x`},
		{`C:\termina en barra\`, `C:\termina en barra`},
		{`C:\acaba en espacio \p.json`, `C:\acaba en espacio \p.json`},
		{`C:\acaba en punto.\p.json`, `C:\acaba en punto.\p.json`},
	} {
		if got := rutaWindowsParaImprimir(c.ruta); got != c.quiero {
			t.Errorf("rutaWindowsParaImprimir(%q) = %q, quiero %q", c.ruta, got, c.quiero)
		}
	}
}
