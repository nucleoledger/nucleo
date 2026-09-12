//go:build testhooks

package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nucleoledger/nucleo/internal/store"
	"github.com/nucleoledger/nucleo/internal/witness"
)

const (
	testOrigin     = "nucleoledger.com/pruebas"
	testTenant     = "1790012345001"
	testPassphrase = "correcta caballo bateria grapa"
	testClockRFC   = "2026-09-07T10:00:00Z"
)

// cli ejecuta la CLI capturando su salida, como haría alguien desde una consola.
type cli struct {
	t   *testing.T
	dir string
}

func newCLI(t *testing.T) *cli {
	t.Helper()
	// Los ganchos de prueba fijan reloj, semilla y passphrase. Sin ellos, cada
	// ejecución produciría claves y horas distintas y no habría golden posible.
	t.Setenv(envSeed, strings.Repeat("07", 32))
	t.Setenv(envClock, testClockRFC)
	t.Setenv(envPassphrase, testPassphrase)
	return &cli{t: t, dir: t.TempDir()}
}

// runTimeout es el tiempo que se le da a una invocación de la CLI antes de
// declararla colgada.
//
// Es generoso a propósito: lo más lento que hace la CLI es derivar la KEK con
// Argon2id, unas decenas de milisegundos, y un init encadena varias. Un minuto no
// se alcanza ni con -race en el runner más lento. Lo que compra es que un bloqueo
// futuro falle en un minuto con las pilas a la vista, en vez de consumir los diez
// del timeout global de `go test` y dejar un panic que hay que descifrar.
const runTimeout = 60 * time.Second

// run invoca la CLI y devuelve stdout, stderr y el código de salida.
//
// Los dos pipes se drenan EN PARALELO, cada uno con su goroutine, arrancadas ANTES
// de ejecutar la CLI. Drenarlos en secuencia —leer stdout hasta el final y solo
// entonces stderr— es un abrazo mortal, y estuvo aquí hasta que lo cazó Windows:
//
//   - El lector de stdout no ve EOF hasta que la CLI termina y se cierran los
//     extremos de escritura.
//   - Si mientras tanto la CLI escribe en stderr más de lo que cabe en el buffer
//     del pipe, la escritura se bloquea.
//   - La CLI no puede terminar porque está bloqueada escribiendo; el test no puede
//     leer stderr porque sigue esperando el EOF de stdout. Los dos esperan al otro.
//
// En Linux y macOS el buffer del pipe es de 64 KiB y nada se acercaba. En Windows
// son 4 KiB, y el texto de ayuda —que sale por stderr en cualquier error de uso—
// pasó de 4 KiB al crecer la ayuda del sprint 7. A partir de ahí, TestExitCodes se
// colgaba en Windows los diez minutos enteros.
//
// La regla general, que es lo que conviene recordar: quien escribe en dos tuberías
// y las lee de una en una ya tiene el abrazo mortal escrito; solo falta que alguien
// llene la que no está leyendo.
func (c *cli) run(args ...string) (string, string, int) {
	c.t.Helper()
	full := append([]string{"--dir", c.dir}, args...)
	return capturar(c.t, "nucleo "+strings.Join(args, " "),
		func(stdout, stderr *os.File) int { return run(full, stdout, stderr) })
}

// capturar ejecuta fn con dos pipes y devuelve lo que escribió en cada uno.
//
// Está separado de (*cli).run para que el propio arnés se pueda probar: con esto,
// el abrazo mortal que solo aparecía en Windows se puede provocar en cualquier
// sistema escribiendo lo bastante. Ver TestArnesDrenaLosDosPipesEnParalelo.
func capturar(t *testing.T, etiqueta string, fn func(stdout, stderr *os.File) int) (string, string, int) {
	t.Helper()
	outR, outW := pipe(t)
	errR, errW := pipe(t)

	var stdout, stderr bytes.Buffer
	var lectores sync.WaitGroup
	lectores.Add(2)
	drenar := func(dst *bytes.Buffer, src *os.File) {
		defer lectores.Done()
		defer src.Close()
		// El error de io.Copy se ignora a propósito: el único que puede llegar aquí
		// es el cierre del otro extremo, que es precisamente cómo termina.
		_, _ = io.Copy(dst, src)
	}
	go drenar(&stdout, outR)
	go drenar(&stderr, errR)

	done := make(chan int, 1)
	go func() {
		code := fn(outW, errW)
		// Cerrar los extremos de escritura es lo que da el EOF a los lectores.
		outW.Close()
		errW.Close()
		done <- code
	}()

	var code int
	select {
	case code = <-done:
	case <-time.After(runTimeout):
		t.Fatalf("%q no terminó en %s: está colgado.\n"+
			"Sospechosos, por orden: una escritura bloqueada en un pipe lleno "+
			"(¿se drenan los dos en paralelo?) o una lectura de os.Stdin, que este "+
			"arnés NO alimenta.\n\nPilas de todas las goroutines:\n%s",
			etiqueta, runTimeout, pilas())
	}
	// Solo se espera a los lectores cuando la CLI terminó. Tras un timeout los
	// extremos de escritura siguen abiertos y esperarlos colgaría el test otra vez,
	// ahora sin diagnóstico.
	lectores.Wait()
	return stdout.String(), stderr.String(), code
}

// pipe crea un pipe o aborta el test.
func pipe(t *testing.T) (*os.File, *os.File) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	return r, w
}

// pilas vuelca las goroutines de todo el proceso. En un abrazo mortal, la pila de
// la que escribe y la de la que lee dicen entre las dos qué pasó.
func pilas() string {
	buf := make([]byte, 1<<20)
	return string(buf[:runtime.Stack(buf, true)])
}

// mustRun exige código 0.
func (c *cli) mustRun(args ...string) string {
	c.t.Helper()
	out, errOut, code := c.run(args...)
	if code != exitOK {
		c.t.Fatalf("`nucleo %s` salió con %d\nstdout:\n%s\nstderr:\n%s",
			strings.Join(args, " "), code, out, errOut)
	}
	return out
}

// initLedger deja un despliegue listo.
func (c *cli) initLedger() {
	c.t.Helper()
	c.mustRun("init", "--origin", testOrigin, "--assume-confirmed")
}

// sealFile sella un contenido y devuelve el índice del bloque.
func (c *cli) sealFile(content string) string {
	c.t.Helper()
	path := filepath.Join(c.dir, fmt.Sprintf("payload-%d.json", time.Now().UnixNano()))
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		c.t.Fatal(err)
	}
	return c.mustRun("seal", "--tenant", testTenant, "--type", "sri.factura.v1", "--payload", path)
}

// writeTemp escribe un payload temporal y devuelve su ruta.
func (c *cli) writeTemp(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(c.dir, fmt.Sprintf("tmp-%d.json", time.Now().UnixNano()))
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestInitIsDeterministicWithTestHooks fija las piezas de la salida de init.
//
// Comprueba las líneas que importan, no la salida entera: un golden byte a byte
// de treinta líneas se rompe cada vez que se añade un campo y acaba actualizándose
// sin leerlo, que es lo contrario de lo que un golden debe provocar. Lo que se fija
// aquí es que cada pieza esté y que las claves sean deterministas: si
// NUCLEO_TEST_SEED dejara de fijar el material, cambiarían.
func TestInitIsDeterministicWithTestHooks(t *testing.T) {
	c := newCLI(t)
	out := c.mustRun("init", "--origin", testOrigin, "--assume-confirmed")

	for _, want := range []string{
		"✔ vault y ledger creados",
		"origin        : " + testOrigin,
		"TARJETAS DE RESPALDO DE LA CLAVE — SLIP-0039",
		"Son 3 tarjetas y hacen falta 2 para recuperar el vault.",
		"Escríbelas EN PAPEL",
		"── TARJETA 1 de 3 ──",
		"── TARJETA 3 de 3 ──",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("la salida de init no contiene %q:\n%s", want, out)
		}
	}

	// Las claves son deterministas bajo el gancho de semilla.
	second := newCLI(t)
	out2 := second.mustRun("init", "--origin", testOrigin, "--assume-confirmed")
	if keyLine(t, out) != keyLine(t, out2) {
		t.Error("con la misma semilla salieron claves distintas: el gancho no fija el material")
	}

	// Y el aviso sale por stderr siempre, diciendo lo que de verdad importa:
	// que ESTE binario honra los ganchos y por tanto no es de producción.
	_, stderr, _ := c.run("status")
	if !strings.Contains(stderr, "HONRA los ganchos de prueba") ||
		!strings.Contains(stderr, envSeed) {
		t.Errorf("no se avisó del gancho de pruebas:\n%s", stderr)
	}
}

func keyLine(t *testing.T, out string) string {
	t.Helper()
	for _, l := range strings.Split(out, "\n") {
		if strings.Contains(l, "clave del log") {
			return l
		}
	}
	t.Fatalf("no se encontró la clave del log en:\n%s", out)
	return ""
}

// TestInitRefusesToOverwrite: init no pisa un despliegue existente. Sería la
// forma más rápida de perder un ledger entero.
func TestInitRefusesToOverwrite(t *testing.T) {
	c := newCLI(t)
	c.initLedger()
	_, stderr, code := c.run("init", "--origin", testOrigin, "--assume-confirmed")
	if code != exitUsage {
		t.Errorf("código = %d, want %d", code, exitUsage)
	}
	if !strings.Contains(stderr, "no sobrescribe nada") {
		t.Errorf("stderr = %q", stderr)
	}
}

// TestStatusGolden fija la salida de status sobre un ledger sin atestiguar. Es
// el estado en el que está cualquiera antes de configurar un testigo, así que
// es el texto que más gente va a leer.
func TestStatusGolden(t *testing.T) {
	c := newCLI(t)
	c.initLedger()
	c.sealFile(`{"factura":1,"importe":"10000.00"}`)

	out := c.mustRun("status")
	if !strings.Contains(out, "bloques   : 1\n") {
		t.Errorf("status no dice cuántos bloques hay:\n%s", out)
	}
	want := `estado    : ⚠ SIN ATESTIGUAR (1 bloques)
            La cadena es localmente válida, pero que esté COMPLETA no
            está garantizado: sin un checkpoint cosignado por un testigo,
            un prefijo truncado es indistinguible de la historia entera.
            Ejecuta ` + "`nucleo sync`" + ` contra un testigo.
`
	if !strings.Contains(out, want) {
		t.Errorf("status:\n%s\n\nno contiene:\n%s", out, want)
	}
}

// TestJSONOutputIsPureJSON: en modo --json no puede colarse prosa, porque hay
// un script al otro lado.
func TestJSONOutputIsPureJSON(t *testing.T) {
	c := newCLI(t)
	c.initLedger()
	c.sealFile(`{"factura":1}`)

	for _, args := range [][]string{{"status"}, {"verify"}, {"verify", "--full"}} {
		out, _, code := c.run(append([]string{"--json"}, args...)...)
		if code != exitOK {
			t.Fatalf("%v salió con %d", args, code)
		}
		var v map[string]any
		if err := json.Unmarshal([]byte(out), &v); err != nil {
			t.Errorf("%v no produjo JSON limpio: %v\n%s", args, err, out)
		}
		if v["ok"] != true {
			t.Errorf("%v: ok = %v", args, v["ok"])
		}
	}
}

// TestExitCodes recorre los cuatro códigos documentados. Son contrato: hay
// scripts que los van a leer, y cambiarlos en silencio rompería cron ajenos.
func TestExitCodes(t *testing.T) {
	c := newCLI(t)
	c.initLedger()
	c.sealFile(`{"factura":1,"importe":"10000.00"}`)

	t.Run("0 — todo correcto", func(t *testing.T) {
		if _, _, code := c.run("verify"); code != exitOK {
			t.Errorf("código = %d, want 0", code)
		}
	})

	t.Run("1 — error de uso", func(t *testing.T) {
		for _, args := range [][]string{
			{"noexiste"},
			{"seal"},
			{"receipt", "--block", "0"},
			{"reconcile"},
			{"sync", "--witness", "http://x"},
		} {
			if _, _, code := c.run(args...); code != exitUsage {
				t.Errorf("%v: código = %d, want 1", args, code)
			}
		}
	})

	t.Run("2 — la verificación falló", func(t *testing.T) {
		live := filepath.Join(c.dir, "live.jsonl")
		// El sistema vivo dice otra cosa de la que se selló.
		body := `{"index":0,"payload_b64":"eyJmYWN0dXJhIjoxLCJpbXBvcnRlIjoiMTAwMC4wMCJ9"}` + "\n"
		if err := os.WriteFile(live, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		out, _, code := c.run("reconcile", "--source", live)
		if code != exitVerify {
			t.Errorf("código = %d, want 2", code)
		}
		if !strings.Contains(out, "REGISTRO ALTERADO DESPUÉS DE SELLARSE") {
			t.Errorf("no se explicó el hallazgo:\n%s", out)
		}
	})

	t.Run("3 — la sincronización falló", func(t *testing.T) {
		out, stderr, code := c.run("sync",
			"--witness", "http://127.0.0.1:1",
			"--witness-name", "witness.example/w1",
			"--witness-key", strings.Repeat("11", 32))
		if code != exitSyncFail {
			t.Errorf("código = %d, want 3\n%s", code, out)
		}
		// Y el mensaje dice que repetido es un incidente, no un aviso.
		if !strings.Contains(stderr, "INCIDENTE") {
			t.Errorf("el mensaje no explica la gravedad:\n%s", stderr)
		}
	})
}

// TestFullCycleWithWitness recorre el ciclo entero contra un testigo real por
// HTTP: sellar, sincronizar, emitir recibo y verificar.
func TestFullCycleWithWitness(t *testing.T) {
	c := newCLI(t)
	c.initLedger()
	c.sealFile(`{"cliente":"María Pérez","importe":"10000.00"}`)

	url, name, key := startTestWitness(t, c.logPubKey(t))

	out := c.mustRun("sync", "--witness", url, "--witness-name", name, "--witness-key", key)
	if !strings.Contains(out, "atestación obtenida") {
		t.Fatalf("sync:\n%s", out)
	}

	// Ahora sí está atestiguado, y status lo dice con otras palabras.
	st := c.mustRun("status")
	if !strings.Contains(st, "✔ historia atestiguada hasta 1 de 1 bloques") {
		t.Errorf("status tras sync:\n%s", st)
	}

	rec := c.mustRun("receipt", "--block", "0", "--recipient", "María Pérez",
		"--witness-name", name, "--witness-key", key)
	for _, want := range []string{
		"destinatario      : María Pérez",
		"TIEMPO DECLARADO  : " + testClockRFC,
		"(declarado por el sistema emisor)",
		"(atestiguado por testigos)",
	} {
		if !strings.Contains(rec, want) {
			t.Errorf("el recibo no contiene %q:\n%s", want, rec)
		}
	}
}

// logPubKey lee la clave pública del log tal como la publica la propia CLI, en
// modo --json. Leerla por la vía del usuario y no de la base es deliberado: si
// esa salida se rompiera, el test lo notaría.
func (c *cli) logPubKey(t *testing.T) string {
	t.Helper()
	out, _, code := c.run("--json", "status")
	if code != exitOK {
		t.Fatalf("status --json salió con %d", code)
	}
	var v map[string]any
	if err := json.Unmarshal([]byte(out), &v); err != nil {
		t.Fatal(err)
	}
	// status no publica la clave del log; se lee del ledger, que es donde init
	// la dejó en claro justamente para esto.
	s, _, err := openStoreAt(c.dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	raw, err := s.GetMeta(metaLogPubKey)
	if err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(raw)
}

// startTestWitness levanta un testigo de verdad, con su propia base y su propia
// clave, y lo sirve por HTTP. El log y el testigo solo se hablan por la red.
func startTestWitness(t *testing.T, logPubHex string) (url, name, keyHex string) {
	t.Helper()
	name = "witness.example/w1"

	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(200 + i)
	}
	priv := ed25519.NewKeyFromSeed(seed)

	st, err := witness.OpenState(filepath.Join(t.TempDir(), "w.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })

	clock, err := time.Parse(time.RFC3339, testClockRFC)
	if err != nil {
		t.Fatal(err)
	}
	w, err := witness.NewWithState(name, priv, func() time.Time { return clock }, st)
	if err != nil {
		t.Fatal(err)
	}
	logPub, err := hex.DecodeString(logPubHex)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.AddLog(testOrigin, ed25519.PublicKey(logPub)); err != nil {
		t.Fatal(err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: witness.NewServer(w).Handler()}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })

	return "http://" + ln.Addr().String(), name,
		hex.EncodeToString(priv.Public().(ed25519.PublicKey))
}

// TestStatusPublishesLogIdentity cubre la fricción que encontró la demo del
// criterio de éxito: para configurar un testigo o una política de verificación
// hacen falta el origin y la clave pública del log, y antes solo se podían
// sacar consultando la base con SQL. Un producto que empuja a hurgar en el
// fichero que él mismo protege está mal terminado.
func TestStatusPublishesLogIdentity(t *testing.T) {
	c := newCLI(t)
	c.initLedger()

	out := c.mustRun("--json", "status")
	var v struct {
		Origin string `json:"origin"`
		LogKey string `json:"log_pubkey"`
	}
	if err := json.Unmarshal([]byte(out), &v); err != nil {
		t.Fatal(err)
	}
	if v.Origin != testOrigin {
		t.Errorf("origin = %q, want %q", v.Origin, testOrigin)
	}
	if len(v.LogKey) != 64 {
		t.Errorf("clave del log = %q, se esperaban 64 caracteres hex", v.LogKey)
	}
	// Y también en la salida para personas.
	human := c.mustRun("status")
	if !strings.Contains(human, "origin    : "+testOrigin) ||
		!strings.Contains(human, "clave log : "+v.LogKey) {
		t.Errorf("status no publica la identidad del log:\n%s", human)
	}
}

// TestWitnessKeyIsReadable: la clave del testigo se puede pedir, no solo leer
// del mensaje de arranque. Un dato que la otra parte necesita para verificar no
// puede vivir únicamente en un log de consola.
func TestWitnessKeyIsReadable(t *testing.T) {
	c := newCLI(t)
	db := filepath.Join(c.dir, "testigo.db")

	first := strings.TrimSpace(c.mustRun("witness", "key", "--db", db))
	if len(first) != 64 {
		t.Fatalf("clave = %q, se esperaban 64 caracteres hex", first)
	}
	// Pedirla dos veces da la MISMA clave: se crea una vez y se conserva. Si
	// cambiara, las cosignatures ya emitidas dejarían de verificar.
	second := strings.TrimSpace(c.mustRun("witness", "key", "--db", db))
	if second != first {
		t.Errorf("la clave del testigo cambió entre llamadas: %q vs %q", first, second)
	}

	if _, _, code := c.run("witness", "key"); code != exitUsage {
		t.Errorf("sin --db: código = %d, want %d", code, exitUsage)
	}
}

// openStoreAt abre el ledger de un directorio sin pasar por env. Vive aquí, en
// el fichero de test, porque solo lo usan los tests: dejarlo en el código de
// producción sería mantener una función que nadie llama.
func openStoreAt(dir string) (*store.Store, store.OpenResult, error) {
	return store.Open(filepath.Join(dir, "nucleo.db"))
}
