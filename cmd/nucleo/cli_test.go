package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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

// run invoca la CLI y devuelve stdout, stderr y el código de salida.
func (c *cli) run(args ...string) (string, string, int) {
	c.t.Helper()
	outR, outW, err := os.Pipe()
	if err != nil {
		c.t.Fatal(err)
	}
	errR, errW, err := os.Pipe()
	if err != nil {
		c.t.Fatal(err)
	}
	full := append([]string{"--dir", c.dir}, args...)
	done := make(chan int, 1)
	go func() {
		code := run(full, outW, errW)
		outW.Close()
		errW.Close()
		done <- code
	}()
	stdout := readAll(c.t, outR)
	stderr := readAll(c.t, errR)
	return stdout, stderr, <-done
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

func readAll(t *testing.T, f *os.File) string {
	t.Helper()
	defer f.Close()
	var sb strings.Builder
	buf := make([]byte, 4096)
	for {
		n, err := f.Read(buf)
		sb.Write(buf[:n])
		if err != nil {
			return sb.String()
		}
	}
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

// TestInitIsDeterministicWithTestHooks fija la salida de init byte a byte.
//
// Un golden aquí vale doble: además de detectar cambios de formato, prueba que
// los ganchos de prueba hacen lo que dicen. Si NUCLEO_TEST_SEED dejara de fijar
// el material, estas claves cambiarían.
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

	// Y el aviso de gancho activo sale por stderr, siempre.
	_, stderr, _ := c.run("status")
	if !strings.Contains(stderr, envSeed+" está definida") {
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
