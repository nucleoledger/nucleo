//go:build testhooks

package main

import (
	"bufio"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

// testigoEnMarcha es un `nucleo witness serve` corriendo en un subproceso.
type testigoEnMarcha struct {
	url string
	cmd *exec.Cmd
	// salida la escribe la goroutine que lee el proceso y la lee el test: mu la protege.
	mu  sync.Mutex
	out strings.Builder
}

// salida devuelve lo que el testigo ha escrito hasta ahora.
func (tm *testigoEnMarcha) salida() string {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	return tm.out.String()
}

var escuchandoEn = regexp.MustCompile(`escuchando en (http://\S+)`)

// levantaTestigo arranca `witness serve` con los argumentos dados en un proceso aparte
// y espera a que diga dónde escucha. Se para solo al terminar el test.
func levantaTestigo(t *testing.T, args ...string) *testigoEnMarcha {
	t.Helper()
	raw, _ := json.Marshal(append([]string{"witness", "serve", "--addr", "127.0.0.1:0"}, args...))
	cmd := exec.Command(os.Args[0], "-test.run=^TestSubprocesoCLI$")
	cmd.Env = append(os.Environ(), envSubprocesoCLI+"="+string(raw))
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = cmd.Stdout
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	tm := &testigoEnMarcha{cmd: cmd}
	url := make(chan string, 1)
	go func() {
		sc := bufio.NewScanner(out)
		for sc.Scan() {
			l := sc.Text()
			tm.mu.Lock()
			tm.out.WriteString(l + "\n")
			tm.mu.Unlock()
			if m := escuchandoEn.FindStringSubmatch(l); m != nil {
				url <- m[1]
			}
		}
		_, _ = io.Copy(io.Discard, out)
	}()
	t.Cleanup(func() { tm.para() })
	select {
	case tm.url = <-url:
	case <-time.After(30 * time.Second):
		t.Fatalf("el testigo no dijo dónde escucha:\n%s", tm.salida())
	}
	// Lo que imprime después de «escuchando» llega enseguida; se le da un instante.
	time.Sleep(200 * time.Millisecond)
	return tm
}

func (tm *testigoEnMarcha) para() {
	if tm.cmd.Process != nil {
		_ = tm.cmd.Process.Kill()
		_ = tm.cmd.Wait()
	}
}

// claveDelLog lee la clave pública del log de un ledger.
func claveDelLog(t *testing.T, c *cli) string {
	t.Helper()
	out := c.mustRun("--json", "status")
	var st struct {
		LogPubkey string `json:"log_pubkey"`
	}
	if err := json.Unmarshal([]byte(out), &st); err != nil || st.LogPubkey == "" {
		t.Fatalf("status --json sin log_pubkey (%v):\n%s", err, out)
	}
	return st.LogPubkey
}

// TestTestigoDeVariosLogs (ADR-030), con el binario: un testigo con --config atiende a
// dos ledgers; reiniciado con uno retirado, a ese le dice que lo retiró —y la CLI lo
// explica— y al otro le sigue cosignando, con la memoria de antes.
func TestTestigoDeVariosLogs(t *testing.T) {
	uno := newCLI(t)
	uno.mustRun("init", "--origin", "ejemplo.ec/uno", "--assume-confirmed")
	uno.sealFile(`{"factura":"uno-1"}`)
	dos := newCLI(t)
	dos.mustRun("init", "--origin", "ejemplo.ec/dos", "--assume-confirmed")
	dos.sealFile(`{"factura":"dos-1"}`)

	dirTestigo := t.TempDir()
	db := filepath.Join(dirTestigo, "testigo.db")
	clave := strings.TrimSpace(uno.mustRun("witness", "key", "--db", db))
	const nombre = "testigo.ejemplo.ec/w1"
	config := filepath.Join(dirTestigo, "testigo.json")
	escribe := func(doc string) {
		t.Helper()
		if err := os.WriteFile(config, []byte(doc), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	k1, k2 := claveDelLog(t, uno), claveDelLog(t, dos)
	escribe(`{"name": "` + nombre + `", "logs": {"ejemplo.ec/uno": "` + k1 + `", "ejemplo.ec/dos": "` + k2 + `"}}`)

	tm := levantaTestigo(t, "--db", db, "--config", config)
	if !strings.Contains(tm.salida(), "logs servidos (2)") {
		t.Errorf("el arranque no dice qué logs sirve:\n%s", tm.salida())
	}
	sync := func(c *cli) (string, string, int) {
		return c.run("--json", "sync", "--witness", tm.url, "--witness-name", nombre, "--witness-key", clave)
	}
	for _, c := range []*cli{uno, dos} {
		if _, _, code := sync(c); code != exitOK {
			t.Fatalf("primer sync: código %d\n%s", code, c.ultima())
		}
	}

	// Se retira «uno»: editar y reiniciar, sobre la misma memoria.
	tm.para()
	escribe(`{"name": "` + nombre + `", "logs": {"ejemplo.ec/dos": "` + k2 + `"}, "retired": {"ejemplo.ec/uno": "` + k1 + `"}}`)
	tm = levantaTestigo(t, "--db", db, "--config", config)
	if !strings.Contains(tm.salida(), "logs retirados (1)") || !strings.Contains(tm.salida(), "ejemplo.ec/uno") {
		t.Errorf("el arranque no dice qué está retirado:\n%s", tm.salida())
	}

	uno.sealFile(`{"factura":"uno-2"}`)
	out, _, code := sync(uno)
	if code != exitSyncFail {
		t.Fatalf("sync de un log retirado: código %d; want %d\n%s", code, exitSyncFail, uno.ultima())
	}
	if !strings.Contains(out, "dejó de cosignar este log") || !strings.Contains(out, "NO se arregla reintentando") {
		t.Errorf("el error no dice que el log está retirado:\n%s", out)
	}

	dos.sealFile(`{"factura":"dos-2"}`)
	if _, _, code := sync(dos); code != exitOK {
		t.Fatalf("el otro log dejó de sincronizar: código %d\n%s", code, dos.ultima())
	}

	// Retirarlo con una clave que no es la suya: el testigo no arranca (enmienda de
	// ADR-030), porque lo que publicaría como «hasta aquí» no sería de ese log.
	tm.para()
	escribe(`{"name": "` + nombre + `", "logs": {"ejemplo.ec/dos": "` + k2 + `"}, "retired": {"ejemplo.ec/uno": "` + strings.Repeat("ab", 32) + `"}}`)
	if _, _, code := uno.run("witness", "serve", "--addr", "127.0.0.1:0", "--db", db, "--config", config); code != exitUsage {
		t.Fatalf("con la clave equivocada en retired, witness serve salió con %d; want %d\n%s", code, exitUsage, uno.ultima())
	}
	if !strings.Contains(uno.ultima(), "no es la que firmó lo que el testigo recuerda") {
		t.Errorf("no explica por qué no arranca:\n%s", uno.ultima())
	}

	// Sin «uno» en la configuración, el arranque dice que tiene su memoria.
	escribe(`{"name": "` + nombre + `", "logs": {"ejemplo.ec/dos": "` + k2 + `"}}`)
	tm = levantaTestigo(t, "--db", db, "--config", config)
	if !strings.Contains(tm.salida(), "que la configuración ya no menciona") {
		t.Errorf("el arranque no avisa de la memoria sin configurar:\n%s", tm.salida())
	}
}

// TestTestigoDeUnLogSigueIgual (ADR-030 §B): --log-origin y --log-key, como siempre.
func TestTestigoDeUnLogSigueIgual(t *testing.T) {
	c := newCLI(t)
	c.initLedger()
	c.sealFile(`{"factura":"uno"}`)
	db := filepath.Join(t.TempDir(), "testigo.db")
	clave := strings.TrimSpace(c.mustRun("witness", "key", "--db", db))
	tm := levantaTestigo(t, "--db", db, "--name", "w.ejemplo.ec/w1", "--log-origin", testOrigin, "--log-key", claveDelLog(t, c))
	if !strings.Contains(tm.salida(), "log servido: "+testOrigin) {
		t.Errorf("el arranque cambió:\n%s", tm.salida())
	}
	c.mustRun("sync", "--witness", tm.url, "--witness-name", "w.ejemplo.ec/w1", "--witness-key", clave)
}

// TestTestigoUsoIncorrecto: las combinaciones sin sentido se rechazan antes de servir.
func TestTestigoUsoIncorrecto(t *testing.T) {
	c := newCLI(t)
	dir := t.TempDir()
	db := filepath.Join(dir, "t.db")
	cfg := filepath.Join(dir, "t.json")
	_ = os.WriteFile(cfg, []byte(`{"name": "w", "logs": {"o": "`+strings.Repeat("ab", 32)+`"}}`), 0o600)
	malo := filepath.Join(dir, "malo.json")
	_ = os.WriteFile(malo, []byte(`{"name": "w", "logs": {"o": "`+strings.Repeat("ab", 32)+`"}, "Logs": {}}`), 0o600)

	_, errOut := c.runWant(t, exitUsage, "witness", "serve", "--db", db, "--config", cfg, "--log-origin", "x")
	if !strings.Contains(errOut+c.ultima(), "no se combina") {
		t.Errorf("--config con --log-origin no lo explica:\n%s", c.ultima())
	}
	c.runWant(t, exitUsage, "witness", "serve", "--db", db, "--config", malo)
	if !strings.Contains(c.ultima(), "variante de mayúsculas") {
		t.Errorf("una configuración inválida no dice por qué:\n%s", c.ultima())
	}
	c.runWant(t, exitUsage, "witness", "serve", "--db", db)
}
