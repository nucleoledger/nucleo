//go:build testhooks

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// Las regresiones del ensayo de operación del Sprint 10.
//
// No salieron de leer el código: salieron de montar un despliegue y usarlo. Cada una
// tiene su secuencia exacta en docs/ensayo-de-operacion-20260923.md.

// TestDosWorkersSellanALaVez es el escenario 6: un ERP con dos workers contra el mismo
// ledger.
//
// Antes del arreglo, de 60 sellados concurrentes fallaban 19 —un tercio— con dos errores
// distintos: "otro proceso tiene el ledger tomado" (BUSY inmediato de SQLite en WAL, que
// `busy_timeout` no reintenta) e "índice fuera de secuencia" (el bloque se firma fuera de
// la transacción y deja de seguir al último cuando otro proceso confirma en medio).
// Ahora las transacciones se abren en modo immediate y el sellado reintenta la carrera
// perdida, que es lo que haría a mano quien viera el error.
//
// Cada goroutine llama a run() por separado, así que cada una abre SU ledger y compite
// por el fichero igual que dos procesos: el candado de escritura del proceso no las
// serializa.
func TestDosWorkersSellanALaVez(t *testing.T) {
	c := newCLI(t)
	c.initLedger()

	const workers = 2
	const porWorker = 10
	type fallo struct {
		worker, i, code int
		errOut          string
	}
	var (
		mu      sync.Mutex
		fallos  []fallo
		hechos  int
		espera  sync.WaitGroup
		payload = func(w, i int) string {
			return fmt.Sprintf(`{"worker":%d,"n":%d}`, w, i)
		}
	)
	espera.Add(workers)
	for w := 0; w < workers; w++ {
		go func(w int) {
			defer espera.Done()
			for i := 0; i < porWorker; i++ {
				f := ficheroUnico(t, c.dir, fmt.Sprintf("w%d-*.json", w), payload(w, i))
				_, errOut, code := c.run("seal", "--tenant", testTenant,
					"--type", "sri.factura.v1", "--payload", f)
				mu.Lock()
				if code == exitOK {
					hechos++
				} else {
					fallos = append(fallos, fallo{w, i, code, errOut})
				}
				mu.Unlock()
			}
		}(w)
	}
	espera.Wait()

	if len(fallos) > 0 {
		for _, f := range fallos {
			t.Errorf("worker %d, sellado %d: código %d\n%s", f.worker, f.i, f.code, f.errOut)
		}
		t.Fatalf("%d de %d sellados concurrentes fallaron; con dos workers el ERP no puede perder ninguno",
			len(fallos), workers*porWorker)
	}
	if hechos != workers*porWorker {
		t.Fatalf("sellados con éxito: %d, esperados %d", hechos, workers*porWorker)
	}

	// Y el ledger tiene que quedar íntegro y sin huecos: la carrera no puede dejar dos
	// bloques con el mismo índice ni saltarse ninguno.
	out, _ := c.runWant(t, exitOK, "--json", "verify", "--full")
	var v map[string]any
	if err := json.Unmarshal([]byte(out), &v); err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprint(v["tree_size"]); got != fmt.Sprint(workers*porWorker) {
		t.Errorf("tree_size = %s, esperado %d", got, workers*porWorker)
	}
}

// TestElRelojAtrasadoLoDiceEnCristiano es el escenario 7, primera mitad: NTP mal puesto o
// una VM restaurada dejan el reloj por detrás del último bloque.
//
// El protocolo no puede ceder —un bloque no lleva fecha anterior al anterior— así que lo
// que se arregla es el mensaje: antes era "ledger: timestamp anterior al del bloque
// previo", exacto e inútil para quien lo lee en un cron.
func TestElRelojAtrasadoLoDiceEnCristiano(t *testing.T) {
	c := newCLI(t)
	c.initLedger()
	c.sealFile(`{"antes":true}`)

	t.Setenv(envClock, "2026-09-07T09:00:00Z") // una hora antes del bloque anterior
	f := ficheroUnico(t, c.dir, "atras-*.json", `{"con":"el reloj atrasado"}`)
	_, errOut, code := c.run("seal", "--tenant", testTenant, "--type", "sri.factura.v1", "--payload", f)
	if code != exitUsage {
		t.Fatalf("código %d, esperado %d\n%s", code, exitUsage, c.ultima())
	}
	for _, quiere := range []string{
		"reloj de esta máquina",
		"2026-09-07T09:00:00Z", // la hora que tiene
		"2026-09-07T10:00:00Z", // la del último bloque
		"NTP",                  // qué mirar
		"append-only",          // y por qué no hay vuelta atrás si el bloque es el raro
	} {
		if !strings.Contains(errOut, quiere) {
			t.Errorf("el mensaje no dice %q:\n%s", quiere, c.ultima())
		}
	}
	if strings.Contains(errOut, "timestamp anterior al del bloque previo") {
		t.Error("el mensaje interno del ledger no debería llegar al operador")
	}
}

// TestElRelojAdelantadoAvisaAntesDeEscribir es el escenario 7, segunda mitad, y el
// hallazgo más caro del ensayo: con el reloj un año adelantado el sellado FUNCIONA y deja
// un bloque con fecha futura que impide sellar hasta esa fecha. Un salto de NTP dejaba el
// ledger de una pyme sin poder sellar durante un año, y el mensaje que lo explicaba era
// el mismo "timestamp anterior al del bloque previo" del caso de arriba.
//
// No se puede prohibir —el reloj de esta máquina es lo único que hay para fechar— pero sí
// avisar ANTES de escribirlo, cuando todavía se puede parar.
func TestElRelojAdelantadoAvisaAntesDeEscribir(t *testing.T) {
	c := newCLI(t)
	c.initLedger()
	c.sealFile(`{"antes":true}`)

	t.Setenv(envClock, "2027-09-07T10:00:00Z") // un año adelante
	f := ficheroUnico(t, c.dir, "futuro-*.json", `{"con":"el reloj adelantado"}`)
	out, errOut, code := c.run("seal", "--tenant", testTenant, "--type", "sri.factura.v1", "--payload", f)
	if code != exitOK {
		t.Fatalf("el sellado no se prohíbe, se avisa: código %d\n%s", code, c.ultima())
	}
	if !strings.Contains(out, "✔ registro sellado") {
		t.Errorf("el sellado debería haberse hecho:\n%s", c.ultima())
	}
	for _, quiere := range []string{
		"por delante del último bloque",
		"IMPIDE sellar",
		"2027-09-07T10:00:00Z",
		"para aquí",
	} {
		if !strings.Contains(errOut, quiere) {
			t.Errorf("el aviso no dice %q:\n%s", quiere, c.ultima())
		}
	}

	// Y un salto pequeño —un reloj que corre unos minutos, lo normal sin NTP— no avisa:
	// un aviso que sale siempre es un aviso que nadie lee.
	t.Setenv(envClock, "2027-09-07T10:30:00Z")
	f2 := ficheroUnico(t, c.dir, "poco-*.json", `{"con":"media hora más"}`)
	_, errOut2, code2 := c.run("seal", "--tenant", testTenant, "--type", "sri.factura.v1", "--payload", f2)
	if code2 != exitOK {
		t.Fatalf("código %d\n%s", code2, c.ultima())
	}
	if strings.Contains(errOut2, "por delante del último bloque") {
		t.Errorf("media hora no es un salto de reloj y no debería avisar:\n%s", c.ultima())
	}
}

// TestElRollbackDetectadoNoSeOlvida es el escenario 4 del ensayo: restaurar un respaldo
// de hace una semana y seguir operando.
//
// `sync` lo cazaba —"✘ ROLLBACK LOCAL DETECTADO", con las dos cifras y código 2— y el
// siguiente `status` decía "✔ historia atestiguada hasta 1322 de 1322 bloques". El primer
// sitio donde mira quien acaba de restaurar decía que todo estaba bien, y la única alarma
// vivía en la salida de un cron que nadie lee. Ahora queda constancia en el propio ledger.
func TestElRollbackDetectadoNoSeOlvida(t *testing.T) {
	c := newCLI(t)
	c.initLedger()
	c.sealFile(`{"factura":"uno"}`)
	c.sealFile(`{"factura":"dos"}`)

	url, name, key := startTestWitness(t, c.logPubKey(t))
	c.mustRun("sync", "--witness", url, "--witness-name", name, "--witness-key", key)

	// El respaldo: una copia del fichero, como la haría un sysadmin.
	respaldo := filepath.Join(t.TempDir(), "nucleo.db")
	copiaDeFichero(t, filepath.Join(c.dir, "nucleo.db"), respaldo)

	// La semana sigue y el testigo ve más historia.
	c.sealFile(`{"factura":"tres"}`)
	c.mustRun("sync", "--witness", url, "--witness-name", name, "--witness-key", key)

	// Y se restaura el respaldo, que es lo que hace quien pierde el disco.
	for _, sufijo := range []string{"", "-wal", "-shm"} {
		_ = os.Remove(filepath.Join(c.dir, "nucleo.db"+sufijo))
	}
	copiaDeFichero(t, respaldo, filepath.Join(c.dir, "nucleo.db"))

	_, errOut, code := c.run("sync", "--witness", url, "--witness-name", name, "--witness-key", key)
	if code != exitVerify {
		t.Fatalf("el sync tras restaurar debe salir con %d: código %d\n%s", exitVerify, code, c.ultima())
	}
	_ = errOut

	// Y ahora lo que faltaba: la alarma DURA.
	_, errOut = c.runWant(t, exitOK, "status")
	for _, quiere := range []string{"ROLLBACK REGISTRADO", "3 bloques", "restauraste un respaldo"} {
		if !strings.Contains(errOut, quiere) {
			t.Errorf("el status tras el rollback no dice %q:\n%s", quiere, c.ultima())
		}
	}

	// verify sale con 2: un rollback registrado no es "hace tiempo que nadie lo ve", es
	// "esto no es la historia que un tercero atestiguó", y eso es lo que verify contesta.
	if _, _, code := c.run("verify", "--full"); code != exitVerify {
		t.Errorf("verify --full con rollback registrado: código %d, esperado %d\n%s", code, exitVerify, c.ultima())
	}

	// El sellado sigue funcionando —lo que se pidió fue sellar— pero lo dice.
	out, errOut, code := c.run("seal", "--tenant", testTenant, "--type", "sri.factura.v1",
		"--payload", ficheroUnico(t, c.dir, "tras-rollback-*.json", `{"factura":"cuatro"}`))
	if code != exitOK {
		t.Fatalf("el sellado no se prohíbe: código %d\n%s", code, c.ultima())
	}
	if !strings.Contains(out, "✔ registro sellado") {
		t.Errorf("debería haber sellado:\n%s", c.ultima())
	}
	if !strings.Contains(errOut, "ROLLBACK REGISTRADO") {
		t.Errorf("el sellado sobre un ledger con rollback tiene que decirlo:\n%s", c.ultima())
	}

	// Y en --json, para un monitor.
	out, _ = c.runWant(t, exitOK, "--json", "status")
	var v map[string]any
	if err := json.Unmarshal([]byte(out), &v); err != nil {
		t.Fatal(err)
	}
	rb, ok := v["rollback"].(map[string]any)
	if !ok {
		t.Fatalf("el JSON de status no trae el objeto rollback:\n%s", out)
	}
	if fmt.Sprint(rb["witness_size"]) != "3" || fmt.Sprint(rb["local_size"]) != "2" {
		t.Errorf("rollback = %v, esperado witness_size 3 y local_size 2", rb)
	}
	if rb["witness"] != name {
		t.Errorf("rollback.witness = %v, esperado %q", rb["witness"], name)
	}
}

// copiaDeFichero copia un fichero, que es lo que hace un respaldo de verdad.
func copiaDeFichero(t *testing.T, de, a string) {
	t.Helper()
	raw, err := os.ReadFile(de)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(a, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}
