//go:build testhooks

package main

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/nucleoledger/nucleo/internal/store"
	"github.com/nucleoledger/nucleo/internal/vault"
	_ "modernc.org/sqlite"
)

// Los cuatro comportamientos de H8, cada uno con su regresión. Ver ADR-020.
//
// Antes del Sprint 8: sellar dos veces el mismo contenido salía con código 1 y el
// volcado `UNIQUE constraint failed: blobs.payload_hash (1555)`; con --no-encrypt salía
// un bloque nuevo en silencio; un fallo entre el blob y el bloque dejaba un huérfano que
// bloqueaba el reintento de ese documento PARA SIEMPRE; y el mismo contenido de otro
// tenant daba el mismo volcado.

// sealPayload sella un contenido concreto (sealFile genera uno distinto cada vez).
func sealPayload(t *testing.T, c *cli, content string, args ...string) (string, string, int) {
	t.Helper()
	f := ficheroUnico(t, c.dir, "idem-*.json", content)
	return c.run(append([]string{"seal", "--tenant", testTenant, "--type", "sri.factura.v1", "--payload", f}, args...)...)
}

// TestResellarElMismoContenidoEsUnBloqueNuevo — ADR-020 §A: el ledger registra hechos
// de sellado, no documentos, así que el segundo sellado entra; pero deja de ser
// silencioso y dice de qué bloque es duplicado.
func TestResellarElMismoContenidoEsUnBloqueNuevo(t *testing.T) {
	c := newCLI(t)
	c.initLedger()
	const doc = `{"factura":"001"}`

	if _, _, code := sealPayload(t, c, doc); code != exitOK {
		t.Fatalf("el primer sellado: código %d\n%s", code, c.ultima())
	}
	out, _, code := sealPayload(t, c, doc)
	if code != exitOK {
		t.Fatalf("re-sellar el mismo contenido debe entrar (ADR-020 §A): código %d\n%s", code, c.ultima())
	}
	if !strings.Contains(out, "ya estaba sellado en el bloque 0") {
		t.Errorf("el duplicado tiene que decirse:\n%s", c.ultima())
	}
	if !strings.Contains(out, "bloque       : 1") {
		t.Errorf("el segundo sellado debería ser el bloque 1:\n%s", c.ultima())
	}

	// Y en --json, el campo que un integrador puede mirar.
	out, _, code = sealPayload(t, c, doc, "--json")
	if code != exitOK {
		t.Fatalf("código %d\n%s", code, c.ultima())
	}
	var v map[string]any
	if err := json.Unmarshal([]byte(out), &v); err != nil {
		t.Fatalf("%v\n%s", err, c.ultima())
	}
	dup, _ := v["duplicate_of"].([]any)
	if len(dup) != 2 || dup[0].(float64) != 0 || dup[1].(float64) != 1 {
		t.Errorf("duplicate_of = %v, want [0 1]", v["duplicate_of"])
	}
	if v["idempotent"] != false {
		t.Errorf("idempotent = %v en un sellado normal", v["idempotent"])
	}

	// Y --no-encrypt se comporta IGUAL, que es lo que antes no pasaba.
	out, _, code = sealPayload(t, c, doc, "--no-encrypt")
	if code != exitOK || !strings.Contains(out, "ya estaba sellado") {
		t.Errorf("--no-encrypt debería decir lo mismo (código %d):\n%s", code, c.ultima())
	}
}

// TestSelladoInterrumpidoNoBloqueaElReintento — ADR-020 §C, el caso del ERP que
// reintenta tras un timeout.
//
// El fallo se provoca de verdad: con el reloj atrasado, el bloque no encadena y el
// sellado falla. Antes, el contenido cifrado ya estaba escrito a esas alturas y el
// reintento con el reloj bien chocaba con su payload_hash para siempre.
func TestSelladoInterrumpidoNoBloqueaElReintento(t *testing.T) {
	c := newCLI(t)
	c.initLedger()
	c.sealFile(`{"primero":true}`)

	const doc = `{"el":"documento del reintento"}`
	f := ficheroUnico(t, c.dir, "reintento-*.json", doc)

	t.Setenv(envClock, "2026-09-07T09:00:00Z") // una hora ANTES del bloque anterior
	_, errOut, code := c.run("seal", "--tenant", testTenant, "--type", "sri.factura.v1", "--payload", f)
	if code != exitUsage {
		t.Fatalf("con el reloj atrasado el sellado debe fallar: código %d\n%s", code, c.ultima())
	}
	if !strings.Contains(errOut, "timestamp anterior") {
		t.Errorf("el fallo debería ser el del encadenamiento:\n%s", c.ultima())
	}

	t.Setenv(envClock, testClockRFC)
	if _, _, code := c.run("seal", "--tenant", testTenant, "--type", "sri.factura.v1", "--payload", f); code != exitOK {
		t.Fatalf("el reintento debe entrar: código %d\n%s", code, c.ultima())
	}
}

// TestHuerfanoAntiguoSeAdopta: un fichero de ANTES de ADR-020 puede llevar un blob sin
// bloque. Si es de este tenant, el sellado lo reutiliza en vez de atascarse.
func TestHuerfanoAntiguoSeAdopta(t *testing.T) {
	c := newCLI(t)
	c.initLedger()

	const doc = `{"huerfano":"de este tenant"}`
	sum := sha256.Sum256([]byte(doc))
	hash := hex.EncodeToString(sum[:])

	s, _, err := store.Open(filepath.Join(c.dir, "nucleo.db"))
	if err != nil {
		t.Fatal(err)
	}
	v, err := vault.Unlock(s, []byte(testPassphrase))
	if err != nil {
		t.Fatal(err)
	}
	ct, nonce, err := v.EncryptBlob(testTenant, hash, []byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.PutBlob(hash, ct, nonce); err != nil {
		t.Fatal(err)
	}
	v.Close()
	s.Close()

	out, _, code := sealPayload(t, c, doc)
	if code != exitOK {
		t.Fatalf("el huérfano de este tenant debería reutilizarse: código %d\n%s", code, c.ultima())
	}
	if !strings.Contains(out, "hash contenido: "+hash) {
		t.Errorf("el sellado no es del contenido esperado:\n%s", c.ultima())
	}
}

// TestContenidoDeOtroTenantSeRechazaConSuRazon — ADR-020 §B. No cabe en el esquema
// congelado de ADR-009, y aceptarlo daría a un tenant un bloque cuyo contenido no puede
// descifrar.
func TestContenidoDeOtroTenantSeRechazaConSuRazon(t *testing.T) {
	c := newCLI(t)
	c.initLedger()
	const doc = `{"el":"mismo documento"}`
	if _, _, code := sealPayload(t, c, doc); code != exitOK {
		t.Fatalf("código %d\n%s", code, c.ultima())
	}

	f := ficheroUnico(t, c.dir, "otro-*.json", doc)
	_, errOut, code := c.run("seal", "--tenant", "0999999999001", "--type", "sri.factura.v1", "--payload", f)
	if code != exitUsage {
		t.Fatalf("código %d, esperado %d\n%s", code, exitUsage, c.ultima())
	}
	for _, quiere := range []string{testTenant, "no podría descifrarla", "--no-encrypt", "ADR-020"} {
		if !strings.Contains(errOut, quiere) {
			t.Errorf("el error no dice %q:\n%s", quiere, c.ultima())
		}
	}

	// Con --no-encrypt sí puede: no hay copia cifrada que atar a nadie.
	if _, _, code := c.run("seal", "--tenant", "0999999999001", "--type", "sri.factura.v1", "--payload", f, "--no-encrypt"); code != exitOK {
		t.Errorf("--no-encrypt debería poder: código %d\n%s", code, c.ultima())
	}
}

// TestClaveDeIdempotenciaNoDuplicaElReintento — ADR-020 §D.
func TestClaveDeIdempotenciaNoDuplicaElReintento(t *testing.T) {
	c := newCLI(t)
	c.initLedger()
	const doc = `{"factura":"idem-001"}`
	const key = "factura-001"

	out, _, code := sealPayload(t, c, doc, "--idempotency-key", key, "--json")
	if code != exitOK {
		t.Fatalf("código %d\n%s", code, c.ultima())
	}
	primero := jsonDe(t, c, out)
	if primero["idempotent"] != false || primero["idempotency_key"] != key {
		t.Errorf("el primer sellado: %v", primero)
	}

	// El reintento: mismo bloque, nada escrito.
	out, _, code = sealPayload(t, c, doc, "--idempotency-key", key, "--json")
	if code != exitOK {
		t.Fatalf("el reintento debe salir con 0: código %d\n%s", code, c.ultima())
	}
	segundo := jsonDe(t, c, out)
	if segundo["idempotent"] != true {
		t.Errorf("idempotent = %v en un reintento", segundo["idempotent"])
	}
	for _, k := range []string{"index", "hash", "payload_hash", "encrypted"} {
		if fmt.Sprint(segundo[k]) != fmt.Sprint(primero[k]) {
			t.Errorf("%s = %v en el reintento, want %v", k, segundo[k], primero[k])
		}
	}
	// Y el ledger no ha crecido.
	st := jsonDe(t, c, c.mustRun("--json", "status"))
	if fmt.Sprint(st["tree_size"]) != "1" {
		t.Errorf("el ledger creció con el reintento: tree_size = %v", st["tree_size"])
	}

	// La misma clave para OTRO documento no es un reintento.
	_, errOut, code := sealPayload(t, c, `{"factura":"otra"}`, "--idempotency-key", key)
	if code != exitUsage {
		t.Fatalf("código %d, esperado %d\n%s", code, exitUsage, c.ultima())
	}
	if !strings.Contains(errOut, "ya se usó para otro documento") {
		t.Errorf("el error no explica el conflicto:\n%s", c.ultima())
	}

	// La misma clave con otro --type tampoco.
	f := ficheroUnico(t, c.dir, "tipo-*.json", doc)
	_, errOut, code = c.run("seal", "--tenant", testTenant, "--type", "sas.acta.v1", "--payload", f, "--idempotency-key", key)
	if code != exitUsage || !strings.Contains(errOut, "distinto tipo") {
		t.Errorf("mismo contenido y otro tipo son dos registros (código %d):\n%s", code, c.ultima())
	}

	// La clave está acotada por tenant: "factura-001" es de cualquiera.
	f = ficheroUnico(t, c.dir, "otrotenant-*.json", `{"de":"otro tenant"}`)
	if _, _, code := c.run("seal", "--tenant", "0999999999001", "--type", "sri.factura.v1", "--payload", f, "--idempotency-key", key); code != exitOK {
		t.Errorf("la clave de otro tenant no debería colisionar: código %d\n%s", code, c.ultima())
	}
}

// TestClaveDeIdempotenciaSeValida: vacía, enorme o con controles no entra.
func TestClaveDeIdempotenciaSeValida(t *testing.T) {
	c := newCLI(t)
	c.initLedger()
	casos := []struct {
		nombre, clave, dice string
	}{
		// Una variable de entorno sin definir en un cron produce exactamente esto, y
		// sellaría un duplicado creyendo que no. Es la lección de --policy-file.
		{"vacía", "", "no puede estar vacía"},
		{"con salto de línea", "a\nb", "carácter de control"},
		{"demasiado larga", strings.Repeat("k", maxIdemKey+1), "el máximo es"},
	}
	for _, cs := range casos {
		t.Run(cs.nombre, func(t *testing.T) {
			f := ficheroUnico(t, c.dir, "val-*.json", `{"x":`+fmt.Sprintf("%q", cs.nombre)+`}`)
			_, errOut, code := c.run("seal", "--tenant", testTenant, "--type", "sri.factura.v1", "--payload", f, "--idempotency-key", cs.clave)
			if code != exitUsage {
				t.Fatalf("código %d, esperado %d\n%s", code, exitUsage, c.ultima())
			}
			if !strings.Contains(errOut, cs.dice) {
				t.Errorf("el error no dice %q:\n%s", cs.dice, c.ultima())
			}
		})
	}
}

// TestRegistroDeIdempotenciaManipulado: log_state no está firmado, así que el bloque al
// que apunta la clave se lee del ledger y se compara. Un registro que apunta a un bloque
// que no está no es un sellado a medias —se escriben juntos—: es una manipulación.
func TestRegistroDeIdempotenciaManipulado(t *testing.T) {
	c := newCLI(t)
	c.initLedger()
	const doc = `{"factura":"manipulada"}`
	const key = "factura-777"
	if _, _, code := sealPayload(t, c, doc, "--idempotency-key", key); code != exitOK {
		t.Fatalf("código %d\n%s", code, c.ultima())
	}

	k := claveIdem(testTenant, key)
	db, err := sql.Open("sqlite", filepath.Join(c.dir, "nucleo.db"))
	if err != nil {
		t.Fatal(err)
	}
	var raw string
	if err := db.QueryRow(`SELECT v FROM log_state WHERE k = ?`, k).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var rec idemRecord
	if err := json.Unmarshal([]byte(raw), &rec); err != nil {
		t.Fatal(err)
	}
	rec.Block = 999
	nuevo, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE log_state SET v = ? WHERE k = ?`, string(nuevo), k); err != nil {
		t.Fatal(err)
	}
	db.Close()

	_, errOut, code := sealPayload(t, c, doc, "--idempotency-key", key)
	if code != exitVerify {
		t.Fatalf("código %d, esperado %d\n%s", code, exitVerify, c.ultima())
	}
	if !strings.Contains(errOut, "alguien ha tocado el fichero") {
		t.Errorf("el error no dice qué significa:\n%s", c.ultima())
	}
}

// jergaDelMotor caza el vocabulario del motor SQLite y sus códigos de resultado.
var jergaDelMotor = regexp.MustCompile(`(?i)sqlite|constraint|SQL logic|\(\d{3,4}\)`)

// TestNingunErrorDelMotorLlegaAlUsuario — ADR-020 §E. La regla es comprobable, que es
// lo único que evita que vuelva: `UNIQUE constraint failed: blobs.payload_hash (1555)`
// salía por la primera línea y, con --json, dentro del campo "error", es decir, entraba
// en el log del integrador como si fuera contrato.
func TestNingunErrorDelMotorLlegaAlUsuario(t *testing.T) {
	c := newCLI(t)
	c.initLedger()
	const doc = `{"factura":"jerga"}`
	c.mustRun("seal", "--tenant", testTenant, "--type", "sri.factura.v1",
		"--payload", ficheroUnico(t, c.dir, "jerga-*.json", doc))

	f := ficheroUnico(t, c.dir, "jerga2-*.json", doc)
	casos := [][]string{
		// Los cuatro caminos de H8, más los mismos con --json.
		{"seal", "--tenant", testTenant, "--type", "sri.factura.v1", "--payload", f},
		{"seal", "--tenant", "0999999999001", "--type", "sri.factura.v1", "--payload", f},
		{"--json", "seal", "--tenant", testTenant, "--type", "sri.factura.v1", "--payload", f},
		{"--json", "seal", "--tenant", "0999999999001", "--type", "sri.factura.v1", "--payload", f},
		{"seal", "--tenant", testTenant, "--type", "sri.factura.v1", "--payload", f, "--idempotency-key", ""},
		{"receipt", "--block", "9999", "--recipient", "Nadie", "--witness-name", "w", "--witness-key", strings.Repeat("ab", 32)},
		{"verify", "--full"},
		{"status"},
	}
	for _, args := range casos {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			out, errOut, _ := c.run(args...)
			for nombre, flujo := range map[string]string{"stdout": out, "stderr": errOut} {
				if m := jergaDelMotor.FindString(flujo); m != "" {
					t.Errorf("%s lleva jerga del motor (%q):\n%s", nombre, m, c.ultima())
				}
			}
		})
	}
}

// jsonDe decodifica una salida --json o aborta con el volcado.
func jsonDe(t *testing.T, c *cli, out string) map[string]any {
	t.Helper()
	var v map[string]any
	if err := json.Unmarshal([]byte(out), &v); err != nil {
		t.Fatalf("%v\n%s", err, c.ultima())
	}
	return v
}
