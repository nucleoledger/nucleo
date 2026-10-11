//go:build testhooks

package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nucleoledger/nucleo/internal/erasure"
	"github.com/nucleoledger/nucleo/internal/ledger"
	"github.com/nucleoledger/nucleo/internal/proof"
	"github.com/nucleoledger/nucleo/internal/receipt"
	"github.com/nucleoledger/nucleo/internal/store"
)

// TestLaSupresionDejaLaCadenaYLosRecibos es el test que pide ADR-031: tras suprimir
// el contenido de un registro, la cadena verifica, el recibo que ya se había
// entregado verifica, se puede emitir uno nuevo, y la reconciliación informa la
// supresión en vez de un registro desaparecido. Con la autorización de la clave de
// supresión de la política, que es lo que hace que cuente (ADR-032).
func TestLaSupresionDejaLaCadenaYLosRecibos(t *testing.T) {
	c := newCLI(t)
	sp := c.initConSupresion(t)
	// El bloque 0, con perfil: tiene copia cifrada Y compromisos.
	xmlPath := c.facturaXML(t, claveDemo())
	c.mustRun("seal", "--profile", "ecuador.sri.factura", "--xml", xmlPath)
	c.sealFile(`{"factura":"002","importe":"75.00"}`)

	url, name, key := sp.url, sp.name, sp.key
	testigo := []string{"--witness-name", name, "--witness-key", key}
	c.mustRun(append([]string{"sync", "--witness", url}, testigo...)...)

	// El recibo que ya se entregó, ANTES de suprimir.
	reciboViejo := filepath.Join(c.dir, "recibo-0.txt")
	c.mustRun(append([]string{"receipt", "--block", "0", "--recipient", "María Pérez", "--out", reciboViejo}, testigo...)...)

	h0, ct0 := contenidoDe(t, c.dir, 0)
	if ct0 == nil {
		t.Fatal("el bloque 0 no tenía copia cifrada: el test no comprobaría nada")
	}
	if !hayMeta(t, c.dir, metaCommitPrefix+h0) {
		t.Fatal("el bloque 0 no tenía compromisos: el test no comprobaría nada")
	}

	// Sin supresión, que el sistema vivo no tenga el bloque 0 es un hallazgo.
	vivos := ficheroVivo(t, c.dir, 1, `{"factura":"002","importe":"75.00"}`)
	c.runWant(t, exitVerify, "reconcile", "--source", vivos, "--policy-file", sp.politica)

	out := c.mustRun("--json", "erase", "--block", "0", "--policy-file", sp.politica,
		"--authorization", c.autoriza(t, sp, h0, 0), "--assume-confirmed")
	var r struct {
		Index         uint64   `json:"index"`
		ErasedHash    string   `json:"erased_payload_hash"`
		Blocks        []uint64 `json:"blocks"`
		AlreadyErased bool     `json:"already_erased"`
		WALPurged     bool     `json:"wal_purged"`
	}
	if err := json.Unmarshal([]byte(out), &r); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if r.Index != 2 || r.ErasedHash != h0 || len(r.Blocks) != 1 || r.Blocks[0] != 0 || r.AlreadyErased || !r.WALPurged {
		t.Errorf("salida de erase: %+v", r)
	}

	// El contenido y los compromisos ya no están.
	if _, ct := contenidoDe(t, c.dir, 0); ct != nil {
		t.Error("la copia cifrada sigue en el ledger")
	}
	if hayMeta(t, c.dir, metaCommitPrefix+h0) {
		t.Error("los compromisos siguen en el ledger")
	}
	// El evento es un bloque normal, del tipo reservado y con el contenido del vector.
	ev := bloqueDeCLI(t, c.dir, 2)
	if want, _ := erasure.EventPayloadHash(h0); ev.Header.Type != erasure.Type || ev.Header.PayloadHash != want || !strings.HasPrefix(ev.Header.PayloadCID, erasure.AuthPrefix+"0:") {
		t.Errorf("evento: %+v", ev.Header)
	}

	// La cadena verifica, también la exhaustiva.
	c.mustRun("verify", "--full")
	c.mustRun(append([]string{"sync", "--witness", url}, testigo...)...)

	// El recibo que ya se había entregado sigue verificando.
	pol := politicaDe(t, c, name, key)
	raw, err := os.ReadFile(reciboViejo)
	if err != nil {
		t.Fatal(err)
	}
	rec, err := receipt.Parse(raw, pol)
	if err != nil {
		t.Fatalf("el recibo entregado antes de suprimir ya no se lee: %v", err)
	}
	if _, err := rec.Verify(pol); err != nil {
		t.Errorf("el recibo entregado antes de suprimir ya no verifica: %v", err)
	}
	// Y se pueden emitir recibos nuevos: del bloque suprimido y del evento.
	c.mustRun(append([]string{"receipt", "--block", "0", "--recipient", "María Pérez"}, testigo...)...)
	c.mustRun(append([]string{"receipt", "--block", "2", "--recipient", "Auditoría"}, testigo...)...)

	// La reconciliación lo informa como suprimido, y sale bien.
	rout, _ := c.runWant(t, exitOK, "--json", "reconcile", "--source", vivos, "--policy-file", sp.politica)
	var rr struct {
		Findings []any `json:"findings"`
		Erased   []struct {
			Index    uint64 `json:"index"`
			ErasedBy uint64 `json:"erased_by"`
		} `json:"erased"`
	}
	if err := json.Unmarshal([]byte(rout), &rr); err != nil {
		t.Fatal(err)
	}
	if len(rr.Findings) != 0 || len(rr.Erased) != 1 || rr.Erased[0].Index != 0 || rr.Erased[0].ErasedBy != 2 {
		t.Errorf("reconcile tras suprimir:\n%s", rout)
	}
	texto := c.mustRun("reconcile", "--source", vivos, "--policy-file", sp.politica)
	if !strings.Contains(texto, "contenido SUPRIMIDO") {
		t.Errorf("reconcile en texto no dice que se suprimió:\n%s", texto)
	}
	// Sin la política, la misma supresión no se puede comprobar, y no cuenta (ADR-032).
	sinPol, _ := c.runWant(t, exitVerify, "reconcile", "--source", vivos)
	if !strings.Contains(sinPol, "SUPRESIÓN SIN AUTORIZACIÓN VÁLIDA") || !strings.Contains(sinPol, "--policy-file") {
		t.Errorf("reconcile sin política no lo explica:\n%s", sinPol)
	}

	// Pedirlo otra vez no sella otro evento, ni pide otra autorización.
	otra := c.mustRun("--json", "erase", "--block", "0", "--policy-file", sp.politica, "--assume-confirmed")
	if !strings.Contains(otra, `"already_erased": true`) {
		t.Errorf("segunda supresión:\n%s", otra)
	}
	if n := bloques(t, c.dir); n != 3 {
		t.Errorf("tras pedirlo dos veces hay %d bloques, want 3", n)
	}
}

// TestLaSupresionPideConfirmacion: sin confirmación no se suprime nada, y con --json
// la confirmación hay que pedirla saltar explícitamente.
func TestLaSupresionPideConfirmacion(t *testing.T) {
	c := newCLI(t)
	sp := c.initConSupresion(t)
	c.sealFile(`{"factura":"001","cliente":"María Pérez"}`)
	h, _ := contenidoDe(t, c.dir, 0)
	conAut := []string{"erase", "--block", "0", "--policy-file", sp.politica, "--authorization", c.autoriza(t, sp, h, 0)}

	_, errOut := c.runWant(t, exitUsage, append([]string{"--json"}, conAut...)...)
	if !strings.Contains(errOut+c.ultima(), "--assume-confirmed") {
		t.Errorf("no dice cómo confirmar en --json:\n%s", c.ultima())
	}

	conEntrada(t, "00000000\n", func() {
		c.runWant(t, exitUsage, conAut...)
	})
	if _, ct := contenidoDe(t, c.dir, 0); ct == nil || bloques(t, c.dir) != 1 {
		t.Fatal("una confirmación equivocada suprimió algo")
	}

	conEntrada(t, h[:prefijoConfirmacion]+"\n", func() {
		c.runWant(t, exitOK, conAut...)
	})
	if _, ct := contenidoDe(t, c.dir, 0); ct != nil || bloques(t, c.dir) != 2 {
		t.Error("la confirmación correcta no suprimió")
	}
}

// TestNoSeSuprimeLoQueNoSeGuardo: un bloque sellado con --no-encrypt y sin perfil no
// tiene nada que suprimir, y se dice por qué en vez de sellar un evento vacío.
func TestNoSeSuprimeLoQueNoSeGuardo(t *testing.T) {
	c := newCLI(t)
	sp := c.initConSupresion(t)
	c.mustRun("seal", "--tenant", testTenant, "--type", "sri.factura.v1", "--no-encrypt",
		"--payload", c.writeTemp(t, `{"factura":"001"}`))
	_, errOut := c.runWant(t, exitUsage, "erase", "--block", "0", "--policy-file", sp.politica, "--assume-confirmed")
	if !strings.Contains(errOut, "--no-encrypt") {
		t.Errorf("no explica por qué no hay nada que suprimir:\n%s", errOut)
	}
	c.runWant(t, exitUsage, "erase", "--block", "7", "--policy-file", sp.politica, "--assume-confirmed")
	if bloques(t, c.dir) != 1 {
		t.Error("se selló algo")
	}
}

// TestSealNoAceptaTiposReservados: un integrador no puede sellar un evento de
// supresión a mano; haría pasar un registro desaparecido por uno suprimido.
func TestSealNoAceptaTiposReservados(t *testing.T) {
	c := newCLI(t)
	c.initLedger()
	for _, typ := range []string{erasure.Type, "nucleo.cualquier.v1"} {
		_, errOut := c.runWant(t, exitUsage, "seal", "--tenant", testTenant, "--type", typ,
			"--payload", c.writeTemp(t, `{"erased_payload_hash":"x"}`))
		if !strings.Contains(errOut, "reservado") {
			t.Errorf("--type %s: %s", typ, errOut)
		}
	}
}

// conSupresion es el despliegue de los tests de supresión (ADR-032): un testigo, la
// política con la erasureKey y las tarjetas de la clave de supresión en el gancho de
// prueba, que es como las teclearía la custodia.
type conSupresion struct {
	politica          string
	url, name, key    string
	erasureKey        string
	tarjetasSupresion []string
}

// initConSupresion crea el despliegue, genera la clave de supresión con la CLI y escribe
// la política con su clave pública.
func (c *cli) initConSupresion(t *testing.T) *conSupresion {
	t.Helper()
	c.initLedger()
	sp := &conSupresion{}
	sp.url, sp.name, sp.key = startTestWitness(t, c.logPubKey(t))
	out := c.mustRun("--json", "erasure-key", "init", "--assume-confirmed")
	var v struct {
		ErasureKey string   `json:"erasure_key"`
		Shares     []string `json:"shares"`
	}
	if err := json.Unmarshal([]byte(out), &v); err != nil || len(v.Shares) < 2 {
		t.Fatalf("erasure-key init --json no dio tarjetas (%v):\n%s", err, out)
	}
	sp.erasureKey, sp.tarjetasSupresion = v.ErasureKey, v.Shares
	raw, err := json.Marshal(policyDoc{Origin: testOrigin, LogKey: c.logPubKey(t), ErasureKey: v.ErasureKey,
		Witnesses: map[string]string{sp.name: sp.key}, Quorum: 1})
	if err != nil {
		t.Fatal(err)
	}
	sp.politica = filepath.Join(c.dir, "politica.json")
	if err := os.WriteFile(sp.politica, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(envCards, v.Shares[0]+"|"+v.Shares[1])
	return sp
}

// autoriza pide a la CLI, como lo haría la custodia, la autorización de suprimir el
// contenido h hasta el bloque through.
func (c *cli) autoriza(t *testing.T, sp *conSupresion, h string, through uint64) string {
	t.Helper()
	out := c.mustRun("--json", "erasure-key", "authorize", "--policy-file", sp.politica,
		"--payload-hash", h, "--through", fmt.Sprint(through))
	var v struct {
		Authorization string `json:"authorization"`
	}
	if err := json.Unmarshal([]byte(out), &v); err != nil || v.Authorization == "" {
		t.Fatalf("erasure-key authorize --json (%v):\n%s", err, out)
	}
	return v.Authorization
}

// contenidoDe devuelve el payload_hash del bloque y su copia cifrada, o nil.
func contenidoDe(t *testing.T, dir string, idx uint64) (string, []byte) {
	t.Helper()
	b := bloqueDeCLI(t, dir, idx)
	s, _, err := openStoreAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	blob, err := s.GetBlob(b.Header.PayloadHash)
	if errors.Is(err, store.ErrNotFound) {
		return b.Header.PayloadHash, nil
	}
	if err != nil {
		t.Fatal(err)
	}
	return b.Header.PayloadHash, blob.Ciphertext
}

func hayMeta(t *testing.T, dir, k string) bool {
	t.Helper()
	s, _, err := openStoreAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	_, err = s.GetMeta(k)
	if errors.Is(err, store.ErrNotFound) {
		return false
	}
	if err != nil {
		t.Fatal(err)
	}
	return true
}

func bloqueDeCLI(t *testing.T, dir string, idx uint64) *ledger.Block {
	t.Helper()
	s, _, err := openStoreAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	b, err := bloqueEnIndice(s, idx)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func bloques(t *testing.T, dir string) int {
	t.Helper()
	s, _, err := openStoreAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	n, err := s.Count()
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// ficheroVivo escribe el JSONL de un sistema vivo con un único registro.
func ficheroVivo(t *testing.T, dir string, idx uint64, payload string) string {
	t.Helper()
	linea := fmt.Sprintf(`{"index":%d,"payload_b64":%q}`+"\n", idx, base64.StdEncoding.EncodeToString([]byte(payload)))
	return ficheroUnico(t, dir, "vivo-*.jsonl", linea)
}

// politicaDe es la política de quien recibe el recibo: origin y clave del log, la
// clave del firmante y el testigo, todo de fuera del recibo.
func politicaDe(t *testing.T, c *cli, name, key string) proof.Policy {
	t.Helper()
	logKey, err := hex.DecodeString(c.logPubKey(t))
	if err != nil {
		t.Fatal(err)
	}
	signer, err := hex.DecodeString(bloqueDeCLI(t, c.dir, 0).Header.SignerPubKey)
	if err != nil {
		t.Fatal(err)
	}
	wk, err := hex.DecodeString(key)
	if err != nil {
		t.Fatal(err)
	}
	return proof.Policy{
		Origin:    testOrigin,
		LogKey:    ed25519.PublicKey(logKey),
		SignerKey: ed25519.PublicKey(signer),
		Witnesses: map[string]ed25519.PublicKey{name: ed25519.PublicKey(wk)},
		Quorum:    1,
	}
}

// conEntrada ejecuta fn con la entrada estándar sustituida por texto.
func conEntrada(t *testing.T, texto string, fn func()) {
	t.Helper()
	f := ficheroUnico(t, t.TempDir(), "stdin-*", texto)
	in, err := os.Open(f)
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	viejo := os.Stdin
	os.Stdin = in
	defer func() { os.Stdin = viejo }()
	fn()
}
