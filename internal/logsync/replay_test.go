package logsync

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nucleoledger/nucleo/internal/checkpoint"
	"github.com/nucleoledger/nucleo/internal/store"
	"github.com/nucleoledger/nucleo/internal/witness"
	_ "modernc.org/sqlite"
)

// replayProxy se pone entre el log y el testigo. Deja pasar todo salvo el
// endpoint de monitorización, donde sirve una nota VIEJA Y GENUINA del testigo
// en lugar de la actual.
//
// Es el adversario realista: el spec no autentica el canal y permite delegar el
// prefijo de monitorización a una CDN, así que servir una respuesta caducada no
// exige romper ninguna firma. Solo hay que guardar una que fue buena.
type replayProxy struct {
	upstream string
	stale    []byte
	hits     int
}

func (p *replayProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if strings.HasSuffix(r.URL.Path, "/checkpoint") && p.stale != nil {
		p.hits++
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Write(p.stale)
		return
	}
	req, err := http.NewRequestWithContext(r.Context(), r.Method, p.upstream+r.URL.Path, r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	for k, vs := range resp.Header {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

// TestSyncRejectsReplayedStaleAttestation es EL ESCENARIO DEL AUDITOR, montado
// con dos sincronizaciones reales: una con 6 bloques y otra con 12. La primera
// deja una cosignature GENUINA de tamaño 6, que es la munición del replay.
//
// El log se trunca después a 6 y el endpoint de monitorización devuelve aquella
// nota vieja. Es auténtica: su firma verifica, la emitió el testigo de verdad.
// Verificarla no basta, y esa es la lección. Antes el tamaño coincidía con el
// local y la sincronización devolvía éxito. Ahora no hay atajo: se pide
// atestación del estado actual, el testigo real contesta que recuerda 12, y el
// rollback sale a la luz.
func TestSyncRejectsReplayedStaleAttestation(t *testing.T) {
	sc := newScene(t, 6)
	ctx := context.Background()

	// 1. Sincronización honesta con 6 bloques. Guardamos la nota GENUINA.
	res6, err := SyncWithWitness(ctx, sc.adapter, sc.client)
	if err != nil {
		t.Fatal(err)
	}
	if !res6.Attested {
		t.Fatal("la primera sincronización no quedó atestiguada")
	}
	genuine6 := append([]byte(nil), res6.Cosigned...)
	if c, err := checkpoint.ParseNote(genuine6); err != nil || c.Size != 6 {
		t.Fatalf("la nota guardada no es de tamaño 6: %+v %v", c, err)
	}

	// 2. El log crece a 12 y se vuelve a sincronizar. El testigo pasa a recordar 12.
	sc.appendMore(t, 6)
	if _, err := SyncWithWitness(ctx, sc.adapter, sc.client); err != nil {
		t.Fatal(err)
	}
	if last, _ := sc.witness.Last(testOrigin); last.Size != 12 {
		t.Fatalf("el testigo recuerda %d, want 12", last.Size)
	}

	// 3. El ataque: truncar el fichero a 6 y reproducir la nota vieja.
	if err := sc.store.Close(); err != nil {
		t.Fatal(err)
	}
	truncate(t, sc.dbPath, 6)

	proxy := &replayProxy{upstream: sc.server.URL, stale: genuine6}
	front := httptest.NewServer(proxy)
	t.Cleanup(front.Close)

	s2, openState, err := store.Open(sc.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s2.Close() })
	if openState.TreeSize != 6 {
		t.Fatalf("tras truncar hay %d bloques, want 6", openState.TreeSize)
	}
	adapter := sc.rebind(t, s2)

	client, err := witness.NewClient(front.URL, "witness.example/w1",
		keyFrom(90).Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}

	// 4. La nota reproducida ES auténtica: el cliente la acepta como firma.
	replayed, err := client.Checkpoint(ctx, testOrigin)
	if err != nil {
		t.Fatalf("la nota reproducida debería verificar —es genuina—: %v", err)
	}
	if c, _ := checkpoint.ParseNote(replayed); c.Size != 6 {
		t.Fatalf("el proxy no sirvió la nota vieja: tamaño %d", c.Size)
	}

	// 5. Y aun así la sincronización NO puede terminar en OK.
	res, err := SyncWithWitness(ctx, adapter, client)
	if err == nil {
		t.Fatalf("la sincronización devolvió ÉXITO con una nota reproducida: %+v", res)
	}
	var rb *RollbackError
	if !errors.As(err, &rb) {
		t.Fatalf("err = %v, want *RollbackError", err)
	}
	if rb.LocalSize != 6 || rb.WitnessSize != 12 {
		t.Errorf("RollbackError = %+v, want local 6 y testigo 12", rb)
	}
	if proxy.hits == 0 {
		t.Error("el proxy no llegó a servir la nota vieja: el escenario no se montó")
	}
}

// TestSyncNeverShortCircuits comprueba que una sincronización sin novedades
// TAMBIÉN pide atestación del estado actual. Es lo que impide que "el testigo
// parece al día" se confunda con "el testigo avala lo que tengo".
func TestSyncNeverShortCircuits(t *testing.T) {
	sc := newScene(t, 4)
	ctx := context.Background()

	first, err := SyncWithWitness(ctx, sc.adapter, sc.client)
	if err != nil {
		t.Fatal(err)
	}
	second, err := SyncWithWitness(ctx, sc.adapter, sc.client)
	if err != nil {
		t.Fatalf("segunda sincronización sin novedades: %v", err)
	}
	if !second.Attested {
		t.Error("la segunda pasada no quedó atestiguada")
	}
	if second.WitnessSize != 4 || second.LocalSize != 4 {
		t.Errorf("resultado = %+v, want 4 y 4", second)
	}
	// La cosignature es NUEVA: se pidió otra vez, no se reutilizó la anterior.
	if string(first.Cosigned) == string(second.Cosigned) {
		t.Error("se devolvió la misma nota: hubo atajo")
	}
	// Pero en disco se conserva la PRIMERA, que es la de timestamp menor y por
	// tanto la mejor prueba de tiempo demostrable.
	stored, err := sc.store.Checkpoint(4)
	if err != nil {
		t.Fatal(err)
	}
	if string(stored) != string(first.Cosigned) {
		t.Error("la nota persistida no es la primera")
	}
}

// truncate ejecuta el ataque por SQL directo.
func truncate(t *testing.T, path string, keep int) {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, stmt := range []string{
		`DROP TRIGGER IF EXISTS blocks_no_delete`,
		`DROP TRIGGER IF EXISTS blocks_no_update`,
		`DROP TRIGGER IF EXISTS checkpoints_no_delete`,
		`DROP TRIGGER IF EXISTS checkpoints_no_update`,
		`DELETE FROM checkpoints`,
		`DELETE FROM blocks WHERE idx >= ` + itoa(keep),
		`DELETE FROM log_state`,
	} {
		if _, err := db.Exec(stmt); err != nil {
			t.Fatalf("%s: %v", stmt, err)
		}
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
