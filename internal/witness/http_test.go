package witness

import (
	"context"
	"crypto/ed25519"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nucleoledger/nucleo/internal/checkpoint"
	"github.com/nucleoledger/nucleo/internal/ledger"
	"golang.org/x/mod/sumdb/note"
)

// httpHarness monta DOS partes que solo se hablan por HTTP: el log, que firma
// checkpoints, y el testigo, que corre en su propio servidor con su propia base
// de datos. No comparten memoria; comparten un puerto.
//
// Esa separación es el punto entero del ejercicio. Un testigo que viviera dentro
// del proceso del log no probaría nada: lo que da valor a su firma es que su
// recuerdo esté fuera del alcance de quien controla el ledger.
type httpHarness struct {
	*harness
	server *httptest.Server
	client *Client
}

func newHTTPHarness(t *testing.T) *httpHarness {
	t.Helper()
	h := newHarness(t)

	// El testigo del servidor tiene memoria PERSISTENTE en su propio SQLite.
	st, err := OpenState(filepath.Join(t.TempDir(), "witness.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })

	w, err := NewWithState(witnessName, ed25519.NewKeyFromSeed(seed(100)), h.clk.now, st)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.AddLog(logOrigin, ed25519.NewKeyFromSeed(seed(0)).Public().(ed25519.PublicKey)); err != nil {
		t.Fatal(err)
	}
	h.witness = w

	srv := httptest.NewServer(NewServer(w).Handler())
	t.Cleanup(srv.Close)
	client, err := NewClient(srv.URL, witnessName, ed25519.NewKeyFromSeed(seed(100)).Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	return &httpHarness{harness: h, server: srv, client: client}
}

// add envía un checkpoint por HTTP y devuelve la nota con las cosignatures ya
// incorporadas, que es lo que haría un log real con la respuesta.
func (h *httpHarness) add(t *testing.T, old uint64, proof [][]byte, msg []byte) ([]byte, error) {
	t.Helper()
	return h.client.AddCheckpoint(context.Background(), old, proof, msg)
}

// TestHTTPWitnessFullDialogue recorre el diálogo completo del protocolo: primer
// checkpoint, extensión con prueba, y retroceso.
func TestHTTPWitnessFullDialogue(t *testing.T) {
	h := newHTTPHarness(t)

	// 1. Primer checkpoint de este origin. El testigo no recuerda nada, así que
	// el tamaño anterior es 0 y la prueba DEBE venir vacía: el árbol vacío es
	// consistente con cualquier árbol.
	first := h.signAt(5)
	cosigned, err := h.add(t, 0, nil, first)
	if err != nil {
		t.Fatalf("el primer checkpoint no fue aceptado: %v", err)
	}
	if _, err := note.Open(cosigned, note.VerifierList(h.witness.Verifier())); err != nil {
		t.Fatalf("la cosignature devuelta no verifica: %v", err)
	}
	if !checkpoint.IsCosigned(cosigned) {
		t.Error("la nota devuelta no lleva una cosignature reconocible")
	}

	// 2. Extensión honesta de 5 a 9, con su prueba de consistencia.
	h.clk.advance(60)
	second := h.signAt(9)
	if _, err := h.add(t, 5, h.proof(5, 9), second); err != nil {
		t.Fatalf("la extensión honesta fue rechazada: %v", err)
	}
	if last, _ := h.witness.Last(logOrigin); last.Size != 9 {
		t.Fatalf("el testigo recuerda %d, want 9", last.Size)
	}

	// 3. Retroceso: se le declara un tamaño anterior que ya no es el suyo. El
	// spec exige 409 con el tamaño verdadero en el cuerpo, y esa cifra es lo
	// que permite a un log honesto reintentar sin adivinar.
	h.clk.advance(60)
	third := h.signAt(12)
	_, err = h.add(t, 5, h.proof(5, 12), third)
	var conflict *ConflictError
	if !errors.As(err, &conflict) {
		t.Fatalf("err = %v, want *ConflictError", err)
	}
	if conflict.LastSize != 9 {
		t.Errorf("el 409 declaró %d, want 9", conflict.LastSize)
	}

	// 4. Y con el tamaño correcto, la misma extensión pasa.
	if _, err := h.add(t, 9, h.proof(9, 12), third); err != nil {
		t.Fatalf("tras el 409, el reintento correcto falló: %v", err)
	}
}

// TestHTTPStatusCodes comprueba la tabla de códigos del spec una por una.
func TestHTTPStatusCodes(t *testing.T) {
	h := newHTTPHarness(t)
	if _, err := h.add(t, 0, nil, h.signAt(5)); err != nil {
		t.Fatal(err)
	}

	// Origin desconocido: 404. Se firma con otra clave Y otro origin.
	foreignPriv := ed25519.NewKeyFromSeed(seed(77))
	foreignSigner, err := checkpoint.NewSigner("otro.example/log", foreignPriv)
	if err != nil {
		t.Fatal(err)
	}
	foreign, err := checkpoint.Sign(checkpoint.Checkpoint{
		Origin: "otro.example/log", Size: 3, RootHash: ledger.Root(h.leaves[:3]),
	}, foreignSigner)
	if err != nil {
		t.Fatal(err)
	}

	// Origin conocido pero firmado por una clave que no es la suya: 403.
	impostorSigner, err := checkpoint.NewSigner(logOrigin, ed25519.NewKeyFromSeed(seed(88)))
	if err != nil {
		t.Fatal(err)
	}
	impostor, err := checkpoint.Sign(checkpoint.Checkpoint{
		Origin: logOrigin, Size: 7, RootHash: ledger.Root(h.leaves[:7]),
	}, impostorSigner)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name  string
		old   uint64
		proof [][]byte
		msg   []byte
		want  int
	}{
		{"origin desconocido", 0, nil, foreign, http.StatusNotFound},
		{"firmado por otra clave", 5, h.proof(5, 7), impostor, http.StatusForbidden},
		{"tamaño anterior mayor que el checkpoint", 9, nil, h.signBypassingLog(7, h.leaves), http.StatusBadRequest},
		{"tamaño anterior que no es el recordado", 2, h.proof(2, 7), h.signBypassingLog(7, h.leaves), http.StatusConflict},
		{"prueba que no verifica", 5, tamper(h.proof(5, 7)), h.signBypassingLog(7, h.leaves), http.StatusConflict},
		// Declarar 0 cuando el testigo recuerda 5 es un 409, no un 422: el spec
		// dice que un cliente sin información PUEDE mandar 0 justamente para
		// que el 409 le devuelva el tamaño verdadero. Se comprueba antes de
		// mirar si la prueba debería venir vacía.
		{"tamaño anterior 0 como sondeo", 0, h.proof(5, 7), h.signBypassingLog(7, h.leaves), http.StatusConflict},
		{"mismo tamaño con otra raíz", 5, nil, h.signBypassingLog(5, h.altered), http.StatusUnprocessableEntity},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			body, err := MarshalAddCheckpoint(AddCheckpointRequest{OldSize: c.old, Proof: c.proof, Note: c.msg})
			if err != nil {
				t.Fatal(err)
			}
			resp, err := http.Post(h.server.URL+AddCheckpointPath, "text/plain", strings.NewReader(string(body)))
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != c.want {
				t.Errorf("HTTP %d, want %d", resp.StatusCode, c.want)
			}
			if c.want == http.StatusConflict {
				if ct := resp.Header.Get("Content-Type"); ct != SizeContentType {
					t.Errorf("Content-Type = %q, want %q", ct, SizeContentType)
				}
			}
		})
	}

	// El estado del testigo no se movió con ninguno de los rechazos.
	if last, _ := h.witness.Last(logOrigin); last.Size != 5 {
		t.Errorf("el testigo recuerda %d tras los rechazos, want 5", last.Size)
	}
}

// TestMonitorEndpoint cubre la ruta de monitorización, que es la que hace
// posible detectar un rollback local.
func TestMonitorEndpoint(t *testing.T) {
	h := newHTTPHarness(t)

	// Antes de cosignar nada: 404.
	if _, err := h.client.Checkpoint(context.Background(), logOrigin); !errors.Is(err, ErrNoWitnessCheckpoint) {
		t.Errorf("err = %v, want %v", err, ErrNoWitnessCheckpoint)
	}

	if _, err := h.add(t, 0, nil, h.signAt(5)); err != nil {
		t.Fatal(err)
	}
	got, err := h.client.Checkpoint(context.Background(), logOrigin)
	if err != nil {
		t.Fatal(err)
	}
	c, err := checkpoint.ParseNote(got)
	if err != nil {
		t.Fatal(err)
	}
	if c.Size != 5 || c.Origin != logOrigin {
		t.Errorf("checkpoint devuelto = %+v, want tamaño 5 de %q", c, logOrigin)
	}
	// El spec exige que lleve la cosignature del testigo Y la firma del log.
	if _, err := note.Open(got, note.VerifierList(h.witness.Verifier())); err != nil {
		t.Errorf("el checkpoint servido no lleva la cosignature del testigo: %v", err)
	}
	if !checkpoint.IsCosigned(got) {
		t.Error("el checkpoint servido no está cosignado")
	}

	// Un origin que el testigo no conoce: 404.
	if _, err := h.client.Checkpoint(context.Background(), "otro.example/log"); !errors.Is(err, ErrNoWitnessCheckpoint) {
		t.Errorf("origin desconocido: err = %v, want %v", err, ErrNoWitnessCheckpoint)
	}
}

// TestWitnessRemembersAcrossRestart es lo que separa un testigo de un adorno: su
// recuerdo tiene que sobrevivir al reinicio. Si lo olvidara, bastaría con
// tumbarlo para que volviera a avalar una historia recortada.
func TestWitnessRemembersAcrossRestart(t *testing.T) {
	h := newHarness(t)
	path := filepath.Join(t.TempDir(), "witness.db")

	st, err := OpenState(path)
	if err != nil {
		t.Fatal(err)
	}
	w, err := NewWithState(witnessName, ed25519.NewKeyFromSeed(seed(100)), h.clk.now, st)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.AddLog(logOrigin, ed25519.NewKeyFromSeed(seed(0)).Public().(ed25519.PublicKey)); err != nil {
		t.Fatal(err)
	}
	if _, err := w.CosignAt(0, h.signAt(9), nil); err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}

	// Reinicio: otro proceso, misma base.
	st2, err := OpenState(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st2.Close()
	w2, err := NewWithState(witnessName, ed25519.NewKeyFromSeed(seed(100)), h.clk.now, st2)
	if err != nil {
		t.Fatal(err)
	}
	if err := w2.AddLog(logOrigin, ed25519.NewKeyFromSeed(seed(0)).Public().(ed25519.PublicKey)); err != nil {
		t.Fatal(err)
	}
	last, ok := w2.Last(logOrigin)
	if !ok || last.Size != 9 {
		t.Fatalf("tras reiniciar recuerda %+v (ok=%v), want tamaño 9", last, ok)
	}

	// Y sigue negándose a avalar un retroceso.
	h.clk.advance(60)
	if _, err := w2.CosignAt(5, h.signBypassingLog(6, h.leaves), h.proof(5, 6)); !errors.Is(err, ErrConflict) {
		t.Errorf("tras reiniciar aceptó un retroceso: %v", err)
	}
}

// TestEmptyTreeCheckpointRules cubre las dos reglas del árbol vacío, que solo se
// pueden probar sobre un origin del que el testigo no recuerda nada.
func TestEmptyTreeCheckpointRules(t *testing.T) {
	h := newHTTPHarness(t)

	// Un checkpoint de tamaño 0 SOLO puede llevar la raíz del árbol vacío, que
	// RFC 6962 §2.1 define como SHA-256 de la cadena vacía.
	bad, err := checkpoint.Sign(checkpoint.Checkpoint{
		Origin: logOrigin, Size: 0, RootHash: ledger.Root(h.leaves[:1]),
	}, logSignerFor(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.add(t, 0, nil, bad); !errors.Is(err, ErrUnprocessable) && !strings.Contains(err.Error(), "422") {
		t.Errorf("tamaño 0 con raíz ajena: err = %v, want 422", err)
	}

	good, err := checkpoint.Sign(checkpoint.Checkpoint{
		Origin: logOrigin, Size: 0, RootHash: emptyTreeRoot,
	}, logSignerFor(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.add(t, 0, nil, good); err != nil {
		t.Errorf("tamaño 0 con la raíz del árbol vacío fue rechazado: %v", err)
	}
}

// logSignerFor construye un firmante con la clave del log del harness.
func logSignerFor(t *testing.T) note.Signer {
	t.Helper()
	s, err := checkpoint.NewSigner(logOrigin, ed25519.NewKeyFromSeed(seed(0)))
	if err != nil {
		t.Fatal(err)
	}
	return s
}
