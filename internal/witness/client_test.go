package witness

import (
	"context"
	"crypto/ed25519"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/nucleoledger/nucleo/internal/checkpoint"
	"golang.org/x/mod/sumdb/note"
)

// forgedServer responde 200 con las líneas de firma que se le den, sin mirar la
// petición. Es un testigo mentiroso, o un intermediario en el camino: el spec no
// autentica el canal, así que ambos son el mismo adversario.
func forgedServer(t *testing.T, lines func() string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(lines()))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// cosignWith devuelve las líneas de firma que produciría un testigo con la
// semilla dada sobre la nota dada. Sirve para fabricar cosignatures ajenas.
func cosignWith(t *testing.T, name string, seedByte byte, msg []byte) string {
	t.Helper()
	w, err := New(name, ed25519.NewKeyFromSeed(seed(seedByte)), func() time.Time {
		return time.Unix(1_800_000_500, 0).UTC()
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := w.AddLog(logOrigin, ed25519.NewKeyFromSeed(seed(0)).Public().(ed25519.PublicKey)); err != nil {
		t.Fatal(err)
	}
	cosigned, err := w.Cosign(msg, nil)
	if err != nil {
		t.Fatal(err)
	}
	lines, err := SignatureLines(msg, cosigned)
	if err != nil {
		t.Fatal(err)
	}
	return string(lines)
}

// clientFor construye un cliente que confía SOLO en el testigo del harness.
func clientFor(t *testing.T, url string) *Client {
	t.Helper()
	c, err := NewClient(url, witnessName, ed25519.NewKeyFromSeed(seed(100)).Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// TestClientRejectsCosignatureFromAnotherKey es EL ESCENARIO DEL AUDITOR.
//
// El servidor devuelve un 200 impecable con una cosignature perfectamente bien
// formada... de otra clave. Antes, el cliente se quedaba con esos bytes y los
// daba por atestación: un 200 pasaba por prueba. No lo es. La única verdad
// autenticada es una cosignature que verifica contra la clave del testigo en el
// que se confía; todo lo demás son bytes con buena pinta.
func TestClientRejectsCosignatureFromAnotherKey(t *testing.T) {
	h := newHarness(t)
	msg := h.signAt(5)

	srv := forgedServer(t, func() string {
		// Firma legítima, testigo legítimo... pero NO el nuestro.
		return cosignWith(t, "witness.impostor/w9", 200, msg)
	})
	c := clientFor(t, srv.URL)

	got, err := c.AddCheckpoint(context.Background(), 0, nil, msg)
	if !errors.Is(err, ErrNoCosignature) {
		t.Fatalf("err = %v, want %v", err, ErrNoCosignature)
	}
	if got != nil {
		t.Error("se devolvieron bytes pese al rechazo")
	}
}

// TestClientRejectsCorruptedSignature: una firma del testigo correcto cuyos
// bytes fueron alterados en el camino.
func TestClientRejectsCorruptedSignature(t *testing.T) {
	h := newHarness(t)
	msg := h.signAt(5)
	good := cosignWith(t, witnessName, 100, msg)

	srv := forgedServer(t, func() string {
		// Se altera un carácter del base64, conservando nombre y key ID.
		i := strings.LastIndex(good, " ")
		blob := []byte(good[i+1:])
		for j := range blob {
			if blob[j] != 'A' && blob[j] != '\n' && blob[j] != '=' {
				blob[j] = 'A'
				break
			}
		}
		return good[:i+1] + string(blob)
	})
	c := clientFor(t, srv.URL)

	if _, err := c.AddCheckpoint(context.Background(), 0, nil, msg); !errors.Is(err, ErrNoCosignature) {
		t.Fatalf("err = %v, want %v", err, ErrNoCosignature)
	}
}

// TestClientAcceptsValidAmongUnknown es la otra mitad del MUST del spec: las
// cosignatures de claves desconocidas se IGNORAN, no invalidan la respuesta.
// Sin esto, un checkpoint que circulase con firmas de terceros dejaría de
// aceptarse, y el protocolo dejaría de componer.
func TestClientAcceptsValidAmongUnknown(t *testing.T) {
	h := newHarness(t)
	msg := h.signAt(5)

	srv := forgedServer(t, func() string {
		return cosignWith(t, "witness.otro/w1", 201, msg) +
			cosignWith(t, witnessName, 100, msg) +
			cosignWith(t, "witness.tercero/w2", 202, msg)
	})
	c := clientFor(t, srv.URL)

	cosigned, err := c.AddCheckpoint(context.Background(), 0, nil, msg)
	if err != nil {
		t.Fatalf("se rechazó una respuesta con la cosignature válida entre desconocidas: %v", err)
	}
	// La nota devuelta abre con nuestra clave y conserva las ajenas.
	n, err := note.Open(cosigned, note.VerifierList(clientFor(t, srv.URL).verifier))
	if err != nil {
		t.Fatal(err)
	}
	if len(n.Sigs) != 1 {
		t.Errorf("%d firmas verificadas, want 1", len(n.Sigs))
	}
	if len(n.UnverifiedSigs) < 3 {
		t.Errorf("%d firmas ignoradas, want al menos 3 (log + dos testigos ajenos)", len(n.UnverifiedSigs))
	}
	if c, err := checkpoint.ParseNote(cosigned); err != nil || c.Size != 5 {
		t.Errorf("la nota devuelta no es el checkpoint enviado: %+v, %v", c, err)
	}
}

// TestClientRejectsEmptyResponse: un 200 sin ninguna línea de firma tampoco es
// atestación.
func TestClientRejectsEmptyResponse(t *testing.T) {
	h := newHarness(t)
	msg := h.signAt(5)
	srv := forgedServer(t, func() string { return "" })
	c := clientFor(t, srv.URL)
	if _, err := c.AddCheckpoint(context.Background(), 0, nil, msg); !errors.Is(err, ErrNoCosignature) {
		t.Errorf("err = %v, want %v", err, ErrNoCosignature)
	}
}

// TestMonitorCheckpointIsVerified aplica el mismo criterio al endpoint de
// monitorización, que el spec permite delegar a una CDN y no autentica.
func TestMonitorCheckpointIsVerified(t *testing.T) {
	h := newHarness(t)
	msg := h.signAt(5)
	forged := msg
	forged = append(forged, cosignWith(t, "witness.impostor/w9", 200, msg)...)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(forged)
	}))
	t.Cleanup(srv.Close)

	c := clientFor(t, srv.URL)
	if _, err := c.Checkpoint(context.Background(), logOrigin); !errors.Is(err, ErrNoCosignature) {
		t.Errorf("err = %v, want %v", err, ErrNoCosignature)
	}
}

// TestNewClientRequiresWitnessIdentity: no se puede construir un cliente sin
// clave, porque sería un cliente que se cree lo que le digan.
func TestNewClientRequiresWitnessIdentity(t *testing.T) {
	if _, err := NewClient("http://x", "", nil); err == nil {
		t.Error("se construyó un cliente sin identidad del testigo")
	}
	if _, err := NewClient("http://x", "witness.example/w1", make([]byte, 10)); err == nil {
		t.Error("se construyó un cliente con una clave de 10 bytes")
	}
}
