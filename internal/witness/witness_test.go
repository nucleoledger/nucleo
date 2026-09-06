package witness

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/nucleoledger/nucleo/internal/checkpoint"
	"github.com/nucleoledger/nucleo/internal/ledger"
	"golang.org/x/mod/sumdb/note"
)

const (
	logOrigin   = "nucleoledger.com/poc"
	witnessName = "witness.nucleoledger.com/w1"
)

func seed(b byte) []byte {
	s := make([]byte, ed25519.SeedSize)
	for i := range s {
		s[i] = b + byte(i)
	}
	return s
}

// clock es un reloj determinista y controlable desde el test.
type clock struct{ t int64 }

func (c *clock) now() time.Time  { return time.Unix(c.t, 0).UTC() }
func (c *clock) advance(d int64) { c.t += d }

// harness monta un log firmante y un testigo que lo conoce.
type harness struct {
	t       *testing.T
	log     *checkpoint.Log
	witness *Witness
	clk     *clock
	leaves  [][]byte
	// altered son las mismas hojas con una cambiada: sirven para construir un
	// árbol del mismo tamaño y distinta raíz, que es una reescritura.
	altered [][]byte
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	logPriv := ed25519.NewKeyFromSeed(seed(0))
	logSigner, err := checkpoint.NewSigner(logOrigin, logPriv)
	if err != nil {
		t.Fatal(err)
	}
	l, err := checkpoint.NewLog(logOrigin, logSigner)
	if err != nil {
		t.Fatal(err)
	}

	clk := &clock{t: 1_800_000_000}
	w, err := New(witnessName, ed25519.NewKeyFromSeed(seed(100)), clk.now)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.AddLog(logOrigin, logPriv.Public().(ed25519.PublicKey)); err != nil {
		t.Fatal(err)
	}

	leaves := make([][]byte, 64)
	for i := range leaves {
		leaves[i] = []byte(fmt.Sprintf("bloque-%d", i))
	}
	altered := append([][]byte{}, leaves...)
	altered[1] = []byte("bloque-1-suplantado")
	return &harness{t: t, log: l, witness: w, clk: clk, leaves: leaves, altered: altered}
}

// signAt emite un checkpoint del árbol formado por las primeras n hojas.
func (h *harness) signAt(n int) []byte {
	h.t.Helper()
	msg, err := h.log.Sign(checkpoint.Checkpoint{
		Origin: logOrigin, Size: uint64(n), RootHash: ledger.Root(h.leaves[:n]),
	})
	if err != nil {
		h.t.Fatalf("el log rechazó firmar el tamaño %d: %v", n, err)
	}
	return msg
}

// signBypassingLog firma un checkpoint con la clave del log pero desde un Log
// recién creado, saltándose así el cerrojo local de checkpoint.Log. Es el
// escenario realista: un operador que manipula su base de datos, no un cliente
// que llama a una API. El cerrojo del log es una barandilla; el testigo es la
// garantía.
func (h *harness) signBypassingLog(size int, leaves [][]byte) []byte {
	h.t.Helper()
	signer, err := checkpoint.NewSigner(logOrigin, ed25519.NewKeyFromSeed(seed(0)))
	if err != nil {
		h.t.Fatal(err)
	}
	l, err := checkpoint.NewLog(logOrigin, signer)
	if err != nil {
		h.t.Fatal(err)
	}
	msg, err := l.Sign(checkpoint.Checkpoint{
		Origin: logOrigin, Size: uint64(size), RootHash: ledger.Root(leaves[:size]),
	})
	if err != nil {
		h.t.Fatal(err)
	}
	return msg
}

// proof devuelve PROOF(old, D[new]) sobre el árbol honesto.
func (h *harness) proof(old, new int) [][]byte {
	h.t.Helper()
	p, err := ledger.ConsistencyProof(h.leaves[:new], old)
	if err != nil {
		h.t.Fatal(err)
	}
	return p
}

// cosignatureOf extrae la timestamped_signature del testigo en una nota.
func cosignatureOf(t *testing.T, msg []byte, w *Witness) []byte {
	t.Helper()
	n, err := note.Open(msg, note.VerifierList(w.Verifier()))
	if err != nil {
		t.Fatalf("no se pudo abrir la nota cosignada: %v", err)
	}
	for _, sig := range n.Sigs {
		if sig.Name != w.Name() {
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(sig.Base64)
		if err != nil {
			t.Fatal(err)
		}
		return raw[4:] // los 4 primeros bytes son el key hash
	}
	t.Fatal("la nota no trae cosignature del testigo")
	return nil
}

// TestCosignatureIsVerifiable comprueba el formato de c2sp.org/tlog-cosignature@v1:
// 72 bytes, timestamp presente, y firma que valida con la pública del testigo.
func TestCosignatureIsVerifiable(t *testing.T) {
	h := newHarness(t)
	cosigned, err := h.witness.Cosign(h.signAt(5), nil)
	if err != nil {
		t.Fatalf("Cosign: %v", err)
	}

	sig := cosignatureOf(t, cosigned, h.witness)
	if len(sig) != TimestampedSignatureSize {
		t.Fatalf("timestamped_signature = %d bytes, want %d", len(sig), TimestampedSignatureSize)
	}
	ts, err := Timestamp(sig)
	if err != nil {
		t.Fatal(err)
	}
	if ts.Unix() != h.clk.t {
		t.Errorf("timestamp = %d, want %d", ts.Unix(), h.clk.t)
	}

	// La nota conserva la firma del log además de la cosignature.
	logPub := ed25519.NewKeyFromSeed(seed(0)).Public().(ed25519.PublicKey)
	logVerifier, err := checkpoint.NewVerifier(logOrigin, logPub)
	if err != nil {
		t.Fatal(err)
	}
	n, err := note.Open(cosigned, note.VerifierList(logVerifier, h.witness.Verifier()))
	if err != nil {
		t.Fatalf("Open con ambas claves: %v", err)
	}
	if len(n.Sigs) != 2 {
		t.Errorf("firmas verificadas = %d, want 2", len(n.Sigs))
	}

	// Una cosignature no debe verificar contra un cuerpo distinto.
	if h.witness.Verifier().Verify([]byte("otro cuerpo\n"), sig) {
		t.Error("la cosignature verifica contra un cuerpo que no es el suyo")
	}
	// Ni con el timestamp alterado, porque va dentro de lo firmado.
	tampered := append([]byte(nil), sig...)
	tampered[0] ^= 0xff
	if h.witness.Verifier().Verify([]byte(n.Text), tampered) {
		t.Error("la cosignature verifica con el timestamp alterado")
	}
}

// TestCosignatureTimestampMonotonic comprueba que el testigo nunca emita un
// timestamp anterior a otro que ya emitió (ADR-002: es tiempo demostrable).
func TestCosignatureTimestampMonotonic(t *testing.T) {
	h := newHarness(t)
	first, err := h.witness.Cosign(h.signAt(5), nil)
	if err != nil {
		t.Fatal(err)
	}
	t1, _ := Timestamp(cosignatureOf(t, first, h.witness))

	h.clk.advance(30)
	second, err := h.witness.Cosign(h.signAt(9), h.proof(5, 9))
	if err != nil {
		t.Fatal(err)
	}
	t2, _ := Timestamp(cosignatureOf(t, second, h.witness))
	if !t2.After(t1) {
		t.Errorf("el timestamp no avanzó: %v -> %v", t1, t2)
	}

	// El reloj retrocede: el testigo debe negarse en vez de antedatar.
	h.clk.advance(-120)
	_, err = h.witness.Cosign(h.signAt(12), h.proof(9, 12))
	if !errors.Is(err, ErrClockRewind) {
		t.Errorf("con el reloj atrasado: err = %v, want %v", err, ErrClockRewind)
	}
	// Y el rechazo no debe haber movido el estado del testigo.
	if last, _ := h.witness.Last(logOrigin); last.Size != 9 {
		t.Errorf("el rechazo alteró el estado: tamaño %d, want 9", last.Size)
	}
}

// TestWitnessAcceptsHonestExtension es el camino feliz: el log crece y lo
// demuestra.
func TestWitnessAcceptsHonestExtension(t *testing.T) {
	h := newHarness(t)
	if _, err := h.witness.Cosign(h.signAt(5), nil); err != nil {
		t.Fatalf("primer checkpoint: %v", err)
	}
	if last, ok := h.witness.Last(logOrigin); !ok || last.Size != 5 {
		t.Fatalf("Last = %+v, %v", last, ok)
	}
	for _, step := range [][2]int{{5, 9}, {9, 12}, {12, 40}} {
		h.clk.advance(60)
		if _, err := h.witness.Cosign(h.signAt(step[1]), h.proof(step[0], step[1])); err != nil {
			t.Fatalf("extensión %d -> %d: %v", step[0], step[1], err)
		}
	}
	if last, _ := h.witness.Last(logOrigin); last.Size != 40 {
		t.Errorf("último tamaño = %d, want 40", last.Size)
	}
}

// TestWitnessRejectsRewrittenHistory es la demostración central del modelo de
// confianza de Núcleo: el log reescribe una entrada histórica y vuelve a firmar
// un árbol del mismo tamaño; el testigo, que ya cosignó la raíz anterior, se
// niega. Ni siquiera con una prueba de consistencia bien formada del árbol
// falso, porque esa prueba no parte de la raíz que el testigo recuerda.
func TestWitnessRejectsRewrittenHistory(t *testing.T) {
	h := newHarness(t)
	if _, err := h.witness.Cosign(h.signAt(5), nil); err != nil {
		t.Fatal(err)
	}
	h.clk.advance(60)

	// El log reescribe la entrada 1 y presenta un árbol de 9 hojas.
	rewritten := make([][]byte, len(h.leaves))
	copy(rewritten, h.leaves)
	rewritten[1] = []byte("factura alterada")

	evilPriv := ed25519.NewKeyFromSeed(seed(0))
	evilSigner, err := checkpoint.NewSigner(logOrigin, evilPriv)
	if err != nil {
		t.Fatal(err)
	}
	// Se firma con un Log nuevo para saltarse el cerrojo local del propio log:
	// el escenario es un operador que manipula su base de datos, no una API.
	evilLog, err := checkpoint.NewLog(logOrigin, evilSigner)
	if err != nil {
		t.Fatal(err)
	}
	evilMsg, err := evilLog.Sign(checkpoint.Checkpoint{
		Origin: logOrigin, Size: 9, RootHash: ledger.Root(rewritten[:9]),
	})
	if err != nil {
		t.Fatal(err)
	}
	evilProof, err := ledger.ConsistencyProof(rewritten[:9], 5)
	if err != nil {
		t.Fatal(err)
	}

	_, err = h.witness.Cosign(evilMsg, evilProof)
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("el testigo cosignó una historia reescrita: err = %v", err)
	}
	var conflict *ConflictError
	if !errors.As(err, &conflict) {
		t.Fatalf("el error no es *ConflictError: %T", err)
	}
	if conflict.LastSize != 5 {
		t.Errorf("ConflictError.LastSize = %d, want 5 (semántica 409)", conflict.LastSize)
	}
	if conflict.Origin != logOrigin {
		t.Errorf("ConflictError.Origin = %q, want %q", conflict.Origin, logOrigin)
	}
	// El estado del testigo sigue apuntando a la historia verdadera.
	if last, _ := h.witness.Last(logOrigin); last.Size != 5 {
		t.Errorf("el conflicto alteró el estado: %+v", last)
	}
	// Y la raíz honesta de tamaño 9 sí se acepta después del rechazo.
	if _, err := h.witness.Cosign(h.signAt(9), h.proof(5, 9)); err != nil {
		t.Errorf("tras el conflicto rechaza la extensión honesta: %v", err)
	}
}

// TestWitnessRejectsBadProofs recorre las formas de prueba que no demuestran
// nada.
func TestWitnessRejectsBadProofs(t *testing.T) {
	h := newHarness(t)
	if _, err := h.witness.Cosign(h.signAt(5), nil); err != nil {
		t.Fatal(err)
	}

	// El testigo clasifica los rechazos como los clasifica el protocolo, porque
	// el servidor HTTP tiene que traducirlos a códigos distintos: una prueba que
	// no demuestra la extensión es un conflicto (409), pero un tamaño anterior
	// mayor que el del checkpoint es una petición mal formada (400). Meterlo
	// todo en el mismo error obligaría al servidor a adivinar.
	cases := []struct {
		name  string
		size  int
		proof [][]byte
		want  error
	}{
		{"sin prueba", 9, nil, ErrConflict},
		{"prueba vacía", 9, [][]byte{}, ErrConflict},
		{"prueba de otro tramo", 12, h.proof(5, 9), ErrConflict},
		{"prueba manipulada", 9, tamper(h.proof(5, 9)), ErrConflict},
		{"retroceso de tamaño", 3, nil, ErrOldSize},
	}
	for _, c := range cases {
		h.clk.advance(10)
		// Se firma saltándose el cerrojo del log: lo que se prueba aquí es la
		// defensa del testigo, no la del emisor.
		msg := h.signBypassingLog(c.size, h.leaves)
		if _, err := h.witness.Cosign(msg, c.proof); !errors.Is(err, c.want) {
			t.Errorf("%s: err = %v, want %v", c.name, err, c.want)
		}
		if last, _ := h.witness.Last(logOrigin); last.Size != 5 {
			t.Fatalf("%s: el rechazo alteró el estado del testigo", c.name)
		}
	}
}

// tamper devuelve una copia de la prueba con un nodo alterado.
func tamper(proof [][]byte) [][]byte {
	out := make([][]byte, len(proof))
	for i := range proof {
		out[i] = append([]byte(nil), proof[i]...)
	}
	if len(out) > 0 {
		out[0][0] ^= 0xff
	}
	return out
}

// TestWitnessRejectsUnknownAndForeignLogs comprueba que el testigo no cosigne a
// ciegas: ni logs que no conoce, ni un log registrado firmando por otro origin.
func TestWitnessRejectsUnknownAndForeignLogs(t *testing.T) {
	h := newHarness(t)

	// Origin desconocido, firmado con su propia clave.
	strangerPriv := ed25519.NewKeyFromSeed(seed(50))
	strangerSigner, err := checkpoint.NewSigner("otro.example/log", strangerPriv)
	if err != nil {
		t.Fatal(err)
	}
	msg, err := checkpoint.Sign(checkpoint.Checkpoint{
		Origin: "otro.example/log", Size: 3, RootHash: ledger.Root(h.leaves[:3]),
	}, strangerSigner)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.witness.Cosign(msg, nil); err == nil {
		t.Error("el testigo cosignó un log que no conoce")
	}

	// Origin conocido, pero firmado por una clave que no es la suya.
	impostor, err := checkpoint.NewSigner(logOrigin, strangerPriv)
	if err != nil {
		t.Fatal(err)
	}
	msg, err = checkpoint.Sign(checkpoint.Checkpoint{
		Origin: logOrigin, Size: 3, RootHash: ledger.Root(h.leaves[:3]),
	}, impostor)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.witness.Cosign(msg, nil); err == nil {
		t.Error("el testigo cosignó un checkpoint firmado por una clave ajena")
	}
	if _, ok := h.witness.Last(logOrigin); ok {
		t.Error("un rechazo dejó estado registrado")
	}
}
