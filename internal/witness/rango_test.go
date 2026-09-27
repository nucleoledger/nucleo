package witness

import (
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"math"
	"strings"
	"testing"

	"github.com/nucleoledger/nucleo/internal/checkpoint"
)

// signSize firma, con la clave del log, un checkpoint de un tamaño arbitrario. La raíz
// da igual: lo que se prueba es qué hace el testigo con el TAMAÑO, que llega de fuera.
func (h *harness) signSize(size uint64) []byte {
	h.t.Helper()
	signer, err := checkpoint.NewSigner(logOrigin, ed25519.NewKeyFromSeed(seed(0)))
	if err != nil {
		h.t.Fatal(err)
	}
	root := sha256.Sum256([]byte("raíz cualquiera"))
	msg, err := checkpoint.Sign(checkpoint.Checkpoint{Origin: logOrigin, Size: size, RootHash: root[:]}, signer)
	if err != nil {
		h.t.Fatal(err)
	}
	return msg
}

// TestTamanoFueraDeRangoSeRechazaComoTal: un tamaño de árbol que no cabe en un int64
// llega de la red —el checkpoint lo manda el cliente— y el testigo lo convierte a int
// para verificar la consistencia (alerta de CodeQL go/incorrect-integer-conversion).
//
// Antes se rechazaba igual, pero por accidente: la conversión lo volvía NEGATIVO y la
// guarda de VerifyConsistency lo cazaba como "la prueba no verifica". Que un control de
// integridad dependa de un desbordamiento es justo lo que no puede pasar, así que se
// rechaza por lo que es, antes de convertir.
func TestTamanoFueraDeRangoSeRechazaComoTal(t *testing.T) {
	for _, c := range []struct {
		nombre string
		size   uint64
	}{
		{"MaxInt64 + 1", math.MaxInt64 + 1},
		{"MaxUint64", math.MaxUint64},
	} {
		t.Run(c.nombre, func(t *testing.T) {
			h := newHarness(t)
			if _, err := h.witness.Cosign(h.signAt(4), nil); err != nil {
				t.Fatal(err)
			}
			_, err := h.witness.Cosign(h.signSize(c.size), [][]byte{make([]byte, 32)})
			if err == nil {
				t.Fatal("el testigo cosignó un tamaño que no cabe en un int64")
			}
			if !errors.Is(err, ErrUnprocessable) {
				t.Errorf("err = %v, want ErrUnprocessable", err)
			}
			if !strings.Contains(err.Error(), "fuera de rango") {
				t.Errorf("se rechazó, pero no por el rango: %v", err)
			}
		})
	}

	// El valor límite que SÍ cabe no se rechaza por el rango: llega a la prueba de
	// consistencia, que no verifica porque la raíz es inventada.
	h := newHarness(t)
	if _, err := h.witness.Cosign(h.signAt(4), nil); err != nil {
		t.Fatal(err)
	}
	_, err := h.witness.Cosign(h.signSize(math.MaxInt64), [][]byte{make([]byte, 32)})
	if err == nil || strings.Contains(err.Error(), "fuera de rango") {
		t.Errorf("MaxInt64 cabe y tenía que llegar a la prueba de consistencia: %v", err)
	}
}

// TestPrimerCheckpointFueraDeRangoNoSeGuarda: el camino de old == 0 no pasa por la
// prueba de consistencia, así que sin la comprobación explícita un primer checkpoint
// gigante quedaba en la memoria del testigo y ningún tamaño real volvía a ser mayor.
func TestPrimerCheckpointFueraDeRangoNoSeGuarda(t *testing.T) {
	h := newHarness(t)
	if _, err := h.witness.Cosign(h.signSize(math.MaxInt64+1), nil); err == nil ||
		!strings.Contains(err.Error(), "fuera de rango") {
		t.Fatalf("err = %v, want un rechazo por rango", err)
	}
	if _, ok := h.witness.Last(logOrigin); ok {
		t.Error("el testigo guardó un checkpoint fuera de rango")
	}
	// Y el log sigue pudiendo empezar con un tamaño real.
	if _, err := h.witness.Cosign(h.signAt(4), nil); err != nil {
		t.Errorf("tras el rechazo, el log no pudo empezar: %v", err)
	}
}
