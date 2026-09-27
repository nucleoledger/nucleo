package logsync

import (
	"errors"
	"math"
	"testing"

	"github.com/nucleoledger/nucleo/internal/ledger"
)

// TestPruebaDeConsistenciaConTamanoAnteriorFueraDeRango: el tamaño anterior lo dice el
// testigo, así que llega de la red. Un uint64 mayor que MaxInt se volvía negativo al
// convertirlo (Sprint 13, CodeQL go/incorrect-integer-conversion); ahora se rechaza por
// lo que es.
func TestPruebaDeConsistenciaConTamanoAnteriorFueraDeRango(t *testing.T) {
	sc := newScene(t, 4)
	for _, old := range []uint64{math.MaxInt64 + 1, math.MaxUint64} {
		if _, err := sc.adapter.ConsistencyProof(old, 4); !errors.Is(err, ledger.ErrSizeRange) {
			t.Errorf("ConsistencyProof(%d, 4) = %v; want ErrSizeRange", old, err)
		}
	}
	// El caso normal sigue funcionando.
	if _, err := sc.adapter.ConsistencyProof(2, 4); err != nil {
		t.Errorf("ConsistencyProof(2, 4): %v", err)
	}
}
