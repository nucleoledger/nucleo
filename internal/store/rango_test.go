package store

import (
	"errors"
	"math"
	"testing"

	"github.com/nucleoledger/nucleo/internal/checkpoint"
	"github.com/nucleoledger/nucleo/internal/ledger"
)

// TestCheckpointFueraDeRangoNoSeGuardaNiSeBusca: la tabla de checkpoints se indexa por
// un entero de SQLite, con signo. Un tamaño mayor que MaxInt64 —que el formato admite y
// que puede llegar en una nota de fuera— se guardaba NEGATIVO (Sprint 13, CodeQL).
func TestCheckpointFueraDeRangoNoSeGuardaNiSeBusca(t *testing.T) {
	s := openTemp(t)
	_, logPriv := testKeys(t, 1)
	signer, err := checkpoint.NewSigner(testOrigin, logPriv)
	if err != nil {
		t.Fatal(err)
	}
	enorme := uint64(math.MaxInt64) + 1
	nota, err := checkpoint.Sign(checkpoint.Checkpoint{
		Origin: testOrigin, Size: enorme, RootHash: make([]byte, 32),
	}, signer)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.PutCheckpoint(nota); !errors.Is(err, ledger.ErrSizeRange) {
		t.Errorf("PutCheckpoint(tamaño %d) = %v; want ErrSizeRange", enorme, err)
	}
	if _, err := s.LastCheckpoint(); !errors.Is(err, ErrNotFound) {
		t.Errorf("se guardó algo: LastCheckpoint = %v", err)
	}
	if _, err := s.Checkpoint(enorme); !errors.Is(err, ledger.ErrSizeRange) {
		t.Errorf("Checkpoint(%d) = %v; want ErrSizeRange", enorme, err)
	}
	// El mayor valor que cabe se busca con normalidad: no está, y lo dice.
	if _, err := s.Checkpoint(math.MaxInt64); !errors.Is(err, ErrNotFound) {
		t.Errorf("Checkpoint(MaxInt64) = %v; want ErrNotFound", err)
	}
}
