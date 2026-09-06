package logsync

import (
	"fmt"

	"github.com/nucleoledger/nucleo/internal/checkpoint"
	"github.com/nucleoledger/nucleo/internal/ledger"
	"github.com/nucleoledger/nucleo/internal/store"
)

// StoreLog conecta el ledger persistente y el emisor de checkpoints con lo que
// la sincronización necesita.
type StoreLog struct {
	Store *store.Store
	Log   *checkpoint.Log
}

// NewStoreLog construye el adaptador.
func NewStoreLog(s *store.Store, l *checkpoint.Log) *StoreLog {
	return &StoreLog{Store: s, Log: l}
}

// Origin identifica al log ante el testigo.
func (a *StoreLog) Origin() string { return a.Log.Origin() }

// TreeSize devuelve el número de bloques persistidos.
func (a *StoreLog) TreeSize() (uint64, error) {
	n, err := a.Store.Count()
	if err != nil {
		return 0, err
	}
	return uint64(n), nil
}

// ConsistencyProof arma PROOF(old, D[size]) desde las hojas del ledger.
func (a *StoreLog) ConsistencyProof(old, size uint64) ([][]byte, error) {
	leaves, err := a.Store.LeafHashes()
	if err != nil {
		return nil, err
	}
	if size > uint64(len(leaves)) {
		return nil, fmt.Errorf("logsync: se pidió una prueba hasta %d y hay %d hojas", size, len(leaves))
	}
	return ledger.ConsistencyProof(leaves[:size], int(old))
}

// SignCheckpoint emite el checkpoint del tamaño dado y lo persiste.
//
// Se guarda ANTES de enviarlo al testigo, no después: si el proceso muere entre
// firmar y recibir la cosignature, lo que no puede pasar es que el log haya
// firmado un checkpoint del que no queda rastro local. checkpoint.Log ya impide
// firmar dos checkpoints incompatibles, y persistirlo aquí extiende esa promesa
// más allá del proceso.
func (a *StoreLog) SignCheckpoint(size uint64) ([]byte, error) {
	leaves, err := a.Store.LeafHashes()
	if err != nil {
		return nil, err
	}
	if size > uint64(len(leaves)) {
		return nil, fmt.Errorf("logsync: se pidió firmar %d bloques y hay %d", size, len(leaves))
	}
	msg, err := a.Log.Sign(checkpoint.Checkpoint{
		Origin: a.Log.Origin(), Size: size, RootHash: ledger.Root(leaves[:size]),
	})
	if err != nil {
		return nil, err
	}
	if err := a.Store.PutCheckpoint(msg); err != nil {
		return nil, err
	}
	return msg, nil
}
