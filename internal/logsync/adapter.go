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

// SignCheckpoint emite el checkpoint del tamaño dado, sin persistirlo.
//
// Lo que se guarda es la nota YA cosignada, en RecordCosigned: la tabla de
// checkpoints es append-only y solo admite una nota por tamaño, así que entre
// la firmada y la cosignada hay que elegir, y la que vale es la avalada.
//
// Queda un hueco conocido: si el proceso muere entre firmar y recibir la
// cosignature, el log habrá emitido un checkpoint del que no queda rastro
// local. Hoy no es peor que el estado previo —el cerrojo anti-retroceso de
// checkpoint.Log vive en memoria y también se pierde al reiniciar— pero se
// cerrará cuando ese cerrojo se haga duradero.
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
	return msg, nil
}

// RecordCosigned guarda la nota cosignada en el ledger.
func (a *StoreLog) RecordCosigned(note []byte) error { return a.Store.PutCheckpoint(note) }
