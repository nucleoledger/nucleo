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

// NewStoreLog construye el adaptador y ata el cerrojo anti-retroceso del log a
// la base, rehidratándolo con el último checkpoint que firmó.
//
// Atarlo aquí y no dejarlo a criterio de quien llame es deliberado: un log sin
// cerrojo duradero olvida lo que firmó en cuanto muere el proceso, y ese olvido
// no da ningún error, simplemente vuelve a firmar. Los fallos silenciosos se
// evitan quitando la opción de equivocarse.
func NewStoreLog(s *store.Store, l *checkpoint.Log) (*StoreLog, error) {
	if err := l.Bind(s); err != nil {
		return nil, err
	}
	return &StoreLog{Store: s, Log: l}, nil
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

// SignCheckpoint emite el checkpoint del tamaño dado.
//
// En la tabla de checkpoints se guarda la nota YA cosignada, en RecordCosigned:
// esa tabla es append-only y solo admite una nota por tamaño, así que entre la
// firmada y la cosignada hay que elegir, y la que vale es la avalada.
//
// El compromiso de haber firmado sí queda en disco de inmediato, en log_state,
// porque checkpoint.Log está atado a la base: si el proceso muere entre firmar
// y recibir la cosignature, el log que arranque después seguirá sabiendo que ya
// se comprometió con este tamaño y se negará a desdecirse.
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
