// Package logsync sincroniza el ledger local con un testigo: le pide una
// cosignature del checkpoint actual y, de paso, le pregunta qué recuerda.
//
// La segunda mitad es la importante. La auditoría externa registrada en ADR-009
// dejó claro que un fichero no puede testificar sobre su propia integridad
// histórica: quien lo controla puede borrar los disparadores, vaciar la tabla de
// checkpoints y truncar los bloques a un prefijo que encadena y verifica
// perfectamente. Ninguna comprobación interna lo detecta, porque cualquier
// prueba que viviera dentro también sería suya.
//
// Lo que sí lo detecta es una memoria que no está en ese disco. El testigo
// recuerda un árbol de 5 y en la base hay 3: ahí se acaba el disimulo. Eso es lo
// que hace este paquete.
package logsync

import (
	"context"
	"errors"
	"fmt"

	"github.com/nucleoledger/nucleo/internal/checkpoint"
	"github.com/nucleoledger/nucleo/internal/witness"
)

// ErrLocalRollback indica que el testigo recuerda un árbol MAYOR que el local:
// el fichero de este log fue truncado.
var ErrLocalRollback = errors.New("logsync: el testigo recuerda más historia de la que hay en disco")

// RollbackError lleva los dos tamaños, porque la cifra es media respuesta: dice
// cuántos bloques faltan y hasta dónde hay que restaurar.
type RollbackError struct {
	Origin      string
	LocalSize   uint64
	WitnessSize uint64
}

func (e *RollbackError) Error() string {
	return fmt.Sprintf("%v: %q tiene %d bloques en disco y el testigo cosignó %d",
		ErrLocalRollback, e.Origin, e.LocalSize, e.WitnessSize)
}

// Is permite compararlo con ErrLocalRollback mediante errors.Is.
func (e *RollbackError) Is(target error) bool { return target == ErrLocalRollback }

// LocalLog es lo que la sincronización necesita del lado del log. Se declara
// aquí, y no se importa internal/store, para que la lógica se pueda probar sin
// una base de datos y para que el paquete no dependa de cómo se persiste nada.
type LocalLog interface {
	// Origin identifica al log ante el testigo.
	Origin() string
	// TreeSize devuelve el número de hojas del ledger local.
	TreeSize() (uint64, error)
	// ConsistencyProof devuelve PROOF(old, D[size]) sobre el árbol local.
	ConsistencyProof(old, size uint64) ([][]byte, error)
	// SignCheckpoint emite un checkpoint firmado del tamaño dado.
	SignCheckpoint(size uint64) ([]byte, error)
	// RecordCosigned guarda la nota YA cosignada.
	//
	// Se persiste la cosignada y no la recién firmada porque la tabla de
	// checkpoints es append-only y solo admite una nota por tamaño: entre las
	// dos, la que vale es la que lleva el aval del testigo. Una sin cosignature
	// solo prueba que el log dijo algo.
	RecordCosigned(note []byte) error
}

// Result cuenta qué pasó en la sincronización.
type Result struct {
	// Origin del log sincronizado.
	Origin string
	// LocalSize es el tamaño del árbol local.
	LocalSize uint64
	// WitnessSize es el tamaño que el testigo recordaba ANTES de esta llamada.
	WitnessSize uint64
	// Cosigned es la nota del checkpoint con la cosignature ya incorporada.
	Cosigned []byte
	// Fresh indica que el testigo no había cosignado nunca para este origin.
	Fresh bool
}

// SyncWithWitness pregunta primero y firma después.
//
// El orden importa: si pidiéramos la cosignature sin consultar antes, un ledger
// truncado recibiría un 409 con el tamaño verdadero —el protocolo lo obliga— y
// eso ya sería una señal. Pero consultar primero convierte una señal indirecta,
// que hay que saber leer, en un error tipado que nombra el problema: faltan
// bloques en disco. Un operador no debería tener que deducir un rollback a
// partir de un código HTTP.
func SyncWithWitness(ctx context.Context, log LocalLog, c *witness.Client) (*Result, error) {
	origin := log.Origin()
	localSize, err := log.TreeSize()
	if err != nil {
		return nil, err
	}

	// 1. Qué recuerda el testigo.
	witnessSize, fresh, err := remoteSize(ctx, c, origin)
	if err != nil {
		return nil, err
	}

	// 2. La comparación que delata el truncamiento.
	if witnessSize > localSize {
		return nil, &RollbackError{Origin: origin, LocalSize: localSize, WitnessSize: witnessSize}
	}

	res := &Result{Origin: origin, LocalSize: localSize, WitnessSize: witnessSize, Fresh: fresh}

	// 3. Nada nuevo que atestiguar: el testigo ya está al día.
	if witnessSize == localSize && !fresh {
		note, err := c.Checkpoint(ctx, origin)
		if err != nil {
			return nil, err
		}
		res.Cosigned = note
		return res, nil
	}

	// 4. Pedir la cosignature del estado actual.
	msg, err := log.SignCheckpoint(localSize)
	if err != nil {
		return nil, err
	}
	var proof [][]byte
	if witnessSize > 0 {
		if proof, err = log.ConsistencyProof(witnessSize, localSize); err != nil {
			return nil, err
		}
	}
	lines, err := c.AddCheckpoint(ctx, witnessSize, proof, msg)
	if err != nil {
		return nil, err
	}
	cosigned := append(append([]byte{}, msg...), lines...)
	if err := log.RecordCosigned(cosigned); err != nil {
		return nil, err
	}
	res.Cosigned = cosigned
	return res, nil
}

// remoteSize consulta el último checkpoint cosignado por el testigo.
//
// La nota que devuelve no se verifica aquí a propósito: lo único que se lee de
// ella es el TAMAÑO, y se usa para levantar una sospecha, no para creerse nada.
// Un testigo que mintiera inflando la cifra provocaría una alarma falsa, que es
// ruidoso y revisable; jamás puede conseguir que un rollback real pase
// inadvertido, porque para eso tendría que declarar MENOS de lo que cosignó y
// el log ya tiene su propia copia de esa cosignature. Quien necesite confiar en
// el contenido usa checkpoint.Verify con la clave del testigo.
func remoteSize(ctx context.Context, c *witness.Client, origin string) (size uint64, fresh bool, err error) {
	note, err := c.Checkpoint(ctx, origin)
	if errors.Is(err, witness.ErrNoWitnessCheckpoint) {
		return 0, true, nil
	}
	if err != nil {
		return 0, false, err
	}
	parsed, err := checkpoint.ParseNote(note)
	if err != nil {
		return 0, false, fmt.Errorf("logsync: el testigo devolvió un checkpoint ilegible: %w", err)
	}
	if parsed.Origin != origin {
		return 0, false, fmt.Errorf("logsync: se pidió %q y el testigo devolvió %q", origin, parsed.Origin)
	}
	return parsed.Size, false, nil
}
