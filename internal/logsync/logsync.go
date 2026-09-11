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
	"bytes"
	"context"
	"errors"
	"fmt"
	"time"

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
	// Root devuelve la raíz de Merkle de los primeros size bloques.
	Root(size uint64) ([]byte, error)
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
	// Attested es true solo si Cosigned es una cosignature verificada que cubre
	// el tamaño y la raíz locales del momento de la llamada.
	Attested bool
	// AttestedAt es el instante que el testigo afirma en la cosignature que se
	// acaba de verificar. Solo tiene valor cuando Attested es true.
	//
	// Es el tiempo demostrable de ADR-002 para el estado actual del log, y el
	// único dato con el que tiene sentido decidir si la atestación está vieja: el
	// reloj local no sirve para eso, porque es el reloj de quien podría querer
	// que la alarma no suene.
	AttestedAt time.Time
}

// SyncWithWitness devuelve éxito ÚNICAMENTE cuando posee una cosignature
// verificada que cubre el tamaño y la raíz locales ACTUALES.
//
// No hay atajos, y la ausencia de atajos es el arreglo. Antes, si el testigo
// parecía estar al día se daba por bueno y se devolvía la nota que él sirviera.
// Eso convertía una nota VIEJA Y GENUINA en un éxito: basta con reproducir la
// que el testigo cosignó cuando el árbol era más pequeño para que un ledger
// truncado cuadre consigo mismo. La nota es auténtica, su firma verifica, y aun
// así no dice nada sobre el estado de HOY.
//
// Lo único que distingue "el testigo avala mi estado actual" de "el testigo
// avaló algo alguna vez" es pedirle una cosignature ahora, sobre el árbol de
// ahora. Por eso cada sincronización pasa por add-checkpoint, incluso cuando
// parece que no hay nada nuevo que atestiguar.
func SyncWithWitness(ctx context.Context, log LocalLog, c *witness.Client) (*Result, error) {
	origin := log.Origin()
	localSize, err := log.TreeSize()
	if err != nil {
		return nil, err
	}
	localRoot, err := log.Root(localSize)
	if err != nil {
		return nil, err
	}

	// 1. Qué recuerda el testigo, según una nota que el cliente ya verificó
	// contra su clave. Si no verificara, esto no sería información: sería lo
	// que quisiera contarnos el camino.
	witnessSize, fresh, err := remoteSize(ctx, c, origin)
	if err != nil {
		return nil, err
	}

	// 2. Primera vía de detección: evidencia VERIFICADA de que el testigo va por
	// delante. Una nota firmada por él con más historia de la que hay en disco
	// no admite otra lectura.
	if witnessSize > localSize {
		return nil, &RollbackError{Origin: origin, LocalSize: localSize, WitnessSize: witnessSize}
	}

	res := &Result{Origin: origin, LocalSize: localSize, WitnessSize: witnessSize, Fresh: fresh}

	// 3. Pedir atestación del estado actual, SIEMPRE.
	msg, err := log.SignCheckpoint(localSize)
	if err != nil {
		return nil, err
	}
	var proof [][]byte
	if witnessSize > 0 && witnessSize < localSize {
		if proof, err = log.ConsistencyProof(witnessSize, localSize); err != nil {
			return nil, err
		}
	}
	cosigned, err := c.AddCheckpoint(ctx, witnessSize, proof, msg)
	if err != nil {
		// 4. Segunda vía de detección: el testigo rechaza extender desde donde
		// creíamos estar y dice recordar MÁS de lo que hay en disco. Es la vía
		// que caza el replay: la nota vieja nos hizo creer que el testigo estaba
		// en 6, y al intentar extender desde 6 el testigo real contesta 12.
		//
		// El tamaño del 409 no está autenticado, así que por sí solo no probaría
		// nada; lo que lo corrobora es que nuestro intento de extender contra el
		// estado real haya fallado. Un adversario de red puede provocar esta
		// alarma sin motivo, y eso es ruido revisable; lo que no puede es
		// fabricar la cosignature que haría falta para lo contrario.
		var conflict *witness.ConflictError
		if errors.As(err, &conflict) && conflict.LastSize > localSize {
			return nil, &RollbackError{Origin: origin, LocalSize: localSize, WitnessSize: conflict.LastSize}
		}
		return nil, err
	}

	// 5. Y comprobar que lo que volvió cubre de verdad el estado actual. El
	// cliente ya verificó la firma; esto verifica el CONTENIDO. Una cosignature
	// impecable sobre otro árbol seguiría sin atestiguar el nuestro.
	if err := coversLocalState(cosigned, origin, localSize, localRoot); err != nil {
		return nil, err
	}
	if err := log.RecordCosigned(cosigned); err != nil {
		return nil, err
	}
	// El instante sale del cliente, que lo lee DESPUÉS de verificar la firma del
	// testigo contra su clave. Si fallara aquí, la sincronización falla: una
	// atestación cuyo instante no se puede leer no es una atestación utilizable,
	// y dar éxito devolviendo un cero silencioso convertiría "no lo sé" en
	// "1 de enero de 1970", que es peor que el error.
	at, err := c.CosignatureTime(cosigned)
	if err != nil {
		return nil, err
	}
	res.Cosigned = cosigned
	res.Attested = true
	res.AttestedAt = at
	return res, nil
}

// ErrNotAttested indica que la sincronización terminó sin una cosignature
// verificada que cubra el estado local actual.
var ErrNotAttested = errors.New("logsync: la cosignature obtenida no cubre el estado local actual")

// coversLocalState exige que la nota cosignada hable de ESTE log, de ESTE tamaño
// y de ESTA raíz.
func coversLocalState(cosigned []byte, origin string, size uint64, root []byte) error {
	c, err := checkpoint.ParseNote(cosigned)
	if err != nil {
		return err
	}
	switch {
	case c.Origin != origin:
		return fmt.Errorf("%w: la cosignature es de %q", ErrNotAttested, c.Origin)
	case c.Size != size:
		return fmt.Errorf("%w: cubre %d bloques y en disco hay %d", ErrNotAttested, c.Size, size)
	case !bytes.Equal(c.RootHash, root):
		return fmt.Errorf("%w: cubre la raíz %x y la local es %x", ErrNotAttested, c.RootHash, root)
	}
	return nil
}

// remoteSize consulta el último checkpoint cosignado por el testigo.
//
// La nota viene ya VERIFICADA: witness.Client no devuelve una nota de
// monitorización sin una cosignature válida de la clave del testigo, y no se
// puede construir sin esa clave. Aquí se comprueba además que hable del origin
// que se pidió.
//
// Que esté verificada no la hace actual. El spec permite delegar el prefijo de
// monitorización a una CDN y admite retrasos de hasta una hora, así que una nota
// vieja y genuina es un resultado legítimo de esta llamada. Por eso su tamaño
// solo se usa para levantar una sospecha y para elegir el punto de partida de la
// extensión: quien decide si hay atestación del estado actual es add-checkpoint.
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
