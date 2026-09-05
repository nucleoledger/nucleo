package checkpoint

import (
	"bytes"
	"fmt"

	"golang.org/x/mod/sumdb/note"
)

// Log firma los checkpoints de un origin concreto y recuerda el último que
// firmó, para hacer cumplir la regla de PROTOCOL.md §3: «A log MUST NOT sign a
// checkpoint inconsistent with any previously signed one».
//
// Un log que se desdice —que firma un árbol más pequeño, o una raíz distinta
// para el mismo tamaño— es exactamente el ataque que el registro debe hacer
// imposible de ocultar. Aquí se impide en origen; que además sea DETECTABLE por
// terceros es trabajo del testigo (internal/witness), que sí verifica la prueba
// de consistencia completa. Esta guarda es un cerrojo local, no la frontera de
// seguridad.
type Log struct {
	origin string
	signer note.Signer
	last   *Checkpoint
}

// NewLog crea un log firmante para el origin dado.
func NewLog(origin string, signer note.Signer) (*Log, error) {
	if err := validOrigin(origin); err != nil {
		return nil, err
	}
	if signer == nil {
		return nil, fmt.Errorf("checkpoint: firmante nulo para %q", origin)
	}
	return &Log{origin: origin, signer: signer}, nil
}

// Origin devuelve el identificador del log.
func (l *Log) Origin() string { return l.origin }

// Last devuelve el último checkpoint firmado, si hubo alguno.
func (l *Log) Last() (Checkpoint, bool) {
	if l.last == nil {
		return Checkpoint{}, false
	}
	return *l.last, true
}

// Sign firma el checkpoint tras comprobar que no contradice al anterior, y solo
// registra el nuevo estado si la firma salió bien.
func (l *Log) Sign(c Checkpoint) ([]byte, error) {
	if c.Origin != l.origin {
		return nil, fmt.Errorf("%w: %q no es el origin del log (%q)", ErrOrigin, c.Origin, l.origin)
	}
	if err := l.checkMonotonic(c); err != nil {
		return nil, err
	}
	msg, err := Sign(c, l.signer)
	if err != nil {
		return nil, err
	}
	stored := c
	stored.RootHash = bytes.Clone(c.RootHash)
	l.last = &stored
	return msg, nil
}

// checkMonotonic aplica lo que se puede comprobar sin el árbol: el tamaño nunca
// decrece y, a igual tamaño, la raíz es la misma. La prueba de que el árbol
// viejo es prefijo del nuevo requiere las hojas y la hace el testigo.
func (l *Log) checkMonotonic(c Checkpoint) error {
	if l.last == nil {
		return nil
	}
	if c.Size < l.last.Size {
		return fmt.Errorf("%w: tamaño %d < %d", ErrRollback, c.Size, l.last.Size)
	}
	if c.Size == l.last.Size && !bytes.Equal(c.RootHash, l.last.RootHash) {
		return fmt.Errorf("%w: dos raíces distintas para el tamaño %d", ErrRollback, c.Size)
	}
	return nil
}
