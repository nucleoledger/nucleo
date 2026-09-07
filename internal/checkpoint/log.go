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
	// extra son las firmas adicionales del log, hoy la ML-DSA-44 de ADR-007.
	// Van en la MISMA nota que la Ed25519: quien no las entienda las ignora.
	extra []note.Signer
	last  *Checkpoint
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

// AddSigner añade una firma adicional a todos los checkpoints que emita el log.
//
// Es como entra la ML-DSA-44 de ADR-007: no sustituye a la Ed25519, se suma a
// ella en la misma nota. Un verificador que no conozca la clave nueva ignora su
// línea de firma y sigue verificando exactamente igual, que es la propiedad que
// hace posible añadir resistencia post-cuántica sin romper a nadie.
//
// El orden importa poco para la validez y mucho para los bytes: las firmas
// salen en el orden en que se pasan a note.Sign, así que añadir un firmante
// cambia los bytes de los checkpoints futuros —no los ya emitidos—.
func (l *Log) AddSigner(s note.Signer) error {
	if s == nil {
		return fmt.Errorf("checkpoint: firmante adicional nulo para %q", l.origin)
	}
	if s.Name() != l.origin {
		return fmt.Errorf("%w: el firmante adicional se llama %q y el log %q",
			ErrOrigin, s.Name(), l.origin)
	}
	l.extra = append(l.extra, s)
	return nil
}

// signers devuelve la firma principal seguida de las adicionales.
func (l *Log) signers() []note.Signer {
	return append([]note.Signer{l.signer}, l.extra...)
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
	msg, err := Sign(c, l.signers()...)
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
