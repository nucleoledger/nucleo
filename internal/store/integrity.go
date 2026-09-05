package store

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/nucleoledger/nucleo/internal/checkpoint"
	"github.com/nucleoledger/nucleo/internal/ledger"
)

// ErrIntegrity indica que la base no es coherente consigo misma.
var ErrIntegrity = errors.New("store: verificación de integridad fallida")

// IntegrityError nombra el bloque implicado y la fase en que se detectó el
// problema. Nombrar el bloque no es un lujo: cuando alguien manipula el fichero,
// lo primero que hay que saber es DÓNDE se rompió la historia.
type IntegrityError struct {
	// Stage describe qué comprobación falló.
	Stage string
	// Index es el bloque implicado, o -1 si el fallo no es de un bloque concreto.
	Index int64
	// Err es la causa.
	Err error
}

func (e *IntegrityError) Error() string {
	if e.Index < 0 {
		return fmt.Sprintf("%v: %s: %v", ErrIntegrity, e.Stage, e.Err)
	}
	return fmt.Sprintf("%v: %s: bloque %d: %v", ErrIntegrity, e.Stage, e.Index, e.Err)
}

// Is permite compararlo con ErrIntegrity mediante errors.Is.
func (e *IntegrityError) Is(target error) bool { return target == ErrIntegrity }

// Unwrap expone la causa concreta.
func (e *IntegrityError) Unwrap() error { return e.Err }

// VerifyIntegrity recorre la base y comprueba que sigue contando la misma
// historia: cada bloque válido y bien encadenado, y la raíz de Merkle
// reconstruida coherente con el último checkpoint persistido.
//
// Es lo que convierte el borrado de un disparador en un fallo visible. Los
// disparadores impiden el UPDATE mientras están; esta función detecta que
// ocurrió aunque no estuvieran.
//
// No exige una clave de firmante concreta: el almacén no la conoce. Comprueba
// que cada bloque esté firmado por la clave que él mismo declara y que la cadena
// sea consistente; contrastar esa clave contra la identidad esperada del tenant
// es trabajo de quien abre el ledger, con ledger.VerifyChain.
func (s *Store) VerifyIntegrity() error {
	blocks, err := s.AllBlocks()
	if err != nil {
		return &IntegrityError{Stage: "lectura", Index: -1, Err: err}
	}

	for i, b := range blocks {
		if uint64(i) != b.Header.Index {
			return &IntegrityError{
				Stage: "secuencia", Index: int64(i),
				Err: fmt.Errorf("%w: la fila %d contiene el bloque %d", ledger.ErrIndexSequence, i, b.Header.Index),
			}
		}
		if err := b.Verify(); err != nil {
			return &IntegrityError{Stage: "bloque", Index: int64(b.Header.Index), Err: err}
		}
		if i > 0 {
			if err := ledger.VerifyLink(blocks[i-1], b); err != nil {
				return &IntegrityError{Stage: "encadenamiento", Index: int64(b.Header.Index), Err: err}
			}
		}
	}

	return s.verifyAgainstCheckpoint(blocks)
}

// verifyAgainstCheckpoint contrasta la raíz reconstruida con el último
// checkpoint guardado. Es la comprobación que ata el contenido del fichero a
// algo que ya se firmó y, si hubo testigos, que ya vio un tercero.
func (s *Store) verifyAgainstCheckpoint(blocks []*ledger.Block) error {
	note, err := s.LastCheckpoint()
	if errors.Is(err, ErrNotFound) {
		return nil // un ledger sin checkpoints todavía no prometió nada
	}
	if err != nil {
		return &IntegrityError{Stage: "checkpoint", Index: -1, Err: err}
	}

	c, err := checkpoint.ParseNote(note)
	if err != nil {
		return &IntegrityError{Stage: "checkpoint", Index: -1, Err: err}
	}
	if c.Size > uint64(len(blocks)) {
		return &IntegrityError{
			Stage: "checkpoint", Index: -1,
			Err: fmt.Errorf("el checkpoint promete %d bloques y solo hay %d: falta historia",
				c.Size, len(blocks)),
		}
	}

	leaves := make([][]byte, 0, c.Size)
	for _, b := range blocks[:c.Size] {
		raw, err := b.HashBytes()
		if err != nil {
			return &IntegrityError{Stage: "checkpoint", Index: int64(b.Header.Index), Err: err}
		}
		leaves = append(leaves, raw)
	}
	if root := ledger.Root(leaves); !bytes.Equal(root, c.RootHash) {
		return &IntegrityError{
			Stage: "checkpoint", Index: -1,
			Err: fmt.Errorf("la raíz reconstruida de %d bloques es %s y el checkpoint firmó %s",
				c.Size, hex.EncodeToString(root), hex.EncodeToString(c.RootHash)),
		}
	}
	return nil
}

// Root devuelve la raíz de Merkle del ledger completo, reconstruida en memoria
// desde los hashes de bloque.
//
// No se cachean subárboles: la reconstrucción es O(n) y a la velocidad de
// hashing medida basta de sobra para el perfil objetivo. La caché queda
// diferida según ADR-009, con condición escrita: se implementa cuando un
// benchmark real muestre apertura por encima de 5 s en hardware objetivo.
func (s *Store) Root() ([]byte, error) {
	leaves, err := s.LeafHashes()
	if err != nil {
		return nil, err
	}
	return ledger.Root(leaves), nil
}
