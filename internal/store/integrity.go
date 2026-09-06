package store

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
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

// verifyMode elige cuánta criptografía se recomputa al recorrer la base.
type verifyMode int

const (
	// modeAttested verifica las firmas Ed25519 solo de los bloques posteriores
	// al último checkpoint cosignado. Es el modo de la apertura.
	modeAttested verifyMode = iota
	// modeFull verifica la firma de todos los bloques. Es el modo de auditoría.
	modeFull
)

// OpenResult describe qué respalda la historia que se acaba de verificar.
//
// Existe porque "la base abrió bien" son dos afirmaciones muy distintas según
// haya o no un testigo detrás, y confundirlas es peligroso. Una cadena
// localmente válida puede ser un PREFIJO de la historia real: quien controle el
// fichero puede borrar los disparadores, borrar la tabla de checkpoints y
// truncar los bloques a un prefijo que encadena y verifica perfectamente. Nada
// dentro del fichero puede desmentirlo, porque el fichero entero es suyo. Lo
// único que lo desmiente es la memoria de un testigo que cosignó una raíz más
// grande.
//
// Por eso Attested viaja en el resultado de Open en vez de quedarse implícito:
// una apertura NO atestiguada es legítima —un ledger recién creado lo es— pero
// quien la reciba tiene que poder decirlo en voz alta.
type OpenResult struct {
	// TreeSize es el número de bloques persistidos.
	TreeSize uint64
	// Attested indica que existe un checkpoint cosignado persistido Y que la
	// raíz reconstruida cuadra con él.
	Attested bool
	// AttestedSize es el tamaño de árbol que ese checkpoint atestigua, o 0.
	AttestedSize uint64
}

// String describe el estado en una línea, para logs y CLI.
func (r OpenResult) String() string {
	if r.Attested {
		return fmt.Sprintf("historia atestiguada hasta %d de %d bloques", r.AttestedSize, r.TreeSize)
	}
	return fmt.Sprintf("SIN ATESTIGUAR: %d bloques, cadena localmente válida, historia completa no garantizada", r.TreeSize)
}

// VerifyIntegrity recorre la base y comprueba que sigue contando la misma
// historia. Es lo que ejecuta Open.
//
// Reconstruye el árbol de Merkle COMPLETO y exige que la raíz iguale la del
// último checkpoint cosignado persistido; las firmas Ed25519 se recomputan solo
// para los bloques posteriores a ese checkpoint. Si no hay ningún checkpoint
// cosignado, se verifican todas: sin testigo no hay atajo (enmienda de ADR-009).
//
// El motivo es que los bytes cubiertos por una raíz cosignada ya están
// atestiguados por un tercero que conserva su copia, y sus firmas se
// verificaron al sellar. Lo que la raíz NO cubre es la columna signature, que
// vive fuera del header: corromper la firma de un bloque histórico no lo detecta
// este camino, lo detecta VerifyFull.
//
// No exige una clave de firmante concreta: el almacén no la conoce. Comprueba
// que cada bloque esté firmado por la clave que él mismo declara y que la cadena
// sea consistente; contrastar esa clave contra la identidad esperada del tenant
// es trabajo de quien abre el ledger, con ledger.VerifyChain.
func (s *Store) VerifyIntegrity() (OpenResult, error) { return s.verify(modeAttested) }

// VerifyFull recomputa TODAS las firmas Ed25519 de la base, sin apoyarse en
// ningún checkpoint. Es la operación de auditoría, y la que hay que llamar ante
// una sospecha: cuesta lo que la apertura costaba antes de la enmienda de
// ADR-009 y a cambio no concede nada.
func (s *Store) VerifyFull() (OpenResult, error) { return s.verify(modeFull) }

func (s *Store) verify(mode verifyMode) (OpenResult, error) {
	if s.db == nil {
		return OpenResult{}, &IntegrityError{Stage: "lectura", Index: -1, Err: ErrClosed}
	}
	n, err := s.Count()
	if err != nil {
		return OpenResult{}, &IntegrityError{Stage: "lectura", Index: -1, Err: err}
	}

	// attested es el checkpoint cosignado que respalda la historia. En modo
	// completo también se busca, aunque no se use para saltarse firmas: el
	// estado atestiguado es un hecho de la base, no del modo de verificación.
	// signedFrom es el primer bloque cuya firma se recomputa.
	attested, err := s.attestedCheckpoint(n)
	if err != nil {
		return OpenResult{}, err
	}
	var signedFrom uint64
	if mode == modeAttested && attested != nil {
		signedFrom = attested.Size
	}

	leaves, err := s.walk(signedFrom)
	if err != nil {
		return OpenResult{}, err
	}
	if err := s.verifyAgainstCheckpoints(leaves, attested); err != nil {
		return OpenResult{}, err
	}

	res := OpenResult{TreeSize: uint64(len(leaves))}
	if attested != nil {
		// Llegar aquí significa que verifyAgainstCheckpoints contrastó la raíz
		// de este checkpoint contra el árbol reconstruido y cuadró.
		res.Attested = true
		res.AttestedSize = attested.Size
	}
	return res, nil
}

// walk recorre la tabla de bloques UNA vez y devuelve las hojas del árbol.
//
// Por debajo de signedFrom el trabajo por bloque es un SHA-256 sobre los bytes
// que hay guardados; a partir de ahí se reconstruye el bloque y se verifican su
// firma Ed25519 y su encadenamiento.
func (s *Store) walk(signedFrom uint64) ([][]byte, error) {
	rows, err := s.db.Query(`SELECT idx, hash, header_json, signature FROM blocks ORDER BY idx`)
	if err != nil {
		return nil, &IntegrityError{Stage: "lectura", Index: -1, Err: err}
	}
	defer rows.Close()

	var (
		leaves [][]byte
		prev   *ledger.Block
		i      int64
	)
	for rows.Next() {
		var (
			idx        int64
			hash       string
			headerJSON string
			signature  string
		)
		if err := rows.Scan(&idx, &hash, &headerJSON, &signature); err != nil {
			return nil, &IntegrityError{Stage: "lectura", Index: i, Err: err}
		}
		if idx != i {
			return nil, &IntegrityError{
				Stage: "secuencia", Index: i,
				Err: fmt.Errorf("%w: la fila %d contiene el bloque %d", ledger.ErrIndexSequence, i, idx),
			}
		}
		// La atadura header↔hash se comprueba SIEMPRE, y sobre los bytes
		// almacenados en vez de recanonicalizarlos. Es más barato y es más
		// estricto: el header_json guardado ES la forma canónica JCS —lo que se
		// firmó—, así que si dejara de serlo esto lo delata en lugar de
		// normalizarlo por lo bajo. Sin esta comprobación el árbol se
		// reconstruiría desde una columna hash que nadie ató a su contenido, y
		// el header_json sería sustituible a voluntad.
		if sha256Hex(headerJSON) != hash {
			return nil, &IntegrityError{Stage: "bloque", Index: idx, Err: ledger.ErrHashMismatch}
		}
		raw, err := decodeHash(hash)
		if err != nil {
			return nil, &IntegrityError{Stage: "bloque", Index: idx, Err: err}
		}
		leaves = append(leaves, raw)

		// El último bloque cubierto por el checkpoint también se reconstruye,
		// para poder comprobar el encadenamiento con el primero que no lo está.
		if uint64(idx)+1 < signedFrom {
			i++
			continue
		}
		b, err := decodeBlock(idx, hash, headerJSON, signature)
		if err != nil {
			return nil, &IntegrityError{Stage: "bloque", Index: idx, Err: err}
		}
		if uint64(idx) >= signedFrom {
			if err := b.Verify(); err != nil {
				return nil, &IntegrityError{Stage: "bloque", Index: idx, Err: err}
			}
			if prev != nil {
				if err := ledger.VerifyLink(prev, b); err != nil {
					return nil, &IntegrityError{Stage: "encadenamiento", Index: idx, Err: err}
				}
			}
		}
		prev = b
		i++
	}
	if err := rows.Err(); err != nil {
		return nil, &IntegrityError{Stage: "lectura", Index: -1, Err: err}
	}
	return leaves, nil
}

// sha256Hex devuelve el SHA-256 en hexadecimal de la cadena dada.
func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// decodeBlock reconstruye el bloque desde sus columnas.
func decodeBlock(idx int64, hash, headerJSON, signature string) (*ledger.Block, error) {
	var h ledger.Header
	if err := json.Unmarshal([]byte(headerJSON), &h); err != nil {
		return nil, fmt.Errorf("store: header del bloque %d ilegible: %w", idx, err)
	}
	return &ledger.Block{Header: h, Hash: hash, Signature: signature}, nil
}

// attestedCheckpoint devuelve el último checkpoint cosignado persistido, o nil
// si no hay ninguno. Un checkpoint que promete más bloques de los que hay es un
// fallo de integridad aquí mismo: no puede respaldar ningún atajo.
func (s *Store) attestedCheckpoint(n int) (*checkpoint.Checkpoint, error) {
	note, err := s.LastCosignedCheckpoint()
	if errors.Is(err, ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, &IntegrityError{Stage: "checkpoint", Index: -1, Err: err}
	}
	c, err := checkpoint.ParseNote(note)
	if err != nil {
		return nil, &IntegrityError{Stage: "checkpoint", Index: -1, Err: err}
	}
	if c.Size > uint64(n) {
		return nil, missingHistory(c.Size, n)
	}
	return &c, nil
}

// verifyAgainstCheckpoints contrasta la raíz reconstruida con la que prometió el
// último checkpoint y, si es otro, con la del último cosignado.
//
// Se comprueban los dos porque cumplen papeles distintos: el último es la
// promesa más reciente del log, y el cosignado es el que respalda el atajo de
// firmas. Saltarse el segundo dejaría el atajo sin fundamento.
func (s *Store) verifyAgainstCheckpoints(leaves [][]byte, attested *checkpoint.Checkpoint) error {
	note, err := s.LastCheckpoint()
	if errors.Is(err, ErrNotFound) {
		return nil // un ledger sin checkpoints todavía no prometió nada
	}
	if err != nil {
		return &IntegrityError{Stage: "checkpoint", Index: -1, Err: err}
	}
	last, err := checkpoint.ParseNote(note)
	if err != nil {
		return &IntegrityError{Stage: "checkpoint", Index: -1, Err: err}
	}
	if err := verifyRootAt(leaves, last); err != nil {
		return err
	}
	if attested != nil && attested.Size != last.Size {
		return verifyRootAt(leaves, *attested)
	}
	return nil
}

// verifyRootAt reconstruye la raíz de las primeras c.Size hojas y la compara con
// la que el checkpoint firmó.
func verifyRootAt(leaves [][]byte, c checkpoint.Checkpoint) error {
	if c.Size > uint64(len(leaves)) {
		return missingHistory(c.Size, len(leaves))
	}
	if root := ledger.Root(leaves[:c.Size]); !bytes.Equal(root, c.RootHash) {
		return &IntegrityError{
			Stage: "checkpoint", Index: -1,
			Err: fmt.Errorf("la raíz reconstruida de %d bloques es %s y el checkpoint firmó %s",
				c.Size, hex.EncodeToString(root), hex.EncodeToString(c.RootHash)),
		}
	}
	return nil
}

func missingHistory(promised uint64, have int) error {
	return &IntegrityError{
		Stage: "checkpoint", Index: -1,
		Err: fmt.Errorf("el checkpoint promete %d bloques y solo hay %d: falta historia", promised, have),
	}
}

// Root devuelve la raíz de Merkle del ledger completo, reconstruida en memoria
// desde los hashes de bloque.
//
// No se cachean subárboles: la reconstrucción son 119 ms con 10^5 bloques,
// medidos. La caché quedó DESCARTADA como remedio de la apertura en la enmienda
// de ADR-009, porque el coste que había que atacar eran las verificaciones
// Ed25519, no el árbol.
func (s *Store) Root() ([]byte, error) {
	leaves, err := s.LeafHashes()
	if err != nil {
		return nil, err
	}
	return ledger.Root(leaves), nil
}
