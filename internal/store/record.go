package store

import (
	"database/sql"
	"errors"
	"fmt"

	"github.com/nucleoledger/nucleo/internal/ledger"
)

// Record es TODO lo que un sellado escribe, para poder escribirlo de una vez.
//
// Antes eran tres escrituras sueltas —blob, bloque, compromisos— en ese orden, con un
// comentario que justificaba el orden: si el proceso muere entre las dos primeras, sobra
// un blob sin bloque, que es inofensivo, en vez de faltar el contenido de un bloque ya
// sellado. El razonamiento era correcto y la conclusión falsa: el huérfano NO era
// inofensivo, porque payload_hash es la clave primaria de blobs y el reintento chocaba
// con él PARA SIEMPRE. Ese documento no se podía volver a sellar en ese ledger nunca
// más. Reproducido en ADR-020, que decide esto: una transacción, o está todo o no está
// nada, y el orden entre las escrituras deja de ser un argumento.
type Record struct {
	// Block es el bloque a añadir. Obligatorio.
	Block *ledger.Block
	// Blob es el contenido cifrado, o nil con --no-encrypt.
	Blob *Blob
	// Meta son entradas de vault_meta: los compromisos del perfil van aquí.
	Meta map[string][]byte
	// State son entradas de log_state: la clave de idempotencia va aquí.
	State map[string]string
}

// AppendRecord escribe el registro entero en una transacción.
//
// La validación del encadenamiento ocurre DENTRO de la transacción, leyendo el último
// bloque persistido, así que no puede quedar desfasada respecto de lo que se inserta.
func (s *Store) AppendRecord(r Record) error {
	if s.db == nil {
		return ErrClosed
	}
	if r.Block == nil {
		return errors.New("store: registro sin bloque")
	}
	if err := r.Block.Verify(); err != nil {
		return fmt.Errorf("store: el bloque no es válido: %w", err)
	}
	if r.Blob != nil {
		if err := validateBlob(r.Blob); err != nil {
			return err
		}
	}

	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	tx, err := s.db.Begin()
	if err != nil {
		return errDB("store: apertura de la transacción de sellado", nil, err)
	}
	// Rollback tras un Commit correcto devuelve ErrTxDone y no hace nada: el defer está
	// para el camino de error, que es el que importa.
	defer func() { _ = tx.Rollback() }()

	if err := s.checkLink(tx, r.Block); err != nil {
		return err
	}
	if r.Blob != nil {
		if err := insertBlob(tx, r.Blob); err != nil {
			return err
		}
	}
	if err := insertBlock(tx, r.Block); err != nil {
		return err
	}
	for _, k := range clavesOrdenadas(r.Meta) {
		if err := insertMeta(tx, k, r.Meta[k]); err != nil {
			return err
		}
	}
	for _, k := range clavesOrdenadas(r.State) {
		if err := insertState(tx, k, r.State[k]); err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return errDB("store: cierre de la transacción de sellado", nil, err)
	}
	return nil
}

// checkLink comprueba que el bloque siga al último persistido, leyéndolo dentro de la
// transacción.
func (s *Store) checkLink(q consulta, b *ledger.Block) error {
	last, err := lastBlockDe(q)
	switch {
	case errors.Is(err, ErrNotFound):
		// Ledger vacío: solo cabe el génesis.
		if b.Header.Index != 0 {
			return fmt.Errorf("%w: el primer bloque debe ser el 0, es el %d",
				ledger.ErrIndexSequence, b.Header.Index)
		}
		return nil
	case err != nil:
		return err
	default:
		return ledger.VerifyLink(last, b)
	}
}

// consulta es lo que comparten *sql.DB y *sql.Tx para leer una fila.
type consulta interface {
	QueryRow(query string, args ...any) *sql.Row
}

// ejecuta es lo que comparten *sql.DB y *sql.Tx para escribir.
type ejecuta interface {
	Exec(query string, args ...any) (sql.Result, error)
}

func insertBlock(e ejecuta, b *ledger.Block) error {
	canonical, err := b.Header.Canonical()
	if err != nil {
		return err
	}
	_, err = e.Exec(
		`INSERT INTO blocks (idx, hash, header_json, signature) VALUES (?, ?, ?, ?)`,
		int64(b.Header.Index), b.Hash, string(canonical), b.Signature)
	return errDB(fmt.Sprintf("store: inserción del bloque %d", b.Header.Index), ErrAppendOnly, err)
}

func insertBlob(e ejecuta, b *Blob) error {
	_, err := e.Exec(
		`INSERT INTO blobs (payload_hash, ciphertext, nonce, created_at) VALUES (?, ?, ?, ?)`,
		b.PayloadHash, b.Ciphertext, b.Nonce, b.CreatedAt)
	return errDB(fmt.Sprintf("store: inserción del contenido %s", b.PayloadHash), ErrDuplicateBlob, err)
}

func insertMeta(e ejecuta, k string, v []byte) error {
	_, err := e.Exec(
		`INSERT INTO vault_meta (k, v) VALUES (?, ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v`, k, v)
	return errDB(fmt.Sprintf("store: escritura de vault_meta[%s]", k), nil, err)
}

func insertState(e ejecuta, k, v string) error {
	_, err := e.Exec(
		`INSERT INTO log_state (k, v) VALUES (?, ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v`, k, v)
	return errDB(fmt.Sprintf("store: escritura de log_state[%s]", k), nil, err)
}

// State lee una entrada de log_state, o ErrNotFound.
func (s *Store) State(k string) (string, error) {
	if s.db == nil {
		return "", ErrClosed
	}
	var v string
	err := s.db.QueryRow(`SELECT v FROM log_state WHERE k = ?`, k).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", errDB(fmt.Sprintf("store: lectura de log_state[%s]", k), nil, err)
	}
	return v, nil
}

// BlocksWithPayload devuelve los índices de los bloques cuyo header declara ese
// payload_hash, en orden.
//
// Se busca dentro del texto del header porque el payload_hash no tiene columna propia
// —el esquema de ADR-009 está congelado— y se puede buscar así porque header_json está
// guardado en su forma canónica JCS: sin espacios y con las claves ordenadas, la cadena
// `"payload_hash":"<hex>"` aparece exactamente una vez y solo si es ese hash. El hex es
// minúsculo por PROTOCOL §1 y decodeHash lo exige, así que el patrón no lleva ningún
// metacarácter de LIKE y no depende de la colación.
//
// Es una pasada sobre la tabla. La usa el sellado para poder NOMBRAR el bloque del que
// un contenido es duplicado (ADR-020 §A), que es lo que evita que un duplicado
// accidental pase en silencio.
func (s *Store) BlocksWithPayload(payloadHash string) ([]uint64, error) {
	if s.db == nil {
		return nil, ErrClosed
	}
	if _, err := decodeHash(payloadHash); err != nil {
		return nil, err
	}
	rows, err := s.db.Query(
		`SELECT idx FROM blocks WHERE header_json LIKE ? ESCAPE '\' ORDER BY idx`,
		`%"payload_hash":"`+payloadHash+`"%`)
	if err != nil {
		return nil, errDB("store: búsqueda de bloques por contenido", nil, err)
	}
	defer rows.Close()

	var out []uint64
	for rows.Next() {
		var idx int64
		if err := rows.Scan(&idx); err != nil {
			return nil, errDB("store: búsqueda de bloques por contenido", nil, err)
		}
		out = append(out, uint64(idx))
	}
	if err := rows.Err(); err != nil {
		return nil, errDB("store: búsqueda de bloques por contenido", nil, err)
	}
	return out, nil
}
