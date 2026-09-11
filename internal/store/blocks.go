package store

import (
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/nucleoledger/nucleo/internal/ledger"
)

// AppendBlock añade un bloque al final del ledger.
//
// Valida el encadenamiento contra el último bloque PERSISTIDO antes de insertar:
// que el bloque sea internamente válido no basta, porque un bloque perfectamente
// firmado puede no seguir a este ledger. La comprobación y la inserción ocurren
// bajo el mismo candado de escritura, así que dos llamadas concurrentes no pueden
// ver el mismo "último bloque".
func (s *Store) AppendBlock(b *ledger.Block) error {
	if s.db == nil {
		return ErrClosed
	}
	if b == nil {
		return errors.New("store: bloque nulo")
	}
	if err := b.Verify(); err != nil {
		return fmt.Errorf("store: el bloque no es válido: %w", err)
	}

	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	last, err := s.lastBlock()
	switch {
	case errors.Is(err, ErrNotFound):
		// Ledger vacío: solo cabe el génesis.
		if b.Header.Index != 0 {
			return fmt.Errorf("%w: el primer bloque debe ser el 0, es el %d",
				ledger.ErrIndexSequence, b.Header.Index)
		}
	case err != nil:
		return err
	default:
		if err := ledger.VerifyLink(last, b); err != nil {
			return err
		}
	}

	canonical, err := b.Header.Canonical()
	if err != nil {
		return err
	}
	_, err = s.db.Exec(
		`INSERT INTO blocks (idx, hash, header_json, signature) VALUES (?, ?, ?, ?)`,
		int64(b.Header.Index), b.Hash, string(canonical), b.Signature)
	if err != nil {
		return fmt.Errorf("store: inserción del bloque %d: %w", b.Header.Index, err)
	}
	return nil
}

// LastBlock devuelve el último bloque persistido, o ErrNotFound si no hay ninguno.
func (s *Store) LastBlock() (*ledger.Block, error) {
	if s.db == nil {
		return nil, ErrClosed
	}
	return s.lastBlock()
}

// lastBlock no toma el candado: lo llaman quienes ya lo tienen y LastBlock, que
// solo lee.
func (s *Store) lastBlock() (*ledger.Block, error) {
	row := s.db.QueryRow(`SELECT idx, hash, header_json, signature FROM blocks ORDER BY idx DESC LIMIT 1`)
	b, err := scanBlock(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return b, err
}

// Count devuelve el número de bloques persistidos.
func (s *Store) Count() (int, error) {
	if s.db == nil {
		return 0, ErrClosed
	}
	var n int
	if err := s.db.QueryRow(`SELECT count(*) FROM blocks`).Scan(&n); err != nil {
		return 0, fmt.Errorf("store: conteo de bloques: %w", err)
	}
	return n, nil
}

// Blocks devuelve los bloques del rango semiabierto [from, to), en orden de
// índice. Con to <= from devuelve una lista vacía.
func (s *Store) Blocks(from, to uint64) ([]*ledger.Block, error) {
	if s.db == nil {
		return nil, ErrClosed
	}
	if to <= from {
		return nil, nil
	}
	rows, err := s.db.Query(
		`SELECT idx, hash, header_json, signature FROM blocks WHERE idx >= ? AND idx < ? ORDER BY idx`,
		int64(from), int64(to))
	if err != nil {
		return nil, fmt.Errorf("store: lectura de bloques [%d, %d): %w", from, to, err)
	}
	defer rows.Close()

	var out []*ledger.Block
	for rows.Next() {
		b, err := scanBlock(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: lectura de bloques [%d, %d): %w", from, to, err)
	}
	return out, nil
}

// AllBlocks devuelve el ledger completo en orden.
func (s *Store) AllBlocks() ([]*ledger.Block, error) {
	n, err := s.Count()
	if err != nil {
		return nil, err
	}
	if n == 0 {
		return nil, nil
	}
	last, err := s.LastBlock()
	if err != nil {
		return nil, err
	}
	return s.Blocks(0, last.Header.Index+1)
}

// LeafData devuelve los leaf_data de los bloques en orden: las hojas del árbol de
// Merkle bajo la regla leaf/v2 (PROTOCOL.md §2.1), que es hash ‖ signature.
//
// Antes se llamaba LeafHashes y leía solo la columna hash. El nombre era engañoso
// incluso entonces —devolvía datos de hoja, no hashes de hoja— y con leaf/v2 habría
// sido directamente falso. Ahora lee las dos columnas, que es lo que hace que una
// raíz cosignada clave también las firmas: bajo leaf/v1, alguien con escritura en
// la base podía destrozar la columna signature sin que la raíz lo notara.
//
// Se leen sin reconstruir los headers, que es lo que permite recomponer la raíz en
// una sola pasada.
func (s *Store) LeafData() ([][]byte, error) {
	if s.db == nil {
		return nil, ErrClosed
	}
	rows, err := s.db.Query(`SELECT hash, signature FROM blocks ORDER BY idx`)
	if err != nil {
		return nil, fmt.Errorf("store: lectura de hojas: %w", err)
	}
	defer rows.Close()

	var out [][]byte
	for rows.Next() {
		var hexHash, hexSig string
		if err := rows.Scan(&hexHash, &hexSig); err != nil {
			return nil, err
		}
		hash, err := decodeHash(hexHash)
		if err != nil {
			return nil, err
		}
		sig, err := hex.DecodeString(hexSig)
		if err != nil {
			return nil, fmt.Errorf("store: firma no es hex: %w", err)
		}
		data, err := ledger.LeafData(hash, sig)
		if err != nil {
			return nil, err
		}
		out = append(out, data)
	}
	return out, rows.Err()
}

// scanner abstrae *sql.Row y *sql.Rows.
type scanner interface{ Scan(dest ...any) error }

// scanBlock reconstruye el bloque desde su fila. El header se guarda en su forma
// canónica JCS, que es exactamente lo que se firmó.
func scanBlock(sc scanner) (*ledger.Block, error) {
	var (
		idx        int64
		hash       string
		headerJSON string
		signature  string
	)
	if err := sc.Scan(&idx, &hash, &headerJSON, &signature); err != nil {
		return nil, err
	}
	return decodeBlock(idx, hash, headerJSON, signature)
}
