package store

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/nucleoledger/nucleo/internal/checkpoint"
)

// PutCheckpoint guarda una nota de checkpoint tal cual, con sus cosignatures.
//
// El tamaño del árbol se deriva del propio cuerpo de la nota en vez de pedirlo
// aparte: así el índice de la tabla no puede contradecir a lo que está firmado.
// Guardar el mismo tamaño dos veces con notas distintas se rechaza — el
// disparador de append-only lo impediría igualmente, pero conviene que el error
// diga lo que pasa.
func (s *Store) PutCheckpoint(note []byte) error {
	if s.db == nil {
		return ErrClosed
	}
	c, err := checkpoint.ParseNote(note)
	if err != nil {
		return err
	}

	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	var existing string
	err = s.db.QueryRow(`SELECT note FROM checkpoints WHERE tree_size = ?`, int64(c.Size)).Scan(&existing)
	switch {
	case err == nil:
		if existing == string(note) {
			return nil // reemitir el mismo checkpoint es inocuo
		}
		return fmt.Errorf("%w: ya hay otro checkpoint para el tamaño %d", ErrAppendOnly, c.Size)
	case !errors.Is(err, sql.ErrNoRows):
		return fmt.Errorf("store: lectura de checkpoint %d: %w", c.Size, err)
	}

	if _, err := s.db.Exec(`INSERT INTO checkpoints (tree_size, note) VALUES (?, ?)`,
		int64(c.Size), string(note)); err != nil {
		return fmt.Errorf("store: inserción del checkpoint %d: %w", c.Size, err)
	}
	return nil
}

// LastCheckpoint devuelve la nota del checkpoint de mayor tamaño, o ErrNotFound.
func (s *Store) LastCheckpoint() ([]byte, error) {
	if s.db == nil {
		return nil, ErrClosed
	}
	var note string
	err := s.db.QueryRow(`SELECT note FROM checkpoints ORDER BY tree_size DESC LIMIT 1`).Scan(&note)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("store: lectura del último checkpoint: %w", err)
	}
	return []byte(note), nil
}

// Checkpoint devuelve la nota guardada para un tamaño concreto.
func (s *Store) Checkpoint(treeSize uint64) ([]byte, error) {
	if s.db == nil {
		return nil, ErrClosed
	}
	var note string
	err := s.db.QueryRow(`SELECT note FROM checkpoints WHERE tree_size = ?`, int64(treeSize)).Scan(&note)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("store: lectura del checkpoint %d: %w", treeSize, err)
	}
	return []byte(note), nil
}

// decodeHash convierte un hash hexadecimal de la base a sus 32 bytes.
func decodeHash(s string) ([]byte, error) {
	raw, err := hex.DecodeString(s)
	if err != nil || len(raw) != sha256.Size {
		return nil, fmt.Errorf("store: hash inválido en la base: %q", s)
	}
	return raw, nil
}

// LastCosignedCheckpoint devuelve la nota del checkpoint COSIGNADO de mayor
// tamaño, o ErrNotFound si ninguno lo está.
//
// "Cosignado" se decide por la forma del blob de firma (checkpoint.IsCosigned),
// no verificando claves de testigos: el almacén no las conoce. Ver la enmienda
// de ADR-009 para lo que eso concede y lo que no.
func (s *Store) LastCosignedCheckpoint() ([]byte, error) {
	if s.db == nil {
		return nil, ErrClosed
	}
	rows, err := s.db.Query(`SELECT note FROM checkpoints ORDER BY tree_size DESC`)
	if err != nil {
		return nil, fmt.Errorf("store: lectura de checkpoints: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var note string
		if err := rows.Scan(&note); err != nil {
			return nil, err
		}
		if checkpoint.IsCosigned([]byte(note)) {
			return []byte(note), nil
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: lectura de checkpoints: %w", err)
	}
	return nil, ErrNotFound
}
