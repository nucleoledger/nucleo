package store

import (
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// Blob es un payload cifrado fuera del ledger. El ledger solo guarda su
// compromiso (payload_hash); el contenido vive aquí y puede borrarse.
type Blob struct {
	PayloadHash string
	Ciphertext  []byte
	Nonce       []byte
	CreatedAt   string
}

// PutBlob guarda un payload cifrado. La tabla no admite UPDATE, así que volver a
// escribir el mismo payload_hash con otro contenido se rechaza: sustituir un
// texto cifrado bajo el mismo compromiso sería reescribir el dato sin tocar el
// ledger.
func (s *Store) PutBlob(payloadHash string, ciphertext, nonce []byte) error {
	if s.db == nil {
		return ErrClosed
	}
	if _, err := decodeHash(payloadHash); err != nil {
		return err
	}
	if len(ciphertext) == 0 || len(nonce) == 0 {
		return errors.New("store: blob sin texto cifrado o sin nonce")
	}

	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	_, err := s.db.Exec(
		`INSERT INTO blobs (payload_hash, ciphertext, nonce, created_at) VALUES (?, ?, ?, ?)`,
		payloadHash, ciphertext, nonce, time.Now().UTC().Format(time.RFC3339Nano))
	if err != nil {
		return fmt.Errorf("store: inserción del blob %s: %w", payloadHash, err)
	}
	return nil
}

// GetBlob devuelve un payload cifrado, o ErrNotFound si ya fue borrado.
func (s *Store) GetBlob(payloadHash string) (*Blob, error) {
	if s.db == nil {
		return nil, ErrClosed
	}
	b := &Blob{PayloadHash: payloadHash}
	err := s.db.QueryRow(
		`SELECT ciphertext, nonce, created_at FROM blobs WHERE payload_hash = ?`, payloadHash).
		Scan(&b.Ciphertext, &b.Nonce, &b.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("store: lectura del blob %s: %w", payloadHash, err)
	}
	return b, nil
}

// DeleteBlob borra un payload cifrado y deja el ledger intacto.
//
// Esto ES el cumplimiento de la LOPDP por construcción: el dato personal
// desaparece, el compromiso que demuestra que existió y cuándo se selló
// permanece, y la cadena y las pruebas de inclusión siguen verificando. Borrar
// dos veces no es un error: el efecto deseado —que el dato no esté— ya se
// cumplió.
func (s *Store) DeleteBlob(payloadHash string) error {
	if s.db == nil {
		return ErrClosed
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	if _, err := s.db.Exec(`DELETE FROM blobs WHERE payload_hash = ?`, payloadHash); err != nil {
		return fmt.Errorf("store: borrado del blob %s: %w", payloadHash, err)
	}
	return nil
}

// PutMeta guarda un valor en vault_meta. A diferencia del ledger, esta tabla sí
// admite actualización: guarda parámetros de derivación, no historia.
func (s *Store) PutMeta(key string, value []byte) error {
	if s.db == nil {
		return ErrClosed
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	if _, err := s.db.Exec(
		`INSERT INTO vault_meta (k, v) VALUES (?, ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v`,
		key, value); err != nil {
		return fmt.Errorf("store: escritura de vault_meta[%s]: %w", key, err)
	}
	return nil
}

// GetMeta lee un valor de vault_meta, o ErrNotFound.
func (s *Store) GetMeta(key string) ([]byte, error) {
	if s.db == nil {
		return nil, ErrClosed
	}
	var v []byte
	err := s.db.QueryRow(`SELECT v FROM vault_meta WHERE k = ?`, key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("store: lectura de vault_meta[%s]: %w", key, err)
	}
	return v, nil
}
