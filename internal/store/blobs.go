package store

import (
	"database/sql"
	"errors"
	"fmt"
	"sort"
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
//
// Ya con el payload_hash repetido devuelve ErrDuplicateBlob, que es una CLASE, no el
// volcado del motor (ADR-020 §E). El sellado no la usa: escribe el blob y el bloque en
// la misma transacción con AppendRecord.
func (s *Store) PutBlob(payloadHash string, ciphertext, nonce []byte) error {
	if s.db == nil {
		return ErrClosed
	}
	b := &Blob{
		PayloadHash: payloadHash,
		Ciphertext:  ciphertext,
		Nonce:       nonce,
		CreatedAt:   time.Now().UTC().Format(time.RFC3339Nano),
	}
	if err := validateBlob(b); err != nil {
		return err
	}

	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	return insertBlob(s.db, b)
}

// validateBlob comprueba lo que el esquema no puede: que el hash sea un SHA-256 en hex
// minúsculo y que haya texto cifrado y nonce.
func validateBlob(b *Blob) error {
	if _, err := decodeHash(b.PayloadHash); err != nil {
		return err
	}
	if len(b.Ciphertext) == 0 || len(b.Nonce) == 0 {
		return errors.New("store: contenido cifrado sin texto o sin nonce")
	}
	if b.CreatedAt == "" {
		return errors.New("store: contenido cifrado sin fecha")
	}
	return nil
}

// clavesOrdenadas devuelve las claves de un mapa en orden, para que una transacción
// escriba siempre en la misma secuencia y dos ejecuciones sean comparables.
func clavesOrdenadas[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
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
		return nil, errDB(fmt.Sprintf("store: lectura del contenido %s", payloadHash), nil, err)
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

	_, err := s.db.Exec(`DELETE FROM blobs WHERE payload_hash = ?`, payloadHash)
	return errDB(fmt.Sprintf("store: borrado del contenido %s", payloadHash), nil, err)
}

// PutMeta guarda un valor en vault_meta. A diferencia del ledger, esta tabla sí
// admite actualización: guarda parámetros de derivación, no historia.
func (s *Store) PutMeta(key string, value []byte) error {
	if s.db == nil {
		return ErrClosed
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	return insertMeta(s.db, key, value)
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
		return nil, errDB(fmt.Sprintf("store: lectura de vault_meta[%s]", key), nil, err)
	}
	return v, nil
}
