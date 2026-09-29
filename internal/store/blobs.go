package store

import (
	"bytes"
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

// ErrMetaChanged indica que una fila de vault_meta ya no tiene el valor que se leyó:
// otro proceso la cambió entre la lectura y la escritura, y no se pisa su cambio.
var ErrMetaChanged = errors.New("store: vault_meta cambió desde que se leyó")

// hookMetaTx, si no es nil, se llama dentro de la transacción de ReplaceMeta después
// de cada escritura, con la clave escrita. Solo lo fija un binario de pruebas
// (hooks_testhooks.go) para matar el proceso A MEDIAS de la transacción y comprobar
// que no queda nada escrito (ADR-029 §C). En producción es nil siempre.
var hookMetaTx func(clave string)

// ReplaceMeta sustituye varias filas de vault_meta en UNA transacción, y solo si las
// filas de expected siguen teniendo exactamente ese valor; si no, ErrMetaChanged y no
// se escribe nada.
//
// Existe para el cambio de passphrase (ADR-029): el salt y la DEK envuelta van juntos
// o no van. Un salt nuevo con la DEK envuelta vieja dejaría un vault que no abre ni la
// passphrase vieja ni la nueva. La comprobación previa es la que evita pisar el cambio
// de otro proceso que hiciera lo mismo a la vez.
func (s *Store) ReplaceMeta(expected, updates map[string][]byte) error {
	if s.db == nil {
		return ErrClosed
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	tx, err := s.db.Begin()
	if err != nil {
		return errDB("store: apertura de la transacción de vault_meta", nil, err)
	}
	// Rollback tras un Commit correcto no hace nada: el defer es para el camino de error.
	defer func() { _ = tx.Rollback() }()

	for _, k := range clavesOrdenadas(expected) {
		var v []byte
		err := tx.QueryRow(`SELECT v FROM vault_meta WHERE k = ?`, k).Scan(&v)
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("%w: falta %s", ErrMetaChanged, k)
		}
		if err != nil {
			return errDB(fmt.Sprintf("store: lectura de vault_meta[%s]", k), nil, err)
		}
		if !bytes.Equal(v, expected[k]) {
			return fmt.Errorf("%w: %s", ErrMetaChanged, k)
		}
	}
	for _, k := range clavesOrdenadas(updates) {
		if err := insertMeta(tx, k, updates[k]); err != nil {
			return err
		}
		if hookMetaTx != nil {
			hookMetaTx(k)
		}
	}
	if err := tx.Commit(); err != nil {
		return errDB("store: cierre de la transacción de vault_meta", nil, err)
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
		return nil, errDB(fmt.Sprintf("store: lectura de vault_meta[%s]", key), nil, err)
	}
	return v, nil
}
