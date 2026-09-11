package store

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

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

// LastSignedKey es la clave bajo la que se guarda el último checkpoint que el
// log FIRMÓ, esté cosignado o no.
const LastSignedKey = "log/last-signed/v1"

// PutLastSigned guarda la nota del último checkpoint firmado por el log.
//
// Va en log_state y no en checkpoints porque son dos cosas distintas: la tabla
// checkpoints es append-only y guarda las promesas ya avaladas, una por tamaño;
// esto es el cerrojo del emisor, que avanza. Mezclarlas obligaría a escribir dos
// notas para el mismo tamaño —la firmada y la cosignada— y la tabla append-only
// rechaza la segunda, con razón.
func (s *Store) PutLastSigned(note []byte) error {
	if s.db == nil {
		return ErrClosed
	}
	if _, err := checkpoint.ParseNote(note); err != nil {
		return err
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	_, err := s.db.Exec(
		`INSERT INTO log_state (k, v) VALUES (?, ?)
		 ON CONFLICT(k) DO UPDATE SET v = excluded.v`,
		LastSignedKey, string(note))
	if err != nil {
		return fmt.Errorf("store: escritura del último checkpoint firmado: %w", err)
	}
	return nil
}

// LastSigned devuelve la nota del último checkpoint firmado por el log, o nil
// si no hay ninguno. Un ledger sin checkpoints firmados no es un error.
func (s *Store) LastSigned() ([]byte, error) {
	if s.db == nil {
		return nil, ErrClosed
	}
	var v string
	err := s.db.QueryRow(`SELECT v FROM log_state WHERE k = ?`, LastSignedKey).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("store: lectura del último checkpoint firmado: %w", err)
	}
	return []byte(v), nil
}

// LastAttestedKey es la clave bajo la que se guarda cuándo obtuvo este
// despliegue, por última vez, una atestación VERIFICADA de un testigo.
const LastAttestedKey = "log/last-attested/v1"

// AttestationRecord es lo que se guarda bajo LastAttestedKey.
//
// Guarda DOS instantes porque responden a preguntas distintas y confundirlas es
// justo el error que ADR-002 prohíbe:
//
//   - At es el timestamp de la cosignature: lo afirmó el testigo y se verificó
//     contra su clave antes de escribir esto. Es el que cuenta para decidir si la
//     atestación está vieja.
//   - RecordedAt es el reloj local del momento en que se guardó. Sirve para
//     detectar un desfase grosero entre las dos máquinas, y para diagnosticar.
type AttestationRecord struct {
	// Witness es el nombre del testigo cuya cosignature se verificó.
	Witness string `json:"witness"`
	// At es el timestamp de esa cosignature, en UTC.
	At time.Time `json:"at"`
	// Size es el tamaño del árbol que la cosignature cubría.
	Size uint64 `json:"size"`
	// RecordedAt es el reloj local al guardar, en UTC.
	RecordedAt time.Time `json:"recorded_at"`
}

// PutLastAttested guarda el registro de la última atestación verificada.
//
// Solo debe llamarse cuando la cosignature se ha VERIFICADO contra la clave del
// testigo. El registro es una caché del resultado de esa verificación: permite
// que `status` responda "hace cuánto que un tercero avaló esto" sin tener que
// pedir al operador la clave del testigo en cada invocación, que es la razón por
// la que nadie ejecutaría el chequeo.
//
// Va en log_state, que es mutable por diseño (enmienda de ADR-009): avanza con
// cada sincronización y no es una promesa append-only.
func (s *Store) PutLastAttested(r AttestationRecord) error {
	if s.db == nil {
		return ErrClosed
	}
	if r.Witness == "" || r.At.IsZero() {
		return fmt.Errorf("store: registro de atestación incompleto")
	}
	r.At = r.At.UTC()
	r.RecordedAt = r.RecordedAt.UTC()
	raw, err := json.Marshal(r)
	if err != nil {
		return fmt.Errorf("store: serialización del registro de atestación: %w", err)
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if _, err := s.db.Exec(
		`INSERT INTO log_state (k, v) VALUES (?, ?)
		 ON CONFLICT(k) DO UPDATE SET v = excluded.v`,
		LastAttestedKey, string(raw)); err != nil {
		return fmt.Errorf("store: escritura del registro de atestación: %w", err)
	}
	return nil
}

// LastAttested devuelve el registro de la última atestación verificada.
//
// El segundo valor es false cuando no hay ninguno, que NO es un error: un ledger
// recién creado, o uno que nunca sincronizó, está en ese estado. Quien llama
// debe tratar la ausencia como el caso más grave, no como falta de información:
// un despliegue que nunca obtuvo atestación está exactamente tan desamparado
// como uno cuya última atestación es de hace un año.
func (s *Store) LastAttested() (AttestationRecord, bool, error) {
	if s.db == nil {
		return AttestationRecord{}, false, ErrClosed
	}
	var v string
	err := s.db.QueryRow(`SELECT v FROM log_state WHERE k = ?`, LastAttestedKey).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return AttestationRecord{}, false, nil
	}
	if err != nil {
		return AttestationRecord{}, false, fmt.Errorf("store: lectura del registro de atestación: %w", err)
	}
	var r AttestationRecord
	if err := json.Unmarshal([]byte(v), &r); err != nil {
		return AttestationRecord{}, false, fmt.Errorf("store: registro de atestación ilegible: %w", err)
	}
	return r, true, nil
}
