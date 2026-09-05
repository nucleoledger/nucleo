// Package store persiste el ledger en SQLite embebido (driver Go puro, sin cgo)
// según PROTOCOL.md §8: WAL, synchronous=FULL y un solo escritor.
//
// Las tablas del ledger son append-only y lo hacen cumplir disparadores BEFORE
// UPDATE/DELETE que abortan. Conviene recordar por qué existen: son una
// barandilla contra el error y contra el atacante perezoso, NO la frontera de
// seguridad. Quien controle el fichero puede borrar los disparadores con una
// sentencia. Lo que hace irreversible una reescritura no es SQLite, son los
// testigos que ya cosignaron la raíz anterior (internal/witness).
package store

import (
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"sync"

	_ "modernc.org/sqlite"
)

var (
	// ErrNotFound indica que la fila pedida no existe.
	ErrNotFound = errors.New("store: no encontrado")
	// ErrAppendOnly indica que se intentó modificar o borrar una fila del ledger.
	ErrAppendOnly = errors.New("store: el ledger es append-only")
	// ErrClosed indica uso de un Store ya cerrado.
	ErrClosed = errors.New("store: base cerrada")
)

// Store es el ledger persistente. Es seguro para uso concurrente.
type Store struct {
	db   *sql.DB
	path string

	// writeMu serializa TODA escritura en el proceso.
	//
	// No es paranoia ni sustituto de las transacciones: AppendBlock decide el
	// índice y el prev_hash del bloque nuevo leyendo el último persistido. Dos
	// escritores concurrentes leerían el mismo "último bloque" y construirían
	// dos bloques con el mismo índice; el UNIQUE de hash rescataría algunos
	// casos, pero no todos, y el que perdiera la carrera ya habría firmado.
	// SQLite en WAL admite un escritor a la vez de todos modos, así que
	// serializar aquí convierte un error de datos en una espera.
	writeMu sync.Mutex
}

// Open abre la base, creándola si no existe, y verifica su integridad.
func Open(path string) (*Store, error) {
	if path == "" {
		return nil, errors.New("store: ruta vacía")
	}
	// Los PRAGMA se pasan en el DSN para que los reciba CADA conexión del pool:
	// journal_mode es persistente en el fichero, pero synchronous y
	// foreign_keys son por conexión y se perderían si solo se ejecutaran una vez.
	dsn := "file:" + url.PathEscape(path) +
		"?_pragma=journal_mode(WAL)" +
		"&_pragma=synchronous(FULL)" +
		"&_pragma=foreign_keys(ON)" +
		"&_pragma=busy_timeout(5000)"

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("store: apertura de %q: %w", path, err)
	}
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("store: apertura de %q: %w", path, err)
	}

	s := &Store{db: db, path: path}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

// Close cierra la base.
func (s *Store) Close() error {
	if s.db == nil {
		return nil
	}
	err := s.db.Close()
	s.db = nil
	return err
}

// Path devuelve la ruta del fichero.
func (s *Store) Path() string { return s.path }

// migrate crea el esquema si falta. El DDL es idempotente.
func (s *Store) migrate() error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if _, err := s.db.Exec(schemaSQL); err != nil {
		return fmt.Errorf("store: creación del esquema: %w", err)
	}
	return nil
}

// Pragma devuelve el valor actual de un PRAGMA, para poder comprobarlo.
func (s *Store) Pragma(name string) (string, error) {
	if s.db == nil {
		return "", ErrClosed
	}
	var v string
	// El nombre no viene de fuera: lo fija quien llama dentro del paquete o los
	// tests, así que no hay superficie de inyección aquí.
	if err := s.db.QueryRow("PRAGMA " + name).Scan(&v); err != nil {
		return "", fmt.Errorf("store: PRAGMA %s: %w", name, err)
	}
	return v, nil
}
