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

	// opened guarda el estado con el que se verificó la base al abrirla.
	opened OpenResult

	// witnesses es la política de testigos que aportó quien abrió, o nil. Sin
	// ella la apertura no puede reportar atestación verificada (ADR-016).
	witnesses *WitnessPolicy
}

// Open abre la base, creándola si no existe, verifica su integridad y devuelve
// QUÉ respalda la historia que acaba de verificar.
//
// El OpenResult no es decoración: una base puede abrir perfectamente y ser un
// prefijo truncado de la historia real (ver el comentario de OpenResult). Quien
// abre necesita poder distinguir "atestiguada hasta N" de "localmente válida y
// nada más", y por eso el estado viaja en el valor de retorno en lugar de
// quedarse implícito en la ausencia de error.
//
// La verificación reconstruye el árbol completo y solo recomputa las firmas
// Ed25519 posteriores al último checkpoint cosignado (enmienda de ADR-009).
// Para la verificación exhaustiva está VerifyFull.
func Open(path string) (*Store, OpenResult, error) { return open(path, nil) }

// OpenWithWitnesses abre como Open, aportando la política de testigos desde
// fuera del fichero. Es la única forma de que el resultado diga
// AttestationVerified, y por tanto la única que toma el atajo de ADR-009.
func OpenWithWitnesses(path string, wp WitnessPolicy) (*Store, OpenResult, error) {
	return open(path, &wp)
}

func open(path string, wp *WitnessPolicy) (*Store, OpenResult, error) {
	s, err := connect(path)
	if err != nil {
		return nil, OpenResult{}, err
	}
	s.witnesses = wp
	// La regla de hoja se comprueba ANTES de la integridad. Si el log es de otra
	// regla, la raíz no va a cuadrar jamás, y un error que diga "la raíz no cuadra"
	// mandaría a buscar corrupción donde hay un cambio de versión.
	if err := s.checkLeafRule(); err != nil {
		s.db.Close()
		return nil, OpenResult{}, err
	}
	// Abrir es el momento de descubrir que alguien tocó el fichero: después ya
	// se estaría sellando encima de una historia alterada.
	res, err := s.VerifyIntegrity()
	if err != nil {
		s.db.Close()
		return nil, OpenResult{}, err
	}
	s.opened = res
	return s, res, nil
}

// connect abre la conexión y aplica el esquema, SIN verificar la integridad.
//
// Está separado de Open porque montar el escenario de un emisor deshonesto —uno
// que escribe en la base antes de atestiguar— exige poder abrirla sin pasar por la
// verificación, y porque duplicar el DSN en un test significaría que los PRAGMA del
// test y los de producción pueden divergir sin que nada avise. No se exporta: nadie
// fuera de este paquete debería poder saltarse la verificación de apertura.
func connect(path string) (*Store, error) {
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

// Attestation devuelve el estado con el que se abrió la base, para quien recibe
// el *Store sin haber visto el resultado de Open.
//
// Es una foto del momento de la apertura: los bloques añadidos después no están
// atestiguados hasta que un testigo cosigne una raíz que los cubra.
func (s *Store) Attestation() OpenResult { return s.opened }

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
