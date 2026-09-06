package witness

import (
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"sync"

	_ "modernc.org/sqlite"
)

// ErrNoState indica que el testigo nunca cosignó un checkpoint de ese origin.
var ErrNoState = errors.New("witness: sin checkpoint cosignado para ese origin")

// State es la memoria del testigo: para cada origin, la nota VERBATIM del
// último checkpoint que cosignó.
//
// Se guarda la nota entera y no solo el tamaño y la raíz por el mismo motivo por
// el que ADR-009 guarda así los checkpoints del log: los bytes exactos son lo
// firmado, y reserializar desde campos sueltos reintroduce el riesgo de que un
// cambio de formato invalide firmas ya emitidas. Además el endpoint de
// monitorización tiene que devolver esos bytes tal cual.
type State interface {
	// Advance ejecuta step DENTRO de una transacción y persiste lo que devuelva.
	//
	// step recibe la nota actual del origin (nil si no hay ninguna) y devuelve
	// la nota nueva. Si devuelve error, no se persiste nada.
	//
	// Que la comprobación y la escritura ocurran aquí dentro NO es un detalle de
	// implementación: es el requisito explícito de c2sp.org/tlog-witness. Si el
	// testigo comprobase el tamaño anterior y guardase el nuevo en dos pasos
	// separados, dos peticiones simultáneas podrían dejarlo avalando una
	// historia más corta que otra que ya avaló. El spec describe la carrera paso
	// a paso; esta interfaz existe para que no se pueda escribir.
	Advance(origin string, step func(current []byte) ([]byte, error)) error

	// Latest devuelve la nota verbatim del último checkpoint cosignado, o
	// ErrNoState.
	Latest(origin string) ([]byte, error)

	// Close libera los recursos.
	Close() error
}

// MemState es la memoria del testigo en RAM. Sirve para tests y para un testigo
// efímero; un testigo de verdad necesita PersistentState, porque olvidar lo que
// avaló es exactamente lo que un log malicioso quiere que le pase.
type MemState struct {
	mu    sync.Mutex
	notes map[string][]byte
}

// NewMemState crea una memoria vacía.
func NewMemState() *MemState { return &MemState{notes: map[string][]byte{}} }

func (m *MemState) Advance(origin string, step func(current []byte) ([]byte, error)) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	next, err := step(m.notes[origin])
	if err != nil {
		return err
	}
	m.notes[origin] = append([]byte(nil), next...)
	return nil
}

func (m *MemState) Latest(origin string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n, ok := m.notes[origin]
	if !ok {
		return nil, ErrNoState
	}
	return append([]byte(nil), n...), nil
}

func (m *MemState) Close() error { return nil }

// PersistentState guarda la memoria del testigo en su propio SQLite, separado
// del ledger: el testigo es una parte distinta, con su propia base y su propia
// clave, y esa separación es la razón por la que su recuerdo vale algo.
type PersistentState struct {
	db *sql.DB
}

const stateSchema = `
CREATE TABLE IF NOT EXISTS witness_logs (
	origin TEXT PRIMARY KEY,
	note   TEXT NOT NULL
);`

// OpenState abre —creándola si hace falta— la base del testigo.
func OpenState(path string) (*PersistentState, error) {
	if path == "" {
		return nil, errors.New("witness: ruta vacía")
	}
	// _txlock=immediate hace que cada BEGIN tome ya el candado de escritura.
	// Con el BEGIN diferido por defecto, dos transacciones podrían leer el mismo
	// estado y una fallaría al escribir: demasiado tarde, porque lo que hay que
	// serializar es la COMPROBACIÓN, no solo la escritura.
	dsn := "file:" + url.PathEscape(path) +
		"?_txlock=immediate" +
		"&_pragma=journal_mode(WAL)" +
		"&_pragma=synchronous(FULL)" +
		"&_pragma=busy_timeout(5000)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("witness: apertura de %q: %w", path, err)
	}
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("witness: apertura de %q: %w", path, err)
	}
	if _, err := db.Exec(stateSchema); err != nil {
		db.Close()
		return nil, fmt.Errorf("witness: esquema: %w", err)
	}
	return &PersistentState{db: db}, nil
}

func (p *PersistentState) Advance(origin string, step func(current []byte) ([]byte, error)) error {
	// La conexión se abre con _txlock=immediate, así que este BEGIN ya toma el
	// candado de escritura y la comprobación queda serializada con la escritura.
	tx, err := p.db.Begin()
	if err != nil {
		return fmt.Errorf("witness: transacción: %w", err)
	}
	defer tx.Rollback()

	var current []byte
	var stored string
	switch err := tx.QueryRow(`SELECT note FROM witness_logs WHERE origin = ?`, origin).Scan(&stored); {
	case err == nil:
		current = []byte(stored)
	case errors.Is(err, sql.ErrNoRows):
		current = nil
	default:
		return fmt.Errorf("witness: lectura del estado de %q: %w", origin, err)
	}

	next, err := step(current)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(
		`INSERT INTO witness_logs (origin, note) VALUES (?, ?)
		 ON CONFLICT(origin) DO UPDATE SET note = excluded.note`,
		origin, string(next)); err != nil {
		return fmt.Errorf("witness: escritura del estado de %q: %w", origin, err)
	}
	return tx.Commit()
}

func (p *PersistentState) Latest(origin string) ([]byte, error) {
	var stored string
	err := p.db.QueryRow(`SELECT note FROM witness_logs WHERE origin = ?`, origin).Scan(&stored)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNoState
	}
	if err != nil {
		return nil, fmt.Errorf("witness: lectura del estado de %q: %w", origin, err)
	}
	return []byte(stored), nil
}

func (p *PersistentState) Close() error {
	if p.db == nil {
		return nil
	}
	err := p.db.Close()
	p.db = nil
	return err
}
