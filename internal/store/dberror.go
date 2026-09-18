package store

import (
	"errors"
	"fmt"
)

// Errores de la base clasificados por lo que significan para quien llama.
//
// Existen porque el mensaje del motor no es un mensaje: es un volcado. La cuarta
// auditoría (H8) encontró `UNIQUE constraint failed: blobs.payload_hash (1555)` saliendo
// por la primera línea de la CLI y, en `--json`, dentro del campo `error`, es decir,
// entrando en el log del integrador como si fuera contrato. Ver ADR-020 §E.
var (
	// ErrDuplicateBlob indica que ya hay un blob con ese payload_hash.
	ErrDuplicateBlob = errors.New("store: ya hay contenido guardado con ese payload_hash")
	// ErrConstraint indica que el esquema rechazó la escritura por alguna otra
	// restricción: un CHECK, una clave ajena, o uno de los disparadores append-only.
	ErrConstraint = errors.New("store: la base rechazó la escritura")
	// ErrBusy indica que otro proceso tiene la base ocupada.
	ErrBusy = errors.New("store: la base está ocupada por otro proceso")
	// ErrInternalDB es el cajón de lo que no se puede clasificar. Su texto no dice
	// nada del motor a propósito; el error del driver sigue ahí, envuelto, para quien
	// depure con errors.As.
	ErrInternalDB = errors.New("store: error interno de la base de datos")
)

// Códigos de resultado de SQLite, los primarios y los extendidos que se usan.
//
// Se clasifica por CÓDIGO y no por el texto del mensaje: el texto cambia entre
// versiones del motor y de la biblioteca, y un `strings.Contains` sobre él es una
// dependencia invisible a un detalle de empaquetado ajeno.
const (
	sqliteBusy       = 5  // SQLITE_BUSY
	sqliteLocked     = 6  // SQLITE_LOCKED
	sqliteConstraint = 19 // SQLITE_CONSTRAINT

	sqliteConstraintPrimaryKey = 1555 // SQLITE_CONSTRAINT_PRIMARYKEY
	sqliteConstraintUnique     = 2067 // SQLITE_CONSTRAINT_UNIQUE
)

// dbError es un error de la base con un mensaje propio.
//
// Envuelve DOS errores: la clase (uno de los sentinelas de arriba), para que
// errors.Is funcione, y el error crudo del driver, para que no se pierda. El texto
// visible solo compone la operación y la clase: el crudo se alcanza con errors.As,
// nunca se imprime.
type dbError struct {
	op   string
	kind error
	raw  error
}

func (e *dbError) Error() string { return fmt.Sprintf("%s: %s", e.op, textoSin(e.kind)) }

// Unwrap devuelve los dos, que es lo que hace que errors.Is(err, ErrDuplicateBlob) y
// errors.Is(err, errDelDriver) sean ciertos a la vez sin que el texto lo delate.
func (e *dbError) Unwrap() []error { return []error{e.kind, e.raw} }

// textoSin quita el prefijo "store: " del sentinela, que dbError ya pone por su cuenta
// al empezar la operación con él.
func textoSin(kind error) string {
	s := kind.Error()
	const p = "store: "
	if len(s) > len(p) && s[:len(p)] == p {
		return s[len(p):]
	}
	return s
}

// errDB clasifica un error del driver y lo devuelve con un mensaje de dominio.
//
// op describe la operación en español y sin jerga de SQL —"store: inserción del bloque
// 7"—: es lo que verá el usuario. dup es la clase que se devuelve cuando el motor dice
// que la fila ya existe, y la pone quien llama porque solo él sabe QUÉ ya existe; con
// nil, una clave repetida se queda en ErrConstraint.
func errDB(op string, dup error, err error) error {
	if err == nil {
		return nil
	}
	kind := ErrInternalDB
	var ce interface{ Code() int }
	if errors.As(err, &ce) {
		switch c := ce.Code(); {
		case c == sqliteConstraintPrimaryKey || c == sqliteConstraintUnique:
			kind = ErrConstraint
			if dup != nil {
				kind = dup
			}
		case c&0xff == sqliteConstraint:
			kind = ErrConstraint
		case c&0xff == sqliteBusy || c&0xff == sqliteLocked:
			kind = ErrBusy
		}
	}
	return &dbError{op: op, kind: kind, raw: err}
}
