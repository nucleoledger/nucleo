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
//
// Y el equilibrio que el ensayo de operación del Sprint 10 corrigió por el otro lado: no
// decir jerga del motor no es lo mismo que no decir nada. Con una sola clase genérica, un
// ledger sin permisos de escritura, un disco lleno, otro proceso escribiendo y un fichero
// que no es una base daban el MISMO "error interno de la base de datos", y el operador no
// tenía por dónde empezar. Cada clase de abajo lleva su acción: qué mirar, si el registro
// se escribió o no, y si reintentar sirve.
var (
	// ErrDuplicateBlob indica que ya hay un blob con ese payload_hash.
	ErrDuplicateBlob = errors.New("store: ya hay contenido guardado con ese payload_hash")
	// ErrConstraint indica que el esquema rechazó la escritura por alguna otra
	// restricción: un CHECK, una clave ajena, o uno de los disparadores append-only.
	ErrConstraint = errors.New("store: la base rechazó la escritura")
	// ErrBusy indica que otro proceso tiene la base ocupada. Es TRANSITORIO: el
	// reintento es la respuesta, y con --idempotency-key no duplica nada (ADR-020 §D).
	ErrBusy = errors.New("store: otro proceso tiene el ledger tomado; el registro NO se escribió. " +
		"Reintenta —con --idempotency-key si el reintento puede repetirse (ADR-020)")
	// ErrReadOnly indica que el fichero no se puede escribir.
	//
	// Su mensaje nombra los TRES ficheros, y el tercero es el que nadie adivina: SQLite
	// crea `-wal` y `-shm` junto a la base y hereda sus permisos. El ensayo de operación
	// del Sprint 10 dejó `nucleo.db` en 644 y el `-shm` en 444, y el despliegue quedó
	// inservible con un "error interno de la base de datos" que no señalaba a ningún
	// sitio. `chmod 644 nucleo.db-shm` lo resucitó.
	ErrReadOnly = errors.New("store: el ledger no se puede escribir. Comprueba los permisos y el dueño de " +
		"nucleo.db, nucleo.db-wal y nucleo.db-shm —los dos últimos los crea el motor de la base junto al " +
		"primero y heredan sus permisos— y del directorio que los contiene")
	// ErrDiskFull indica que no cabe.
	ErrDiskFull = errors.New("store: no queda espacio para escribir el ledger. Libera disco y reintenta; " +
		"el registro NO se escribió")
	// ErrIO indica un fallo de entrada/salida al escribir o leer.
	ErrIO = errors.New("store: fallo de entrada/salida en el ledger. Si se repite, el disco o el sistema de " +
		"ficheros están dando problemas; copia el fichero a otro sitio antes de seguir")
	// ErrNotALedger indica un fichero que no es una base de Núcleo, o que está corrupto.
	ErrNotALedger = errors.New("store: el fichero no es un ledger de Núcleo, o está dañado. Si restauraste " +
		"un respaldo, comprueba que copiaste nucleo.db entero")
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
	sqliteReadOnly   = 8  // SQLITE_READONLY
	sqliteBusy       = 5  // SQLITE_BUSY
	sqliteLocked     = 6  // SQLITE_LOCKED
	sqliteIOErr      = 10 // SQLITE_IOERR
	sqliteCorrupt    = 11 // SQLITE_CORRUPT
	sqliteFull       = 13 // SQLITE_FULL
	sqliteCantOpen   = 14 // SQLITE_CANTOPEN
	sqliteConstraint = 19 // SQLITE_CONSTRAINT
	sqliteNotADB     = 26 // SQLITE_NOTADB

	sqliteConstraintPrimaryKey = 1555 // SQLITE_CONSTRAINT_PRIMARYKEY
	sqliteConstraintUnique     = 2067 // SQLITE_CONSTRAINT_UNIQUE
	// SQLITE_IOERR_WRITE y compañía son extendidos de IOERR; se clasifican por el
	// primario (código & 0xff), así que no hace falta enumerarlos.
	//
	// SQLITE_FULL llega como primario, pero un disco lleno en WAL puede aparecer
	// también como SQLITE_IOERR_WRITE: los dos mensajes mandan al operador al mismo
	// sitio, que es mirar el disco.
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
		case c&0xff == sqliteReadOnly:
			kind = ErrReadOnly
		case c&0xff == sqliteFull:
			kind = ErrDiskFull
		case c&0xff == sqliteIOErr:
			kind = ErrIO
		case c&0xff == sqliteCorrupt || c&0xff == sqliteNotADB:
			kind = ErrNotALedger
		case c&0xff == sqliteCantOpen:
			// No se pudo ni abrir: permisos del directorio, ruta que no existe, o un
			// -wal/-shm que no se puede crear. Es el mismo consejo que READONLY.
			kind = ErrReadOnly
		}
	}
	return &dbError{op: op, kind: kind, raw: err}
}
