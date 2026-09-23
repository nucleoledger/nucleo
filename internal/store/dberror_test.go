package store

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// errorFalsoDelDriver imita al error del driver: lo único que se le mira es el código.
type errorFalsoDelDriver struct {
	code int
}

func (e *errorFalsoDelDriver) Error() string { return fmt.Sprintf("fake sqlite error %d", e.code) }
func (e *errorFalsoDelDriver) Code() int     { return e.code }

// TestErrDBClasificaPorCodigo es la tabla de clasificación, comprobada código a código.
//
// Sale del ensayo de operación del Sprint 10: con una sola clase genérica, un ledger sin
// permisos, un disco lleno, otro proceso escribiendo y un fichero que no era una base
// daban todos "error interno de la base de datos", y el operador no tenía por dónde
// empezar. No decir jerga del motor no es lo mismo que no decir nada.
func TestErrDBClasificaPorCodigo(t *testing.T) {
	casos := []struct {
		code  int
		clase error
		dice  string // algo que el mensaje TIENE que decirle al operador
	}{
		{8, ErrReadOnly, "permisos"},
		{8 | (1 << 8), ErrReadOnly, "nucleo.db-shm"}, // SQLITE_READONLY_RECOVERY, extendido
		{14, ErrReadOnly, "permisos"},                // SQLITE_CANTOPEN
		{5, ErrBusy, "reintenta"},
		{6, ErrBusy, "reintenta"},
		{13, ErrDiskFull, "espacio"},
		{10, ErrIO, "entrada/salida"},
		{10 | (3 << 8), ErrIO, "entrada/salida"}, // SQLITE_IOERR_WRITE
		{11, ErrNotALedger, "dañado"},
		{26, ErrNotALedger, "no es un ledger"},
		{19, ErrConstraint, "rechazó"},
		{1555, ErrDuplicateBlob, "payload_hash"},
		{2067, ErrDuplicateBlob, "payload_hash"},
		{1, ErrInternalDB, "interno"}, // SQLITE_ERROR: lo que no se puede clasificar
	}
	for _, c := range casos {
		err := errDB("store: prueba", ErrDuplicateBlob, &errorFalsoDelDriver{code: c.code})
		if !errors.Is(err, c.clase) {
			t.Errorf("código %d → %v, want %v", c.code, err, c.clase)
			continue
		}
		if !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(c.dice)) {
			t.Errorf("código %d: el mensaje no dice %q: %v", c.code, c.dice, err)
		}
		if jergaDelMotor.MatchString(err.Error()) {
			t.Errorf("código %d: el mensaje lleva jerga del motor: %v", c.code, err)
		}
		// El error del driver no se pierde nunca: quien depura lo alcanza.
		var conCodigo interface{ Code() int }
		if !errors.As(err, &conCodigo) || conCodigo.Code() != c.code {
			t.Errorf("código %d: el error del driver no viaja envuelto", c.code)
		}
	}
	if errDB("store: prueba", nil, nil) != nil {
		t.Error("errDB(nil) tiene que ser nil")
	}
}

// TestLedgerSinPermisoDeEscrituraLoDice es el hallazgo del ensayo de operación que dejó
// un despliegue inservible: SQLite crea `-wal` y `-shm` junto a la base y hereda sus
// permisos, así que un `chmod` sobre la base deja el `-shm` en solo lectura AUNQUE se
// arregle la base después. El síntoma era "error interno de la base de datos" y la cura,
// `chmod 644 nucleo.db-shm`, no estaba en ninguna parte.
func TestLedgerSinPermisoDeEscrituraLoDice(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("los permisos POSIX no gobiernan el acceso en Windows: lo hace la ACL, que no se ve desde aquí")
	}
	if os.Geteuid() == 0 {
		t.Skip("como root los permisos no impiden escribir")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "nucleo.db")
	s, _, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	g := bloqueDe(t, nil, []byte("uno"), 0)
	if err := s.AppendRecord(Record{Block: g}); err != nil {
		t.Fatal(err)
	}
	s.Close()

	// El fichero en solo lectura, que es el caso que se puede provocar igual en
	// cualquier sistema POSIX. El del ensayo de operación fue su primo: la base a 644 y
	// el -shm a 444 —SQLite los crea junto a ella y heredan sus permisos—, y el
	// despliegue quedó inservible sin que nada señalara al fichero culpable. Lo que esta
	// prueba fija es que el mensaje los NOMBRA, que es lo que faltaba.
	if err := os.Chmod(path, 0o444); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(path, 0o644) })

	s2, _, err := Open(path)
	if err == nil {
		defer s2.Close()
		segundo := bloqueDe(t, g, []byte("dos"), 0)
		err = s2.AppendRecord(Record{Block: segundo})
	}
	if err == nil {
		t.Skip("este sistema de ficheros permitió escribir en un fichero 444; no hay nada que comprobar")
	}
	if !errors.Is(err, ErrReadOnly) {
		t.Fatalf("err = %v, want ErrReadOnly", err)
	}
	// Y el mensaje tiene que nombrar los tres ficheros: el -shm y el -wal son los que
	// nadie adivina, y son los que dejaron el despliegue del ensayo sin sellar.
	for _, quiere := range []string{"nucleo.db", "nucleo.db-wal", "nucleo.db-shm", "permisos"} {
		if !strings.Contains(err.Error(), quiere) {
			t.Errorf("el mensaje no menciona %q, que es justo lo que hay que arreglar: %v", quiere, err)
		}
	}
}

// TestFicheroQueNoEsUnLedgerLoDice: restaurar medio respaldo, o apuntar --dir a otra
// cosa, es un error de operación frecuente y merece su mensaje.
func TestFicheroQueNoEsUnLedgerLoDice(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nucleo.db")
	if err := os.WriteFile(path, []byte("esto no es una base de datos, es un fichero de texto"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, _, err := Open(path)
	if err == nil {
		t.Fatal("un fichero que no es una base no debería abrir")
	}
	if !errors.Is(err, ErrNotALedger) {
		t.Fatalf("err = %v, want ErrNotALedger", err)
	}
	if jergaDelMotor.MatchString(err.Error()) {
		t.Errorf("el mensaje lleva jerga del motor: %v", err)
	}
}
