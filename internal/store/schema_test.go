package store

import (
	"path/filepath"
	"strings"
	"testing"
)

// openTemp abre un Store nuevo en un directorio temporal del test.
func openTemp(t *testing.T) *Store {
	t.Helper()
	s, _, err := Open(filepath.Join(t.TempDir(), "nucleo.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// TestPragmas comprueba que los PRAGMA de PROTOCOL.md §8 quedan realmente
// aplicados, no solo enviados. synchronous y foreign_keys son por conexión, así
// que se leen de vuelta desde la propia base.
func TestPragmas(t *testing.T) {
	s := openTemp(t)
	cases := []struct{ pragma, want string }{
		{"journal_mode", "wal"},
		{"synchronous", "2"}, // 2 = FULL
		{"foreign_keys", "1"},
	}
	for _, c := range cases {
		got, err := s.Pragma(c.pragma)
		if err != nil {
			t.Fatalf("PRAGMA %s: %v", c.pragma, err)
		}
		if !strings.EqualFold(got, c.want) {
			t.Errorf("PRAGMA %s = %q, want %q", c.pragma, got, c.want)
		}
	}
}

// TestSchemaTablesAndIdempotence comprueba que el esquema se crea y que volver a
// abrir la misma base no falla ni duplica nada.
func TestSchemaTablesAndIdempotence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nucleo.db")
	s, _, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"blocks", "blobs", "checkpoints", "vault_meta"} {
		var name string
		err := s.db.QueryRow(`SELECT name FROM sqlite_master WHERE type='table' AND name=?`, table).Scan(&name)
		if err != nil {
			t.Errorf("falta la tabla %s: %v", table, err)
		}
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	// Reabrir debe ser inocuo.
	s2, _, err := Open(path)
	if err != nil {
		t.Fatalf("reabrir falla: %v", err)
	}
	defer s2.Close()
	var n int
	if err := s2.db.QueryRow(`SELECT count(*) FROM sqlite_master WHERE type='trigger'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 5 {
		t.Errorf("disparadores = %d, want 5", n)
	}
}

// seedRows mete una fila en cada tabla saltándose la API, para poder atacar los
// disparadores directamente por SQL.
func seedRows(t *testing.T, s *Store) {
	t.Helper()
	h := strings.Repeat("ab", 32)
	if _, err := s.db.Exec(`INSERT INTO blocks (idx, hash, header_json, signature) VALUES (0, ?, '{}', 'ff')`, h); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`INSERT INTO checkpoints (tree_size, note) VALUES (1, 'nota')`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`INSERT INTO blobs (payload_hash, ciphertext, nonce, created_at) VALUES (?, x'00', x'01', '2026-09-05T00:00:00Z')`, h); err != nil {
		t.Fatal(err)
	}
}

// TestAppendOnlyTriggers ataca el ledger por SQL directo, como haría quien tiene
// el fichero. Los disparadores deben abortar.
func TestAppendOnlyTriggers(t *testing.T) {
	s := openTemp(t)
	seedRows(t, s)
	h := strings.Repeat("ab", 32)

	forbidden := []struct {
		name string
		sql  string
		args []any
	}{
		{"UPDATE de blocks", `UPDATE blocks SET header_json = '{"x":1}' WHERE idx = 0`, nil},
		{"UPDATE del hash de blocks", `UPDATE blocks SET hash = ? WHERE idx = 0`, []any{strings.Repeat("cd", 32)}},
		{"DELETE de blocks", `DELETE FROM blocks WHERE idx = 0`, nil},
		{"DELETE masivo de blocks", `DELETE FROM blocks`, nil},
		{"UPDATE de checkpoints", `UPDATE checkpoints SET note = 'otra' WHERE tree_size = 1`, nil},
		{"DELETE de checkpoints", `DELETE FROM checkpoints WHERE tree_size = 1`, nil},
		{"UPDATE de blobs", `UPDATE blobs SET ciphertext = x'ff' WHERE payload_hash = ?`, []any{h}},
	}
	for _, c := range forbidden {
		_, err := s.db.Exec(c.sql, c.args...)
		if err == nil {
			t.Errorf("%s: la base lo permitió", c.name)
			continue
		}
		if !strings.Contains(err.Error(), "nucleo: ledger append-only") {
			t.Errorf("%s: err = %v, se esperaba el abort del disparador", c.name, err)
		}
	}

	// La fila del bloque sigue intacta tras los intentos.
	var got string
	if err := s.db.QueryRow(`SELECT header_json FROM blocks WHERE idx = 0`).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != "{}" {
		t.Errorf("el header cambió pese al disparador: %q", got)
	}
}

// TestBlobDeleteAllowed comprueba lo contrario: borrar un blob SÍ se permite,
// porque es el borrado de datos personales que exige la LOPDP.
func TestBlobDeleteAllowed(t *testing.T) {
	s := openTemp(t)
	seedRows(t, s)
	h := strings.Repeat("ab", 32)

	res, err := s.db.Exec(`DELETE FROM blobs WHERE payload_hash = ?`, h)
	if err != nil {
		t.Fatalf("el borrado de un blob debe permitirse: %v", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("filas borradas = %d, want 1", n)
	}
	// Y el compromiso en el ledger sobrevive al borrado del dato.
	var idx int
	if err := s.db.QueryRow(`SELECT idx FROM blocks WHERE idx = 0`).Scan(&idx); err != nil {
		t.Errorf("el borrado del blob afectó al ledger: %v", err)
	}
}

// TestSchemaConstraints comprueba los CHECK de longitud y las claves únicas.
func TestSchemaConstraints(t *testing.T) {
	s := openTemp(t)
	h := strings.Repeat("ab", 32)

	cases := []struct {
		name string
		sql  string
		args []any
	}{
		{"hash corto en blocks", `INSERT INTO blocks (idx, hash, header_json, signature) VALUES (1, 'abc', '{}', 'ff')`, nil},
		{"payload_hash corto en blobs", `INSERT INTO blobs (payload_hash, ciphertext, nonce, created_at) VALUES ('abc', x'00', x'01', 'now')`, nil},
	}
	for _, c := range cases {
		if _, err := s.db.Exec(c.sql, c.args...); err == nil {
			t.Errorf("%s: la base lo aceptó", c.name)
		}
	}

	// hash UNIQUE: dos bloques distintos no pueden compartir hash.
	if _, err := s.db.Exec(`INSERT INTO blocks (idx, hash, header_json, signature) VALUES (0, ?, '{}', 'ff')`, h); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`INSERT INTO blocks (idx, hash, header_json, signature) VALUES (1, ?, '{}', 'ff')`, h); err == nil {
		t.Error("aceptó dos bloques con el mismo hash")
	}
}
