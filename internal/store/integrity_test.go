package store

import (
	"database/sql"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nucleoledger/nucleo/internal/checkpoint"
	"github.com/nucleoledger/nucleo/internal/ledger"
)

// rawDB abre la base saltándose el paquete, como haría quien tiene el fichero y
// un cliente de SQLite. Es el modelo de atacante correcto: los disparadores son
// una barandilla, no una frontera.
func rawDB(t *testing.T, path string) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// dropTriggers borra los disparadores de append-only, primer paso de cualquier
// manipulación seria del fichero.
func dropTriggers(t *testing.T, db *sql.DB) {
	t.Helper()
	for _, name := range []string{
		"blocks_no_update", "blocks_no_delete",
		"checkpoints_no_update", "checkpoints_no_delete", "blobs_no_update",
	} {
		if _, err := db.Exec("DROP TRIGGER IF EXISTS " + name); err != nil {
			t.Fatal(err)
		}
	}
}

// seedLedger crea una base con n bloques y, si withCheckpoint, un checkpoint
// firmado sobre la raíz real. Devuelve la ruta.
func seedLedger(t *testing.T, n int, withCheckpoint bool) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "nucleo.db")
	s, _, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, b := range chain(t, n, 0) {
		if err := s.AppendBlock(b); err != nil {
			t.Fatal(err)
		}
	}
	if withCheckpoint {
		root, err := s.Root()
		if err != nil {
			t.Fatal(err)
		}
		_, priv := testKeys(t, 7)
		signer, err := checkpoint.NewSigner("nucleoledger.com/poc", priv)
		if err != nil {
			t.Fatal(err)
		}
		note, err := checkpoint.Sign(checkpoint.Checkpoint{
			Origin: "nucleoledger.com/poc", Size: uint64(n), RootHash: root,
		}, signer)
		if err != nil {
			t.Fatal(err)
		}
		if err := s.PutCheckpoint(note); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestOpenAcceptsHealthyLedger es el control negativo: sin este test, los demás
// pasarían aunque Open rechazara siempre.
func TestOpenAcceptsHealthyLedger(t *testing.T) {
	path := seedLedger(t, 5, true)
	s, _, err := Open(path)
	if err != nil {
		t.Fatalf("Open rechaza una base sana: %v", err)
	}
	defer s.Close()
	if _, err := s.VerifyIntegrity(); err != nil {
		t.Errorf("VerifyIntegrity sobre base sana: %v", err)
	}
	n, _ := s.Count()
	if n != 5 {
		t.Errorf("Count = %d, want 5", n)
	}
}

// TestOpenDetectsTampering es el test central del bloque: se borran los
// disparadores y se manipula la base por SQL directo. Open debe negarse y decir
// qué bloque está roto.
func TestOpenDetectsTampering(t *testing.T) {
	cases := []struct {
		name      string
		withCP    bool
		tamper    func(t *testing.T, db *sql.DB)
		wantStage string
		wantIndex int64
	}{
		{
			name: "header alterado",
			tamper: func(t *testing.T, db *sql.DB) {
				if _, err := db.Exec(
					`UPDATE blocks SET header_json = replace(header_json, '"tenant":"1790012345001"', '"tenant":"9999999999001"') WHERE idx = 2`); err != nil {
					t.Fatal(err)
				}
			},
			wantStage: "bloque", wantIndex: 2,
		},
		{
			name: "hash reescrito",
			tamper: func(t *testing.T, db *sql.DB) {
				if _, err := db.Exec(`UPDATE blocks SET hash = ? WHERE idx = 3`, strings.Repeat("ab", 32)); err != nil {
					t.Fatal(err)
				}
			},
			wantStage: "bloque", wantIndex: 3,
		},
		{
			name: "firma sustituida",
			tamper: func(t *testing.T, db *sql.DB) {
				if _, err := db.Exec(`UPDATE blocks SET signature = ? WHERE idx = 1`, strings.Repeat("00", 64)); err != nil {
					t.Fatal(err)
				}
			},
			wantStage: "bloque", wantIndex: 1,
		},
		{
			name: "bloque intermedio borrado",
			tamper: func(t *testing.T, db *sql.DB) {
				if _, err := db.Exec(`DELETE FROM blocks WHERE idx = 2`); err != nil {
					t.Fatal(err)
				}
			},
			wantStage: "secuencia", wantIndex: 2,
		},
		{
			name:   "historia truncada bajo un checkpoint",
			withCP: true,
			tamper: func(t *testing.T, db *sql.DB) {
				if _, err := db.Exec(`DELETE FROM blocks WHERE idx = 4`); err != nil {
					t.Fatal(err)
				}
			},
			wantStage: "checkpoint", wantIndex: -1,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			path := seedLedger(t, 5, c.withCP)
			db := rawDB(t, path)
			dropTriggers(t, db)
			c.tamper(t, db)
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}

			s, _, err := Open(path)
			if err == nil {
				s.Close()
				t.Fatal("Open aceptó una base manipulada")
			}
			if !errors.Is(err, ErrIntegrity) {
				t.Fatalf("err = %v, want que envuelva a ErrIntegrity", err)
			}
			var ie *IntegrityError
			if !errors.As(err, &ie) {
				t.Fatalf("el error no es *IntegrityError: %T", err)
			}
			if ie.Stage != c.wantStage {
				t.Errorf("Stage = %q, want %q", ie.Stage, c.wantStage)
			}
			if ie.Index != c.wantIndex {
				t.Errorf("Index = %d, want %d", ie.Index, c.wantIndex)
			}
		})
	}
}

// TestOpenDetectsCheckpointMismatch cubre el caso en que la historia está intacta
// pero el checkpoint promete otra raíz.
func TestOpenDetectsCheckpointMismatch(t *testing.T) {
	path := seedLedger(t, 5, false)

	// Un checkpoint firmado sobre una raíz que no es la de esta base.
	s, _, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	_, priv := testKeys(t, 7)
	signer, err := checkpoint.NewSigner("nucleoledger.com/poc", priv)
	if err != nil {
		t.Fatal(err)
	}
	fake := make([]byte, 32)
	for i := range fake {
		fake[i] = byte(i)
	}
	note, err := checkpoint.Sign(checkpoint.Checkpoint{
		Origin: "nucleoledger.com/poc", Size: 5, RootHash: fake,
	}, signer)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.PutCheckpoint(note); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, _, err := Open(path)
	if err == nil {
		reopened.Close()
		t.Fatal("Open aceptó una base cuya raíz no coincide con su checkpoint")
	}
	var ie *IntegrityError
	if !errors.As(err, &ie) || ie.Stage != "checkpoint" {
		t.Fatalf("err = %v, want IntegrityError en fase checkpoint", err)
	}
	if !strings.Contains(err.Error(), "raíz reconstruida") {
		t.Errorf("el error no explica la discrepancia de raíces: %v", err)
	}
}

// TestRootMatchesLedger comprueba que la raíz reconstruida desde la base es la
// misma que se obtiene calculándola sobre los bloques en memoria.
func TestRootMatchesLedger(t *testing.T) {
	s := openTemp(t)
	blocks := chain(t, 9, 0)
	leaves := make([][]byte, 0, len(blocks))
	for _, b := range blocks {
		if err := s.AppendBlock(b); err != nil {
			t.Fatal(err)
		}
		hb, err := b.LeafData()
		if err != nil {
			t.Fatal(err)
		}
		leaves = append(leaves, hb)
	}
	got, err := s.Root()
	if err != nil {
		t.Fatal(err)
	}
	want := ledger.Root(leaves)
	if string(got) != string(want) {
		t.Errorf("Root desde la base = %x, en memoria = %x", got, want)
	}
}
