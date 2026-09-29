package store

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestReplaceMetaSustituyeJuntas: las filas cambian juntas cuando las esperadas siguen
// como se leyeron.
func TestReplaceMetaSustituyeJuntas(t *testing.T) {
	s := openTemp(t)
	mustPutMeta(t, s, "a", "a-viejo")
	mustPutMeta(t, s, "b", "b-viejo")

	err := s.ReplaceMeta(
		map[string][]byte{"a": []byte("a-viejo"), "b": []byte("b-viejo")},
		map[string][]byte{"a": []byte("a-nuevo"), "b": []byte("b-nuevo")},
	)
	if err != nil {
		t.Fatal(err)
	}
	wantMeta(t, s, "a", "a-nuevo")
	wantMeta(t, s, "b", "b-nuevo")
}

// TestReplaceMetaNoPisaUnCambioAjeno: si una fila esperada ya no es la que se leyó —otro
// proceso la cambió—, no se escribe NINGUNA, tampoco las que sí coincidían.
func TestReplaceMetaNoPisaUnCambioAjeno(t *testing.T) {
	s := openTemp(t)
	mustPutMeta(t, s, "a", "a-viejo")
	mustPutMeta(t, s, "b", "b-cambiado-por-otro")

	err := s.ReplaceMeta(
		map[string][]byte{"a": []byte("a-viejo"), "b": []byte("b-viejo")},
		map[string][]byte{"a": []byte("a-nuevo"), "b": []byte("b-nuevo")},
	)
	if !errors.Is(err, ErrMetaChanged) {
		t.Fatalf("ReplaceMeta = %v; want ErrMetaChanged", err)
	}
	wantMeta(t, s, "a", "a-viejo")
	wantMeta(t, s, "b", "b-cambiado-por-otro")

	// Una fila esperada que no existe también es un cambio.
	err = s.ReplaceMeta(map[string][]byte{"c": []byte("x")}, map[string][]byte{"a": []byte("otro")})
	if !errors.Is(err, ErrMetaChanged) {
		t.Fatalf("ReplaceMeta con esperada ausente = %v; want ErrMetaChanged", err)
	}
	wantMeta(t, s, "a", "a-viejo")
}

// envSubprocesoMeta y envMuereTras gobiernan el subproceso de
// TestReplaceMetaMuertoAMediasNoDejaNada.
const (
	envSubprocesoMeta = "NUCLEO_STORE_TEST_SUBPROCESO_DB"
	envMuereTras      = "NUCLEO_STORE_TEST_MUERE_TRAS"
)

// TestReplaceMetaMuertoAMediasNoDejaNada mata el proceso DENTRO de la transacción —con
// os.Exit, sin que corra ningún defer ni el Rollback— después de la primera escritura y
// después de la segunda, y comprueba al reabrir que no quedó nada a medias: SQLite
// deshace lo que no llegó al COMMIT (ADR-029 §C).
func TestReplaceMetaMuertoAMediasNoDejaNada(t *testing.T) {
	if db := os.Getenv(envSubprocesoMeta); db != "" {
		subprocesoReplaceMeta(db, os.Getenv(envMuereTras))
		return
	}
	for _, tras := range []string{"a", "b"} {
		t.Run("muere tras escribir "+tras, func(t *testing.T) {
			db := filepath.Join(t.TempDir(), "nucleo.db")
			s, _, err := Open(db)
			if err != nil {
				t.Fatal(err)
			}
			mustPutMeta(t, s, "a", "a-viejo")
			mustPutMeta(t, s, "b", "b-viejo")
			s.Close()

			cmd := exec.Command(os.Args[0], "-test.run=^TestReplaceMetaMuertoAMediasNoDejaNada$")
			cmd.Env = append(os.Environ(), envSubprocesoMeta+"="+db, envMuereTras+"="+tras)
			out, err := cmd.CombinedOutput()
			var ee *exec.ExitError
			if !errors.As(err, &ee) || ee.ExitCode() != 97 {
				t.Fatalf("el subproceso tenía que morir con 97 y salió con %v:\n%s", err, out)
			}

			s, _, err = Open(db)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			wantMeta(t, s, "a", "a-viejo")
			wantMeta(t, s, "b", "b-viejo")
		})
	}
}

// subprocesoReplaceMeta es el proceso que muere: abre la base, arma el gancho y llama a
// ReplaceMeta. Si llegara a volver, sale con 0 y el test lo denuncia.
func subprocesoReplaceMeta(db, tras string) {
	s, _, err := Open(db)
	if err != nil {
		os.Exit(3)
	}
	hookMetaTx = func(clave string) {
		if clave == tras {
			os.Exit(97)
		}
	}
	_ = s.ReplaceMeta(
		map[string][]byte{"a": []byte("a-viejo"), "b": []byte("b-viejo")},
		map[string][]byte{"a": []byte("a-nuevo"), "b": []byte("b-nuevo")},
	)
	os.Exit(0)
}

func mustPutMeta(t *testing.T, s *Store, k, v string) {
	t.Helper()
	if err := s.PutMeta(k, []byte(v)); err != nil {
		t.Fatal(err)
	}
}

func wantMeta(t *testing.T, s *Store, k, want string) {
	t.Helper()
	got, err := s.GetMeta(k)
	if err != nil {
		t.Fatalf("GetMeta(%q): %v", k, err)
	}
	if string(got) != want {
		t.Errorf("vault_meta[%q] = %q; want %q", k, got, want)
	}
}
