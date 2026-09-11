package store

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/nucleoledger/nucleo/internal/ledger"
)

// La regla de hoja solo vale si una máquina la comprueba. PROTOCOL.md §2.1 lo pide
// así por una razón concreta: sin marca legible, abrir un log de leaf/v1 con un
// binario de leaf/v2 da un error de raíz que no cuadra —cierto e inútil— y quien lo
// lea buscará corrupción donde hay un cambio de versión.

func TestLeafRuleSeRegistraEnUnLogNuevo(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nucleo.db")
	s, _, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.LeafRule()
	if err != nil {
		t.Fatal(err)
	}
	if got != ledger.LeafRule {
		t.Errorf("regla registrada = %q, want %q", got, ledger.LeafRule)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	// Y se conserva al reabrir.
	s2, _, err := Open(path)
	if err != nil {
		t.Fatalf("reabrir un log de la regla vigente falló: %v", err)
	}
	defer s2.Close()
}

func TestLeafRuleRechazaOtraRegla(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nucleo.db")
	s, _, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, b := range chain(t, 3, 0) {
		if err := s.AppendBlock(b); err != nil {
			t.Fatal(err)
		}
	}
	// Alguien cambia la marca a una regla que este binario no implementa.
	if err := s.PutMeta(MetaLeafRuleKey, []byte("leaf/v9")); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	_, _, err = Open(path)
	if !errors.Is(err, ErrLeafRule) {
		t.Fatalf("err = %v, want ErrLeafRule", err)
	}
	// El mensaje tiene que nombrar las dos reglas y la ruta de salida, o no sirve
	// de nada: quien lo lea necesita saber qué tiene y qué hacer.
	for _, quiero := range []string{"leaf/v9", ledger.LeafRule, "segmento"} {
		if !contiene(err.Error(), quiero) {
			t.Errorf("el mensaje no menciona %q: %v", quiero, err)
		}
	}
}

// TestLeafRuleRechazaUnLogSinMarcaConBloques: un log con historia y sin marca es de
// leaf/v1 por definición, porque la marca se escribe desde que existe.
func TestLeafRuleRechazaUnLogSinMarcaConBloques(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nucleo.db")
	s, _, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, b := range chain(t, 2, 0) {
		if err := s.AppendBlock(b); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	// Se borra la marca para simular un log creado antes de que existiera.
	db := rawDB(t, path)
	if _, err := db.Exec(`DELETE FROM vault_meta WHERE k = ?`, MetaLeafRuleKey); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	_, _, err = Open(path)
	if !errors.Is(err, ErrLeafRule) {
		t.Fatalf("err = %v, want ErrLeafRule", err)
	}
	if !contiene(err.Error(), ledger.LeafRuleV1) {
		t.Errorf("el mensaje debería decir que el log es de %s: %v", ledger.LeafRuleV1, err)
	}
}

// TestLeafRuleUnLogVacioSinMarcaSeAdopta: sin bloques no hay nada construido bajo
// ninguna regla, así que se marca y se sigue. Rechazarlo obligaría a borrar bases
// recién creadas por una marca que nadie había escrito todavía.
func TestLeafRuleUnLogVacioSinMarcaSeAdopta(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nucleo.db")
	s, _, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	db := rawDB(t, path)
	if _, err := db.Exec(`DELETE FROM vault_meta WHERE k = ?`, MetaLeafRuleKey); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	s2, _, err := Open(path)
	if err != nil {
		t.Fatalf("un log vacío sin marca debería adoptarla: %v", err)
	}
	defer s2.Close()
	if got, _ := s2.LeafRule(); got != ledger.LeafRule {
		t.Errorf("regla = %q, want %q", got, ledger.LeafRule)
	}
}

func contiene(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
