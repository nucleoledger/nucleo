package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestLaCLINoRecibeLaDEK: la CLI solo necesita saber si unas tarjetas son de este vault,
// y para eso está vault.CheckKEK, que borra la DEK antes de volver. Llamar a UnwrapDEK
// desde aquí dejaría la DEK en memoria de la CLI hasta que pasara el recolector (BAJA de
// la revisión del 2026-10-03). Este test es estructural: falla si alguien vuelve a
// llamarla.
func TestLaCLINoRecibeLaDEK(t *testing.T) {
	fuentes, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range fuentes {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(raw), "vault.UnwrapDEK(") {
			t.Errorf("%s llama a vault.UnwrapDEK: usa vault.CheckKEK, que no devuelve la DEK", f)
		}
	}
}
