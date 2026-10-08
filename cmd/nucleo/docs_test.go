package main

import (
	"os"
	"strings"
	"testing"
)

// TestElTutorialDiceLoQueRestoreNoHace: el apartado del tutorial sobre restore
// --new-passphrase tiene que decir, junto a la orden, las dos cosas que el comando no
// hace (revisión del 2026-10-03 y enmienda de ADR-029): una copia del ledger de antes
// del cambio se sigue abriendo con las tarjetas viejas, y una passphrase ROBADA no se
// arregla cambiándola. Si alguien recorta el apartado, este test lo dice.
func TestElTutorialDiceLoQueRestoreNoHace(t *testing.T) {
	raw, err := os.ReadFile("../../docs/TUTORIAL-es.md")
	if err != nil {
		t.Fatal(err)
	}
	tut := string(raw)
	i := strings.Index(tut, "restore --new-passphrase")
	if i < 0 {
		t.Fatal("el tutorial ya no explica restore --new-passphrase")
	}
	apartado := tut[i:]
	if fin := strings.Index(apartado, "\n---\n"); fin >= 0 {
		apartado = apartado[:fin]
	}
	for _, q := range []string{
		"copia del ledger hecha antes del cambio",
		"se sigue abriendo con las tarjetas viejas",
		"**robaron**",
		"un log nuevo",
	} {
		if !strings.Contains(apartado, q) {
			t.Errorf("el apartado de restore del tutorial ya no dice %q", q)
		}
	}
}
