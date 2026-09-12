package receipt

import (
	"strings"
	"testing"
)

// TestDestinatarioQueImitaUnaLineaDeFirma (D.6): un nombre con la forma exacta de
// una línea de firma del emisor —"— <tenant> <base64>"— tiene que viajar como
// nombre y nada más. La segunda auditoría lo probó y pasaba; aquí queda vigilado,
// porque nada lo vigilaba: el parser de la firma es posicional y la auditoría lo
// confirmó, pero una refactorización que buscara la línea por su prefijo en vez de
// por su posición lo rompería en silencio.
func TestDestinatarioQueImitaUnaLineaDeFirma(t *testing.T) {
	sc := newScene(t, 1)
	nombre := ReceiptSigPrefix + testTenant + " AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	r, err := sc.issue(t, nombre, 2)
	if err != nil {
		t.Fatal(err)
	}
	data, err := Format(r, sc.policy())
	if err != nil {
		t.Fatal(err)
	}
	// Aparece dos veces con la forma de línea de firma: en el texto (como nombre)
	// y en la parte de máquina (como firma). El parser tiene que distinguirlas.
	if strings.Count(string(data), ReceiptSigPrefix+testTenant+" ") != 2 {
		t.Fatalf("el recibo debería tener el prefijo de firma dos veces:\n%s", data)
	}
	back, err := Parse(data, sc.policy())
	if err != nil {
		t.Fatalf("Parse rechazó un destinatario legítimo con forma de firma: %v", err)
	}
	if back.Recipient != nombre {
		t.Errorf("destinatario = %q, want %q", back.Recipient, nombre)
	}
	if _, err := back.Verify(sc.policy()); err != nil {
		t.Errorf("Verify: %v", err)
	}
}
