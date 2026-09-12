package ledger

import (
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"
	"time"
)

// C.6 del Sprint 7c. La auditoría adversarial selló con --tenant $'ACME\nS.A.' y
// todo fue bien hasta que alguien intentó verificar el recibo: el tenant viaja en
// una línea, y con un salto dentro la línea de la firma del emisor se parte en
// dos y ningún verificador la lee. El emisor lo descubre cuando se queja la
// contraparte, quizá años después. Se rechaza al sellar.
func TestTenantTieneQueCaberEnUnaLinea(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 12, 10, 0, 0, 0, time.UTC)

	for _, c := range []struct {
		nombre, tenant string
		valido         bool
	}{
		{"RUC normal", "1790012345001", true},
		{"nombre con espacios", "ACME S.A.", true},
		{"acentos y ñ", "Compañía Ñandú", true},
		{"el caso de la auditoría", "ACME\nS.A.", false},
		{"retorno de carro", "ACME\rS.A.", false},
		{"CRLF", "ACME\r\nS.A.", false},
		{"tabulador", "ACME\tS.A.", false},
		{"carácter de control", "ACME\x00S.A.", false},
		{"solo espacios", "   ", false},
	} {
		t.Run(c.nombre, func(t *testing.T) {
			_, err := NewHeader(nil, c.tenant, "t.v1", []byte("x"), "blob://x", pub, now)
			if err == nil && !c.valido {
				t.Fatalf("NewHeader aceptó el tenant %q", c.tenant)
			}
			if err != nil && c.valido {
				t.Fatalf("NewHeader rechazó un tenant válido %q: %v", c.tenant, err)
			}
			if !c.valido {
				if !errors.Is(err, ErrInvalidHeader) {
					t.Errorf("err = %v, want ErrInvalidHeader", err)
				}
				if strings.Contains(c.tenant, "\n") && !strings.Contains(err.Error(), "una línea") {
					t.Errorf("el mensaje no explica que tiene que caber en una línea: %v", err)
				}
			}
			_ = priv
		})
	}
}
