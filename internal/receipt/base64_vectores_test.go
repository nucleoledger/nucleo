package receipt

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nucleoledger/nucleo/internal/checkpoint"
)

// TestVectoresBase64ConElMotivo (Sprint 38b): los dieciséis invalido-b64-* —un \r, un \n,
// un espacio o un tabulador en mitad del base64 de un nodo, de la firma del bloque, de la
// firma del emisor o de la línea de firma del log— se rechazan, y POR EL MOTIVO que
// declara el vector, el mismo que exigen las suites de TypeScript, PHP y la página.
// TestVectoresGoldenDicenLaVerdad ya exige el rechazo; esto exige el porqué.
func TestVectoresBase64ConElMotivo(t *testing.T) {
	files, err := filepath.Glob(filepath.Join("..", "..", "testdata", "vectors", "receipt", "invalido-b64-*.json"))
	if err != nil || len(files) != 16 {
		t.Fatalf("vectores invalido-b64-*: %d, want 16 (%v)", len(files), err)
	}
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var v vectorFile
		if err := json.Unmarshal(raw, &v); err != nil {
			t.Fatal(err)
		}
		t.Run(v.Name, func(t *testing.T) {
			if v.Valid {
				t.Fatal("el vector se declara válido")
			}
			pol := policyFromVector(t, v.Policy)
			r, err := Parse([]byte(v.Receipt), pol)
			if err == nil {
				_, err = r.Verify(pol)
			}
			if err == nil {
				t.Fatal("Go lo ACEPTA")
			}
			var ok bool
			switch v.Reason {
			case "noncanonical_base64":
				ok = errors.Is(err, checkpoint.ErrBase64)
			case "note_control_character":
				ok = errors.Is(err, checkpoint.ErrFormat) && strings.Contains(err.Error(), "caracteres de control")
			case "receipt_signer_name":
				ok = errors.Is(err, ErrFormat) && strings.Contains(err.Error(), "dice ser de")
			default:
				t.Fatalf("motivo %q que este test no conoce", v.Reason)
			}
			if !ok {
				t.Errorf("motivo del vector %s, y Go dice: %v", v.Reason, err)
			}
		})
	}
}
