package policy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestVectoresDePolitica: los vectores de testdata/vectors/policy/, escritos a mano
// desde la tabla de PROTOCOL.md §3.2, son la vara. Los leen también las dos suites
// de TypeScript.
//
// Los vectores con "requires": "0.8-draft" (ADR-033, ADR-034) son de una gramática que
// este lector todavía no implementa: hasta el Sprint C, los válidos se tienen que
// RECHAZAR como miembro desconocido, que es lo que PROTOCOL §3.2 manda a un lector
// 0.7-draft. Los inválidos se rechazan igual en las dos versiones.
func TestVectoresDePolitica(t *testing.T) {
	files, err := filepath.Glob(filepath.Join("..", "..", "testdata", "vectors", "policy", "*.json"))
	if err != nil || len(files) < 50 {
		t.Fatalf("vectores de política: %d, %v", len(files), err)
	}
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var v struct {
			Name     string `json:"name"`
			Text     string `json:"text"`
			Valid    bool   `json:"valid"`
			Requires string `json:"requires"`
		}
		if err := json.Unmarshal(raw, &v); err != nil {
			t.Fatal(err)
		}
		t.Run(v.Name, func(t *testing.T) {
			_, err := Parse([]byte(v.Text))
			switch v.Requires {
			case "":
			case "0.8-draft":
				// Exigen 0.8: hasta el Sprint C, un válido es un miembro desconocido.
				if v.Valid && (err == nil || !strings.Contains(err.Error(), "miembro desconocido")) {
					t.Errorf("exige 0.8-draft: este lector debía rechazarla como miembro desconocido, y dice %v", err)
				}
				if !v.Valid && err == nil {
					t.Errorf("debía rechazarse")
				}
				return
			default:
				t.Fatalf("requires %q: versión que este test no conoce", v.Requires)
			}
			if v.Valid && err != nil {
				t.Errorf("debía aceptarse: %v", err)
			}
			if !v.Valid && err == nil {
				t.Errorf("debía rechazarse")
			}
		})
	}
}
