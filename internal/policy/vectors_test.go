package policy

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// TestVectoresDePolitica: los vectores de testdata/vectors/policy/, escritos a mano
// desde la tabla de PROTOCOL.md §3.2, son la vara. Los leen también las suites de
// TypeScript y de PHP.
//
// En Go se comprueba el veredicto Y el motivo: el "reason" del vector es el que da
// Motivo(err). Los vectores con "requires": "0.8-draft" (ADR-033, ADR-034) pasan por la
// misma comprobación desde el Sprint C1, porque este lector ya implementa esa gramática;
// en TypeScript y en PHP siguen rechazándose como miembro desconocido hasta el Sprint D.
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
			Reason   string `json:"reason"`
			Requires string `json:"requires"`
		}
		if err := json.Unmarshal(raw, &v); err != nil {
			t.Fatal(err)
		}
		t.Run(v.Name, func(t *testing.T) {
			switch v.Requires {
			case "", "0.8-draft":
			default:
				t.Fatalf("requires %q: versión que este test no conoce", v.Requires)
			}
			_, err := Parse([]byte(v.Text))
			if v.Valid {
				if err != nil {
					t.Errorf("debía aceptarse: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("debía rechazarse (%s)", v.Reason)
			}
			if !errors.Is(err, ErrPolicy) {
				t.Errorf("el rechazo no envuelve ErrPolicy: %v", err)
			}
			if got := Motivo(err); got != v.Reason {
				t.Errorf("motivo %q, y el vector dice %q: %v", got, v.Reason, err)
			}
		})
	}
}
