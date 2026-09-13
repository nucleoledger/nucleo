package policy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// TestVectoresDePolitica: los vectores de testdata/vectors/policy/, escritos a mano
// desde la tabla de PROTOCOL.md §3.2, son la vara. Los leen también las dos suites
// de TypeScript.
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
			Name  string `json:"name"`
			Text  string `json:"text"`
			Valid bool   `json:"valid"`
		}
		if err := json.Unmarshal(raw, &v); err != nil {
			t.Fatal(err)
		}
		t.Run(v.Name, func(t *testing.T) {
			_, err := Parse([]byte(v.Text))
			if v.Valid && err != nil {
				t.Errorf("debía aceptarse: %v", err)
			}
			if !v.Valid && err == nil {
				t.Errorf("debía rechazarse")
			}
		})
	}
}
