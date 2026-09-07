package jcs

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestVectors(t *testing.T) {
	vectorDirs, err := filepath.Glob(filepath.Join("..", "..", "testdata", "vectors", "jcs", "*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(vectorDirs) == 0 {
		t.Fatal("no se encontraron vectores JCS externalizados")
	}

	for _, dir := range vectorDirs {
		t.Run(filepath.Base(dir), func(t *testing.T) {
			src, err := os.ReadFile(filepath.Join(dir, "input.json"))
			if err != nil {
				t.Fatal(err)
			}
			want, err := os.ReadFile(filepath.Join(dir, "canonical.json"))
			if err != nil {
				t.Fatal(err)
			}
			want = bytes.TrimSuffix(want, []byte("\n"))

			var in any
			if err := jsonUnmarshal(src, &in); err != nil {
				t.Fatal(err)
			}
			got, err := Marshal(in)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != string(want) {
				t.Fatalf("\n got: %s\nwant: %s", got, want)
			}
		})
	}
}
