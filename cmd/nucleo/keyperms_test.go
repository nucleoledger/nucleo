//go:build testhooks && !windows

package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestWitnessKeyHardening es el hallazgo LOW de la auditoría pre-pública.
//
// La clave del testigo es una clave privada en un fichero, y se trataba como un
// fichero cualquiera: se leía, y si no estaba, se escribía. Entre esas dos
// operaciones cabe otro proceso.
func TestWitnessKeyHardening(t *testing.T) {
	dir := t.TempDir()

	t.Run("se crea con permisos 0600", func(t *testing.T) {
		path := filepath.Join(dir, "nueva.key")
		_, creada, err := witnessKey(path)
		if err != nil {
			t.Fatal(err)
		}
		if !creada {
			t.Error("no se marcó como creada")
		}
		st, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if perm := st.Mode().Perm(); perm != 0o600 {
			t.Errorf("permisos = %04o, want 0600", perm)
		}
	})

	t.Run("la segunda llamada devuelve la MISMA clave", func(t *testing.T) {
		path := filepath.Join(dir, "estable.key")
		a, creada, err := witnessKey(path)
		if err != nil || !creada {
			t.Fatalf("primera: %v %v", creada, err)
		}
		b, creada2, err := witnessKey(path)
		if err != nil {
			t.Fatal(err)
		}
		if creada2 {
			t.Error("la segunda llamada dijo que la creaba")
		}
		if !a.Equal(b) {
			t.Fatal("la clave cambió entre llamadas: las cosignatures anteriores dejarían de verificar")
		}
	})

	t.Run("rehúsa una clave legible por otros", func(t *testing.T) {
		path := filepath.Join(dir, "abierta.key")
		seed := make([]byte, ed25519.SeedSize)
		if err := os.WriteFile(path, []byte(hex.EncodeToString(seed)), 0o644); err != nil {
			t.Fatal(err)
		}
		_, _, err := witnessKey(path)
		if err == nil {
			t.Fatal("se aceptó una clave privada legible por cualquiera")
		}
		for _, quiero := range []string{"0644", "otros usuarios", "chmod 600"} {
			if !strings.Contains(err.Error(), quiero) {
				t.Errorf("el mensaje no contiene %q: %v", quiero, err)
			}
		}
	})

	t.Run("acepta 0600 y también 0400", func(t *testing.T) {
		for _, modo := range []os.FileMode{0o600, 0o400} {
			path := filepath.Join(dir, "modo.key")
			os.Remove(path)
			seed := make([]byte, ed25519.SeedSize)
			if err := os.WriteFile(path, []byte(hex.EncodeToString(seed)), modo); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(path, modo); err != nil {
				t.Fatal(err)
			}
			if _, _, err := witnessKey(path); err != nil {
				t.Errorf("permisos %04o rechazados: %v", modo, err)
			}
		}
	})

	t.Run("rechaza contenido que no es una clave", func(t *testing.T) {
		for _, contenido := range []string{"", "no es hex", hex.EncodeToString(make([]byte, 16))} {
			path := filepath.Join(dir, "mala.key")
			os.Remove(path)
			if err := os.WriteFile(path, []byte(contenido), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, _, err := witnessKey(path); err == nil {
				t.Errorf("se aceptó %q como clave", contenido)
			}
		}
	})

	t.Run("no pisa una clave existente", func(t *testing.T) {
		// La propiedad que da O_EXCL: si el fichero ya está, jamás se escribe.
		path := filepath.Join(dir, "existente.key")
		os.Remove(path)
		original := hex.EncodeToString([]byte("01234567890123456789012345678901"))
		if err := os.WriteFile(path, []byte(original), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, _, err := witnessKey(path); err != nil {
			t.Fatal(err)
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if string(raw) != original {
			t.Error("se sobrescribió una clave existente")
		}
	})
}
