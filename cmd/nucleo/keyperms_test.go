//go:build testhooks

package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// skipEnWindows salta un subtest que solo tiene sentido con permisos POSIX.
//
// En Windows, el FileMode que expone Go es una traducción aproximada: un fichero
// se reporta como 0666 o 0444 según pueda escribirse o no, y el control de
// acceso real vive en la ACL, que desde ahí no se ve. Un test que compruebe el
// bit de "otros" no estaría comprobando nada: pasaría o fallaría por el mapeo,
// no por la protección.
//
// Por eso se salta con la razón escrita, en vez de relajar la aserción hasta que
// pase en todas partes. Una aserción que pasa siempre es peor que un salto
// visible: la primera finge cobertura, el segundo la declara ausente.
func skipEnWindows(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("los permisos POSIX no existen en Windows: el acceso lo gobierna la ACL, " +
			"que FileMode no refleja. Ver checkKeyPerms en keyperms_windows.go y " +
			"docs/RELEASING.md para cómo restringirla a mano.")
	}
}

// TestWitnessKeyCreation cubre lo que vale en TODOS los sistemas: la creación
// exclusiva y la estabilidad de la clave.
//
// Estos son los que importan de verdad y por eso no se saltan en ninguna parte.
// La propiedad de O_EXCL —que un segundo proceso no pueda pisar una clave ya
// creada— es exactamente igual de necesaria en Windows, y allí O_EXCL SÍ
// funciona: lo que no funciona es la comprobación de permisos.
func TestWitnessKeyCreation(t *testing.T) {
	dir := t.TempDir()

	t.Run("la segunda llamada devuelve la MISMA clave", func(t *testing.T) {
		path := filepath.Join(dir, "estable.key")
		a, creada, err := witnessKey(path)
		if err != nil || !creada {
			t.Fatalf("primera llamada: creada=%v err=%v", creada, err)
		}
		b, creada2, err := witnessKey(path)
		if err != nil {
			t.Fatal(err)
		}
		if creada2 {
			t.Error("la segunda llamada dijo que la creaba")
		}
		if !a.Equal(b) {
			t.Fatal("la clave cambió entre llamadas: las cosignatures ya emitidas dejarían de verificar")
		}
	})

	t.Run("no pisa una clave existente", func(t *testing.T) {
		// La propiedad que da O_EXCL: si el fichero ya está, jamás se escribe.
		// Sin ella, dos procesos arrancando a la vez dejarían al testigo con una
		// clave distinta de la que el primero ya usó para cosignar.
		path := filepath.Join(dir, "existente.key")
		original := hex.EncodeToString([]byte("01234567890123456789012345678901"))
		if err := os.WriteFile(path, []byte(original), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, creada, err := witnessKey(path); err != nil || creada {
			t.Fatalf("creada=%v err=%v", creada, err)
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if string(raw) != original {
			t.Error("se sobrescribió una clave existente")
		}
	})

	t.Run("rechaza contenido que no es una clave", func(t *testing.T) {
		for _, contenido := range []string{"", "no es hex", hex.EncodeToString(make([]byte, 16))} {
			path := filepath.Join(dir, "mala.key")
			if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte(contenido), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, _, err := witnessKey(path); err == nil {
				t.Errorf("se aceptó %q como clave del testigo", contenido)
			}
		}
	})
}

// TestWitnessKeyPOSIXPerms cubre lo que solo existe fuera de Windows.
func TestWitnessKeyPOSIXPerms(t *testing.T) {
	dir := t.TempDir()

	t.Run("se crea con permisos 0600", func(t *testing.T) {
		skipEnWindows(t)
		path := filepath.Join(dir, "nueva.key")
		if _, creada, err := witnessKey(path); err != nil || !creada {
			t.Fatalf("creada=%v err=%v", creada, err)
		}
		st, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if perm := st.Mode().Perm(); perm != 0o600 {
			t.Errorf("permisos = %04o, want 0600", perm)
		}
	})

	t.Run("rehúsa una clave legible por otros", func(t *testing.T) {
		skipEnWindows(t)
		path := filepath.Join(dir, "abierta.key")
		if err := os.WriteFile(path, []byte(hex.EncodeToString(make([]byte, ed25519.SeedSize))), 0o644); err != nil {
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
		skipEnWindows(t)
		for _, modo := range []os.FileMode{0o600, 0o400} {
			path := filepath.Join(dir, "modo.key")
			if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte(hex.EncodeToString(make([]byte, ed25519.SeedSize))), modo); err != nil {
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
}
