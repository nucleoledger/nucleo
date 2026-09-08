//go:build testhooks

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestReadLimits es el hallazgo LOW de la auditoría pre-pública.
//
// Ninguno de estos ficheros lo elige el programa: los da quien lo invoca, y en
// un despliegue automatizado eso puede ser lo que devuelva otro sistema. Leer
// sin tope convierte un fichero equivocado en el proceso comiéndose la memoria
// de la máquina.
func TestReadLimits(t *testing.T) {
	c := newCLI(t)
	c.initLedger()

	grande := filepath.Join(c.dir, "grande.bin")
	if err := os.WriteFile(grande, make([]byte, 2<<20), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Run("el documento a sellar respeta --max-payload", func(t *testing.T) {
		_, stderr, code := c.run("seal", "--tenant", testTenant, "--type", "x",
			"--payload", grande, "--max-payload", "1024")
		if code != exitUsage {
			t.Fatalf("código = %d, want %d", code, exitUsage)
		}
		// El mensaje dice el tamaño real y cómo subirlo: quien se equivocó de
		// fichero necesita saber cuál cogió.
		for _, quiero := range []string{"MiB", "--max-payload", "comprueba la ruta"} {
			if !strings.Contains(stderr, quiero) {
				t.Errorf("el mensaje no contiene %q:\n%s", quiero, stderr)
			}
		}
	})

	t.Run("por debajo del tope sí sella", func(t *testing.T) {
		pequeno := filepath.Join(c.dir, "pequeno.json")
		if err := os.WriteFile(pequeno, []byte(`{"a":1}`), 0o600); err != nil {
			t.Fatal(err)
		}
		if out := c.mustRun("seal", "--tenant", testTenant, "--type", "x",
			"--payload", pequeno, "--max-payload", "1024"); !strings.Contains(out, "registro sellado") {
			t.Errorf("no selló:\n%s", out)
		}
	})

	t.Run("--max-payload no puede ser cero ni negativo", func(t *testing.T) {
		for _, v := range []string{"0", "-1"} {
			if _, _, code := c.run("seal", "--tenant", testTenant, "--type", "x",
				"--payload", grande, "--max-payload", v); code != exitUsage {
				t.Errorf("--max-payload=%s: código = %d", v, code)
			}
		}
	})

	t.Run("el fichero de passphrase tiene tope", func(t *testing.T) {
		enorme := filepath.Join(c.dir, "pass.txt")
		if err := os.WriteFile(enorme, make([]byte, maxKeyFile+1), 0o600); err != nil {
			t.Fatal(err)
		}
		_, stderr, code := c.run("status", "--passphrase-file", enorme)
		// status no pide passphrase, así que se usa un subcomando que sí.
		_ = stderr
		_ = code

		_, stderr, code = c.run("seal", "--tenant", testTenant, "--type", "x",
			"--payload", filepath.Join(c.dir, "pequeno.json"), "--passphrase-file", enorme)
		if code != exitUsage {
			t.Errorf("código = %d, want %d", code, exitUsage)
		}
		if !strings.Contains(stderr, "fichero de passphrase") {
			t.Errorf("el mensaje no nombra el fichero:\n%s", stderr)
		}
	})

	t.Run("readLimited detecta el exceso aunque Stat no lo diga", func(t *testing.T) {
		// Se comprueba el segundo cinturón: el lector acotado. Con un tope de
		// 10 bytes sobre un fichero de 20, el error llega igual.
		p := filepath.Join(c.dir, "veinte.bin")
		if err := os.WriteFile(p, make([]byte, 20), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := readLimited(p, 10, "el fichero"); err == nil {
			t.Error("se leyó un fichero que pasa del tope")
		}
		if _, err := readLimited(p, 20, "el fichero"); err != nil {
			t.Errorf("un fichero justo en el tope se rechazó: %v", err)
		}
	})

	t.Run("el tope se anuncia en la ayuda", func(t *testing.T) {
		out := c.mustRun("help")
		for _, quiero := range []string{"LÍMITES DE LECTURA", "64 MiB", "--max-payload"} {
			if !strings.Contains(out, quiero) {
				t.Errorf("la ayuda no menciona %q", quiero)
			}
		}
	})
}
