//go:build testhooks

package main

import (
	"fmt"
	"os"
	"strings"
	"testing"
)

// Tests DEL ARNÉS, no de la CLI.
//
// Existen porque el arnés tuvo un abrazo mortal que solo se manifestaba en Windows
// y que colgó el CI diez minutos enteros (runs #22 y #23). La causa era drenar los
// dos pipes en SECUENCIA: el lector de stdout no ve EOF hasta que el proceso
// termina, el proceso no termina porque está bloqueado escribiendo en un stderr
// lleno, y cada uno espera al otro.
//
// En Linux y macOS el buffer del pipe es de 64 KiB y nada se acercaba; en Windows
// son 4 KiB, y la ayuda —que sale por stderr en cualquier error de uso— pasó de esa
// marca al crecer en el sprint 7. Un bug latente desde el primer día que se armó
// solo cuando un texto cruzó un umbral invisible.
//
// La lección que estos tests fijan: un arnés que captura salida es código, y el
// código que nadie prueba es el que falla en el sistema operativo que nadie usa
// para desarrollar.

// TestArnesDrenaLosDosPipesEnParalelo reproduce el abrazo mortal EN CUALQUIER
// SISTEMA, que es lo que el bug original no hacía.
//
// Escribe en stderr mucho más de lo que cabe en el buffer de un pipe en cualquier
// plataforma. Con el arnés secuencial esto se cuelga en Linux igual que se colgaba
// en Windows con 5 KiB; con el arnés que drena en paralelo, pasa.
func TestArnesDrenaLosDosPipesEnParalelo(t *testing.T) {
	// 256 KiB: cuatro veces el buffer de Linux (64 KiB) y sesenta el de Windows.
	const grande = 256 << 10

	for _, c := range []struct {
		nombre       string
		enOut, enErr int
	}{
		{"stderr desbordado mientras se lee stdout", 1024, grande},
		{"stdout desbordado mientras se lee stderr", grande, 1024},
		{"los dos desbordados a la vez", grande, grande},
	} {
		t.Run(c.nombre, func(t *testing.T) {
			out, errOut, code := capturar(t, c.nombre, func(stdout, stderr *os.File) int {
				// Se escribe alternando para que ninguno pueda vaciarse entero antes
				// de que el otro empiece: es la situación real de la CLI, que mezcla
				// prosa en stdout con avisos en stderr.
				fmt.Fprint(stderr, strings.Repeat("e", c.enErr/2))
				fmt.Fprint(stdout, strings.Repeat("o", c.enOut/2))
				fmt.Fprint(stderr, strings.Repeat("E", c.enErr-c.enErr/2))
				fmt.Fprint(stdout, strings.Repeat("O", c.enOut-c.enOut/2))
				return 3
			})
			if len(out) != c.enOut {
				t.Errorf("stdout = %d bytes, want %d", len(out), c.enOut)
			}
			if len(errOut) != c.enErr {
				t.Errorf("stderr = %d bytes, want %d", len(errOut), c.enErr)
			}
			// El código de salida tiene que llegar entero, no perderse en el camino.
			if code != 3 {
				t.Errorf("código = %d, want 3", code)
			}
		})
	}
}

// TestErrorDeUsoDevuelveLaAyudaEntera es la regresión contra el caso REAL que colgó
// el CI: un error de uso vuelca la ayuda completa por stderr.
//
// No comprueba un tamaño concreto —la ayuda crecerá— sino que llega COMPLETA: desde
// la primera línea hasta la última. Si algún día se volviera a drenar en secuencia,
// este test se colgaría, y el guardián lo convertiría en un fallo en un minuto.
func TestErrorDeUsoDevuelveLaAyudaEntera(t *testing.T) {
	c := newCLI(t)
	_, errOut, code := c.run("noexiste")
	if code != exitUsage {
		t.Fatalf("código = %d, want %d", code, exitUsage)
	}

	ayuda := usageText()
	if !strings.Contains(errOut, ayuda) {
		t.Errorf("stderr no trae la ayuda entera: %d bytes recibidos, la ayuda son %d",
			len(errOut), len(ayuda))
	}
	// Y que la ayuda siga siendo lo bastante grande para que este test valga de algo:
	// el día que quepa en el buffer más pequeño, dejaría de cubrir el caso original
	// sin que nadie se entere.
	const bufferWindows = 4096
	if len(ayuda) <= bufferWindows {
		t.Logf("AVISO: la ayuda mide %d bytes y ya cabe en el buffer de pipe de "+
			"Windows (%d). Este test sigue siendo correcto, pero ya no reproduce el "+
			"caso que colgó el CI; el que lo reproduce es "+
			"TestArnesDrenaLosDosPipesEnParalelo.", len(ayuda), bufferWindows)
	}
}
