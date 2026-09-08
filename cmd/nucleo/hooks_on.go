//go:build testhooks

package main

import (
	"encoding/hex"
	"fmt"
	"os"
	"time"
)

// Binario DE PRUEBAS: aquí sí existen los ganchos.
//
// Esta mitad solo se compila con `-tags testhooks`. Los tests de la CLI
// comparan salidas byte a byte, y una salida con la hora de ahora y claves
// aleatorias no se puede comparar con nada.
//
// NADA de este fichero llega a un binario publicado. goreleaser compila sin el
// tag, y el snapshot lo comprueba buscando la cadena del gancho en el binario.

// hookClock devuelve el reloj fijado, si lo hay.
func hookClock() time.Time {
	if v := os.Getenv(envClock); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			return t.UTC()
		}
	}
	return time.Now().UTC()
}

// hookSeed devuelve la semilla fija de 32 bytes, si la hay.
func hookSeed() ([]byte, bool) {
	v := os.Getenv(envSeed)
	if v == "" {
		return nil, false
	}
	raw, err := hex.DecodeString(v)
	if err != nil || len(raw) != 32 {
		return nil, false
	}
	return raw, true
}

// hookPassphrase devuelve la passphrase del entorno, si la hay.
func hookPassphrase() (string, bool) {
	v := os.Getenv(envPassphrase)
	return v, v != ""
}

// checkHooks avisa de que este binario SÍ los admite, que es lo peligroso.
func checkHooks(e *env) error {
	var activos []string
	for _, k := range hookVars {
		if _, ok := os.LookupEnv(k); ok {
			activos = append(activos, k)
		}
	}
	if len(activos) == 0 {
		return nil
	}
	fmt.Fprintf(e.stderr,
		"AVISO: este binario se compiló con el tag `testhooks` y HONRA los ganchos de prueba: %v.\n"+
			"       No es un binario de producción.\n", activos)
	return nil
}
