package main

import (
	"encoding/hex"
	"os"
	"time"
)

// Ganchos de prueba. NO SON PARA PRODUCCIÓN.
//
// Existen porque los tests de la CLI comparan salidas byte a byte, y una salida
// con la hora de ahora y claves aleatorias no se puede comparar con nada. Las
// dos variables están documentadas aquí, se leen en un solo sitio y avisan por
// stderr cuando se usan, para que nadie las active en un despliegue real sin
// enterarse.
const (
	// envSeed fija el material "aleatorio" de init. Con él, las claves de un
	// despliegue son predecibles: usarlo fuera de un test destruye la seguridad
	// del vault por completo.
	envSeed = "NUCLEO_TEST_SEED"
	// envClock fija el reloj en RFC 3339.
	envClock = "NUCLEO_TEST_CLOCK"
	// envPassphrase evita el terminal. Es visible en el entorno del proceso.
	envPassphrase = "NUCLEO_TEST_PASSPHRASE"
)

// testClock devuelve el reloj, fijo si se pidió.
func testClock() time.Time {
	if v := os.Getenv(envClock); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			return t.UTC()
		}
	}
	return time.Now().UTC()
}

// testSeed devuelve la semilla fija de 32 bytes, si la hay.
func testSeed() ([]byte, bool) {
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

// warnTestHooks avisa por stderr si algún gancho está activo.
func warnTestHooks(e *env) {
	for _, k := range []string{envSeed, envClock, envPassphrase} {
		if os.Getenv(k) != "" {
			e.stderr.WriteString("AVISO: " + k + " está definida. Es un gancho de PRUEBAS y no debe usarse en producción.\n")
		}
	}
}

// decodeHex es hex.DecodeString con el error envuelto por quien llama.
func decodeHex(s string) ([]byte, error) { return hex.DecodeString(s) }
