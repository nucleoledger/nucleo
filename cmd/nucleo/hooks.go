package main

// Interfaz de los ganchos de prueba, compartida por las dos implementaciones.
//
// Los NOMBRES de las variables viven aquí, fuera del build tag, porque el
// binario de producción necesita conocerlos para RECHAZARLOS. Lo que no existe
// sin el tag es el código que los honra.

import "time"

// Nombres de las variables de entorno que actúan como ganchos de prueba.
//
// Ninguna de ellas tiene efecto en un binario de producción. Al contrario: si
// alguna está definida, el binario se niega a arrancar. Ver hooksOff.go.
const (
	// envSeed fijaría el material "aleatorio" de init. Con él, las claves de un
	// despliegue serían predecibles.
	envSeed = "NUCLEO_TEST_SEED"
	// envClock fijaría el reloj.
	envClock = "NUCLEO_TEST_CLOCK"
	// envPassphrase evitaría el terminal y pasaría la passphrase por el entorno.
	envPassphrase = "NUCLEO_TEST_PASSPHRASE"
)

// hookVars son todas, para poder comprobarlas de una vez.
var hookVars = []string{envSeed, envClock, envPassphrase}

// now es el reloj de la CLI.
func now() time.Time { return hookClock() }
