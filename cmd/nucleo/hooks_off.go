//go:build !testhooks

package main

import (
	"fmt"
	"os"
	"time"
)

// Binario de PRODUCCIÓN: los ganchos de prueba no existen aquí.
//
// Este fichero es la mitad que se compila cuando NO se pasa el tag `testhooks`,
// y es lo único que hay en un binario publicado. No lee ninguna semilla, no
// acepta ningún reloj impuesto y no toma la passphrase del entorno: ese código
// simplemente no está en el ejecutable.
//
// Que no esté es la diferencia que importa. Un gancho apagado por una condición
// en tiempo de ejecución sigue siendo código presente, alcanzable por cualquiera
// que consiga alterar el entorno del proceso o encontrar un camino que salte esa
// condición. Un gancho que no se compiló no tiene esa superficie.

// hookClock devuelve el reloj del sistema, y solo ese.
func hookClock() time.Time { return time.Now().UTC() }

// hookSeed no existe en producción.
func hookSeed() ([]byte, bool) { return nil, false }

// hookPassphrase no existe en producción.
func hookPassphrase() (string, bool) { return "", false }

// checkHooks aborta si alguna variable de gancho está definida.
//
// FALLO CERRADO, y a propósito. La alternativa —seguir adelante con un aviso—
// deja al usuario creyendo que puso un gancho y que funcionó, cuando lo que ha
// hecho es exactamente lo contrario de lo que cree. Alguien que define
// NUCLEO_TEST_SEED espera claves deterministas; si el binario las genera
// aleatorias y solo avisa por stderr, ese aviso se pierde en un log y el
// despliegue queda con una expectativa falsa sobre sus propias claves.
//
// Abortar convierte una confusión silenciosa en un error que hay que resolver.
func checkHooks(e *env) error {
	for _, k := range hookVars {
		if _, ok := os.LookupEnv(k); ok {
			fmt.Fprintf(e.stderr,
				"error: la variable %s está definida.\n\n"+
					"  Es un gancho de PRUEBAS y este binario no lo admite: se compiló sin\n"+
					"  el tag `testhooks`, así que ese código no existe en él. Definirla no\n"+
					"  hace nada, y seguir adelante te dejaría creyendo lo contrario.\n\n"+
					"  Quita %s del entorno y vuelve a ejecutar.\n", k, k)
			return &exitError{code: exitUsage, err: fmt.Errorf("gancho de pruebas %s definido en un binario de producción", k), reported: true}
		}
	}
	return nil
}
