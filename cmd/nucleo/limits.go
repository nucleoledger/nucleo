package main

import (
	"fmt"
	"io"
	"os"
)

// Límites de lectura.
//
// Ninguno de estos ficheros lo elige el programa: los da quien lo invoca, y en
// un despliegue automatizado eso puede acabar siendo lo que devuelva otro
// sistema. Leer sin tope convierte un fichero equivocado —un volcado de la base,
// un log rotado, un /dev/zero por accidente— en el proceso consumiendo toda la
// memoria de la máquina.
//
// Los topes son generosos a propósito: han de estorbar a un error, no a un uso
// legítimo.
const (
	// DefaultMaxPayload es el tope de un documento a sellar. Una factura
	// electrónica pesa kilobytes; 64 MiB deja sitio de sobra para un PDF con
	// anexos y sigue siendo un tope.
	DefaultMaxPayload = 64 << 20

	// maxKeyFile es el tope de un fichero de passphrase o de clave. Una
	// passphrase son decenas de bytes y una clave en hexadecimal, 64. Un MiB es
	// mil veces más de lo que puede hacer falta: si el fichero es mayor, no es
	// el fichero que se cree.
	maxKeyFile = 1 << 20
)

// readLimited lee un fichero entero, rechazando los que pasen del tope.
//
// El tamaño se comprueba con Stat ANTES de leer, y además se lee con un lector
// acotado. Lo primero da un error inmediato y con el tamaño real, que es lo útil
// para quien se equivocó de fichero; lo segundo cubre el caso en que Stat mienta
// —un FIFO, /dev/zero, un fichero que crece mientras se lee—.
func readLimited(path string, max int64, que string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		// Se envuelve con %w y no con %v: quien llama necesita poder distinguir
		// "no existe" de "no se puede leer". witnessKey crea la clave la primera
		// vez, y sin esa distinción trataría un fichero ausente como un fallo.
		return nil, usageErr("no se pudo leer %s %q: %w", que, path, err)
	}
	defer f.Close()

	if st, err := f.Stat(); err == nil && st.Mode().IsRegular() && st.Size() > max {
		return nil, usageErr(
			"%s %q mide %s y el máximo es %s.\n"+
				"  Si es correcto, súbelo con --max-payload; si no, comprueba la ruta.",
			que, path, humanBytes(st.Size()), humanBytes(max))
	}

	data, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, usageErr("no se pudo leer %s %q: %v", que, path, err)
	}
	if int64(len(data)) > max {
		return nil, usageErr("%s %q pasa del máximo de %s", que, path, humanBytes(max))
	}
	return data, nil
}

// humanBytes formatea un tamaño para que lo lea una persona.
func humanBytes(n int64) string {
	switch {
	case n >= 1<<20:
		return fmt.Sprintf("%.0f MiB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.0f KiB", float64(n)/(1<<10))
	default:
		return fmt.Sprintf("%d bytes", n)
	}
}
