package estricto

import (
	"errors"
	"slices"
)

// Clase es el tipo de desviación de la gramática que rechazó un documento. No cambia qué se
// acepta ni el mensaje: dice, a quien tiene que dar un motivo con nombre (los vectores de
// política llevan uno, "reason"), qué falló y dónde, sin adivinarlo del texto.
type Clase string

// Las clases de rechazo del lector.
const (
	ClaseTamano    Clase = "tamaño"    // el documento supera Opciones.Max
	ClaseUTF8      Clase = "utf8"      // no es UTF-8 válido
	ClaseBOM       Clase = "bom"       // empieza con BOM
	ClaseNoObjeto  Clase = "no-objeto" // el documento es otro valor que un objeto
	ClaseSintaxis  Clase = "sintaxis"  // no es JSON, o está vacío
	ClaseNumero    Clase = "número"    // un número que no sigue la gramática de RFC 8259
	ClaseDetras    Clase = "detrás"    // hay algo después del objeto
	ClaseRepetido  Clase = "repetido"  // un nombre repetido, también tras deshacer escapes
	ClaseSurrogate Clase = "surrogate" // un surrogate UTF-16 suelto en un escape
	ClaseNull      Clase = "null"      // un null
	ClaseBooleano  Clase = "booleano"  // un true o un false
	ClaseArray     Clase = "array"     // un array
	ClaseAnidado   Clase = "anidado"   // un objeto más hondo que Opciones.Profundidad
)

// Error es todo rechazo del lector. Su texto es «<centinela>: <mensaje>», el de siempre, y
// envuelve el centinela de Opciones.Error.
type Error struct {
	// Clase es qué falló.
	Clase Clase
	// Ruta son los nombres de los miembros, desde el documento, cuyo valor se estaba
	// leyendo; vacía si el fallo es del documento o de su primer nivel de nombres.
	Ruta []string
	base error
	msg  string
}

func nuevoError(base error, clase Clase, ruta []string, msg string) *Error {
	return &Error{Clase: clase, Ruta: slices.Clone(ruta), base: base, msg: msg}
}

func (e *Error) Error() string { return e.base.Error() + ": " + e.msg }

func (e *Error) Unwrap() error { return e.base }

// Como devuelve el *Error que hay en la cadena de err, o nil.
func Como(err error) *Error {
	var e *Error
	if errors.As(err, &e) {
		return e
	}
	return nil
}
