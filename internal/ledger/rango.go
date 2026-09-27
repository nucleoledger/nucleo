package ledger

import (
	"errors"
	"fmt"
	"math"
)

// ErrSizeRange indica un tamaño de árbol que no cabe en el entero con el que se opera.
//
// El formato del checkpoint (C2SP) permite cualquier uint64 decimal, y eso no se toca:
// es el formato. Lo que tiene límite es esta implementación —los índices de Go son int y
// SQLite guarda int64—, y un tamaño que llega de fuera no puede convertirse a int y
// volverse NEGATIVO. Hasta el Sprint 13 esos valores se rechazaban igual, pero por
// accidente: la conversión los desbordaba y alguna guarda posterior los cazaba. Un
// control de integridad no puede depender de un desbordamiento.
var ErrSizeRange = errors.New("ledger: tamaño de árbol fuera de rango")

// SizeToInt convierte un tamaño o índice de árbol a int, o falla con ErrSizeRange.
func SizeToInt(n uint64) (int, error) {
	if n > math.MaxInt {
		return 0, fmt.Errorf("%w: %d no cabe en un int de esta plataforma", ErrSizeRange, n)
	}
	return int(n), nil
}

// SizeToInt64 convierte un tamaño o índice de árbol a int64, o falla con ErrSizeRange.
// Es el que necesita SQLite, cuyos enteros son de 64 bits con signo.
func SizeToInt64(n uint64) (int64, error) {
	if n > math.MaxInt64 {
		return 0, fmt.Errorf("%w: %d no cabe en un int64", ErrSizeRange, n)
	}
	return int64(n), nil
}
