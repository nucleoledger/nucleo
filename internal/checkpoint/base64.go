package checkpoint

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

// El base64 de cable (Sprint 38b, hallazgo del fuzzer en el ci #104).
//
// base64.StdEncoding.Strict() NO basta: rechaza los bits de relleno distintos de cero,
// pero ignora \r y \n en cualquier punto de la entrada (está documentado). Un recibo con
// un \r en mitad de un nodo decodificaba a los mismos 32 bytes que sin él: dos ficheros,
// un recibo. Y el verificador de PHP lo rechazaba, así que el veredicto dependía de quién
// mirase. Aquí se decide en un solo sitio, y con la regla de los otros dos verificadores.

// ErrBase64 es el error de un base64 que no es la codificación canónica de sus bytes.
var ErrBase64 = errors.New("base64 no canónico")

// DecodeBase64Canonical decodifica base64 estándar (RFC 4648 §4) y exige que el texto sea
// EXACTAMENTE la codificación de lo que decodifica: solo el alfabeto estándar, longitud
// múltiplo de 4, relleno presente y bien puesto, bits de relleno a cero, y ningún \r, \n,
// espacio, tabulador ni otro carácter en ningún punto. La cadena vacía no es un base64
// válido de nada que viaje en un recibo, y también se rechaza.
func DecodeBase64Canonical(s string) ([]byte, error) {
	if s == "" || len(s)%4 != 0 {
		return nil, fmt.Errorf("%w: longitud %d", ErrBase64, len(s))
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case 'A' <= c && c <= 'Z', 'a' <= c && c <= 'z', '0' <= c && c <= '9', c == '+', c == '/':
		case c == '=' && i >= len(s)-2:
		default:
			return nil, fmt.Errorf("%w: carácter %q en la posición %d", ErrBase64, c, i)
		}
	}
	b, err := base64.StdEncoding.Strict().DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrBase64, err)
	}
	// Y la vuelta: cierra cualquier holgura del decodificador sin enumerarlas (un "=" en
	// la penúltima posición sin otro detrás, por ejemplo, ya lo rechaza Strict; esto es lo
	// que garantiza que no quede ninguna).
	if base64.StdEncoding.EncodeToString(b) != s {
		return nil, ErrBase64
	}
	return b, nil
}

// CheckSigLines aplica DecodeBase64Canonical a cada línea de firma de una nota firmada,
// ANTES de entregarla a note.Open: x/mod decodifica esas líneas con el decodificador no
// estricto, que acepta relleno con bits a uno y saltos de línea dentro. Solo mira lo que
// sigue al nombre (signed-note: «— <nombre> <base64>», nombre sin espacios); el resto de
// la estructura lo sigue validando x/mod.
//
// Antes mira la regla de la nota entera que x/mod aplica primero —ningún carácter de
// control salvo \n—, para que un \r o un \t en una línea de firma se rechace por lo
// mismo que en los verificadores de TypeScript y PHP, que la miran primero también.
func CheckSigLines(msg []byte) error {
	for _, c := range msg {
		if c < 0x20 && c != '\n' {
			return fmt.Errorf("%w: la nota contiene caracteres de control (%q)", ErrFormat, c)
		}
	}
	i := strings.LastIndex(string(msg), "\n\n")
	if i < 0 {
		return nil // sin bloque de firmas: note.Open dará su error
	}
	for _, line := range strings.Split(strings.TrimSuffix(string(msg[i+2:]), "\n"), "\n") {
		rest, ok := strings.CutPrefix(line, "— ")
		if !ok {
			continue
		}
		name, b64, ok := strings.Cut(rest, " ")
		if !ok {
			continue
		}
		if _, err := DecodeBase64Canonical(b64); err != nil {
			return fmt.Errorf("%w: firma de %q: %w", ErrFormat, name, err)
		}
	}
	return nil
}
