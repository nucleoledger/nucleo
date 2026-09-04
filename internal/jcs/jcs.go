// Package jcs implementa JSON Canonicalization Scheme (RFC 8785) sin dependencias
// externas. Toda estructura que se hashea o firma en Núcleo pasa por aquí, de modo
// que dos implementaciones (Go, TypeScript, un auditor externo) produzcan
// exactamente los mismos bytes a partir del mismo contenido lógico.
//
// Reglas aplicadas:
//   - Sin espacios en blanco entre tokens.
//   - Claves de objeto ordenadas por unidades de código UTF-16 (no por bytes UTF-8).
//   - Números serializados como ECMAScript Number.prototype.toString().
//   - Cadenas con el escape mínimo de RFC 8785 §3.2.2.2 (sin escapar '<', '>', '&').
//
// Advertencia de diseño: JCS trata todo número como IEEE-754 double. Enteros por
// encima de 2^53 pierden precisión y los decimales monetarios (12.50) tampoco son
// exactos. En Núcleo los montos viajan SIEMPRE como strings dentro del payload.
package jcs

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

var (
	// ErrInvalidNumber se devuelve para NaN o ±Inf, que JSON no puede representar.
	ErrInvalidNumber = errors.New("jcs: número no finito (NaN/Inf) no es serializable")
	// ErrInvalidUTF8 se devuelve si una cadena contiene bytes UTF-8 inválidos.
	ErrInvalidUTF8 = errors.New("jcs: cadena con UTF-8 inválido")
)

// Marshal serializa v en forma canónica. Acepta structs (respetando etiquetas
// `json:"..."`), mapas, slices y primitivos. Internamente hace una pasada por
// encoding/json para reutilizar sus reglas de etiquetas y omitempty, y después
// re-serializa la forma genérica aplicando las reglas de RFC 8785.
func Marshal(v any) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("jcs: pre-serialización: %w", err)
	}

	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber() // conserva el literal numérico; nunca lo convierte a float64 a ciegas
	var generic any
	if err := dec.Decode(&generic); err != nil {
		return nil, fmt.Errorf("jcs: decodificación intermedia: %w", err)
	}

	var buf bytes.Buffer
	if err := encode(&buf, generic); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// encode recorre la forma genérica y escribe la representación canónica.
func encode(buf *bytes.Buffer, v any) error {
	switch t := v.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		buf.WriteString(strconv.FormatBool(t))
	case json.Number:
		s, err := formatNumber(t)
		if err != nil {
			return err
		}
		buf.WriteString(s)
	case string:
		return encodeString(buf, t)
	case []any:
		buf.WriteByte('[')
		for i, el := range t {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := encode(buf, el); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool { return lessUTF16(keys[i], keys[j]) })
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := encodeString(buf, k); err != nil {
				return err
			}
			buf.WriteByte(':')
			if err := encode(buf, t[k]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	default:
		return fmt.Errorf("jcs: tipo intermedio no soportado %T", v)
	}
	return nil
}

// lessUTF16 compara dos claves por unidades de código UTF-16, como exige RFC 8785.
// Para texto del plano básico coincide con el orden de bytes UTF-8; difiere con
// emojis y otros caracteres fuera del BMP, por eso no se usa strings.Compare.
func lessUTF16(a, b string) bool {
	ua := utf16.Encode([]rune(a))
	ub := utf16.Encode([]rune(b))
	for i := 0; i < len(ua) && i < len(ub); i++ {
		if ua[i] != ub[i] {
			return ua[i] < ub[i]
		}
	}
	return len(ua) < len(ub)
}

// encodeString aplica el escape mínimo de RFC 8785 §3.2.2.2.
func encodeString(buf *bytes.Buffer, s string) error {
	if !utf8.ValidString(s) {
		return ErrInvalidUTF8
	}
	buf.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			buf.WriteString(`\"`)
		case '\\':
			buf.WriteString(`\\`)
		case '\b':
			buf.WriteString(`\b`)
		case '\f':
			buf.WriteString(`\f`)
		case '\n':
			buf.WriteString(`\n`)
		case '\r':
			buf.WriteString(`\r`)
		case '\t':
			buf.WriteString(`\t`)
		default:
			if r < 0x20 {
				fmt.Fprintf(buf, `\u%04x`, r) // hex en minúsculas según la norma
			} else {
				buf.WriteRune(r) // todo lo demás, incluido no-ASCII, va literal
			}
		}
	}
	buf.WriteByte('"')
	return nil
}

// formatNumber convierte el literal JSON a double y lo re-serializa como ES6.
func formatNumber(n json.Number) (string, error) {
	f, err := strconv.ParseFloat(string(n), 64)
	if err != nil {
		return "", fmt.Errorf("jcs: número inválido %q: %w", n, err)
	}
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return "", ErrInvalidNumber
	}
	return formatES6(f), nil
}

// formatES6 reproduce el algoritmo Number::toString de ECMAScript:
// dígitos más cortos que hacen round-trip, notación posicional entre 1e-6 y 1e21,
// exponencial fuera de ese rango, y "-0" se imprime como "0".
func formatES6(f float64) string {
	if f == 0 {
		return "0"
	}
	sign := ""
	if f < 0 {
		sign = "-"
		f = -f
	}

	// 'e' con precisión -1 entrega los mismos dígitos significativos mínimos que ES6.
	e := strconv.FormatFloat(f, 'e', -1, 64) // p.ej. "1.2345e+02"
	mant, expStr, _ := strings.Cut(e, "e")
	exp, _ := strconv.Atoi(expStr) // FormatFloat siempre produce un exponente válido
	digits := strings.Replace(mant, ".", "", 1)
	k := len(digits) // cantidad de dígitos significativos
	n := exp + 1     // posición del punto decimal respecto al primer dígito

	var out string
	switch {
	case k <= n && n <= 21:
		out = digits + strings.Repeat("0", n-k)
	case 0 < n && n <= 21:
		out = digits[:n] + "." + digits[n:]
	case -6 < n && n <= 0:
		out = "0." + strings.Repeat("0", -n) + digits
	default:
		expSign := "+"
		if n-1 < 0 {
			expSign = "-"
		}
		absExp := strconv.Itoa(absInt(n - 1))
		if k == 1 {
			out = digits + "e" + expSign + absExp
		} else {
			out = digits[:1] + "." + digits[1:] + "e" + expSign + absExp
		}
	}
	return sign + out
}

func absInt(x int) int {
	if x < 0 {
		return -x
	}
	return x
}
