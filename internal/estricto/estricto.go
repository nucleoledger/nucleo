// Package estricto lee los documentos JSON de configuración que deciden qué se
// verifica o qué se firma —la política (PROTOCOL.md §3.2, ADR-018) y la
// configuración del testigo (ADR-030)— con una gramática estricta.
//
// La tercera auditoría enseñó por qué no sirve encoding/json para esto:
// `{"signerKey": A, "signerkey": B}` le daba B a la CLI —empareja claves sin
// distinguir mayúsculas y gana la última— y A a la página. Cuando Unmarshal
// devuelve, el duplicado ya se ha perdido. Así que aquí hay un lector propio,
// pequeño, que implementa la gramática literalmente: miembros repetidos,
// comentarios, comas finales, BOM, arrays, booleanos y null son error. Qué
// miembros existen y qué significan lo decide cada formato; este paquete solo lee.
//
// Vivió dentro de internal/policy hasta el Sprint 15, y se movió sin cambiar un
// solo mensaje de la política: cada formato pone su centinela de error y los dos
// mensajes que hablan de él.
package estricto

import (
	"bytes"
	"crypto/ed25519"
	"fmt"
	"strconv"
	"unicode/utf16"
	"unicode/utf8"
)

// Opciones son lo que distingue un formato de otro al leerlo.
type Opciones struct {
	// Error es el centinela que envuelve todo rechazo.
	Error error
	// Max es el tamaño máximo del documento, en bytes.
	Max int
	// Profundidad es la máxima de objetos anidados; 1 es el documento.
	Profundidad int
	// MsgAnidado es el mensaje para un objeto más hondo que Profundidad.
	MsgAnidado string
	// MsgValor es el mensaje para un valor que no es cadena, número ni objeto.
	MsgValor string
}

// Leer valida que raw sea un único objeto JSON bien formado según la gramática
// estricta y devuelve sus miembros en orden.
func Leer(raw []byte, o Opciones) ([]Miembro, error) {
	if len(raw) > o.Max {
		return nil, fmt.Errorf("%w: mide %d bytes y el máximo es %d", o.Error, len(raw), o.Max)
	}
	if !utf8.Valid(raw) {
		return nil, fmt.Errorf("%w: no es UTF-8 válido", o.Error)
	}
	if bytes.HasPrefix(raw, []byte("\xef\xbb\xbf")) {
		return nil, fmt.Errorf("%w: empieza con BOM", o.Error)
	}
	p := &lector{s: raw, o: o}
	p.espacios()
	if p.i >= len(p.s) || p.s[p.i] != '{' {
		return nil, fmt.Errorf("%w: el documento tiene que ser un objeto JSON", o.Error)
	}
	obj, err := p.objeto(1)
	if err != nil {
		return nil, err
	}
	p.espacios()
	if p.i != len(p.s) {
		return nil, fmt.Errorf("%w: hay contenido después del objeto (posición %d)", o.Error, p.i)
	}
	return obj, nil
}

// Valor es un valor JSON leído. Solo existen los tipos que estos formatos pueden
// contener; arrays, booleanos y null son error en cuanto aparecen.
type Valor struct {
	Cadena string
	Numero string // literal tal cual, si es número
	Objeto []Miembro
	Tipo   byte // 's', 'n', 'o'
}

// Miembro es un par nombre–valor de un objeto, en el orden del documento.
type Miembro struct {
	Nombre string
	Valor  Valor
}

type lector struct {
	s []byte
	i int
	o Opciones
}

func (p *lector) errorf(format string, args ...any) error {
	return fmt.Errorf("%w: "+format+" (posición %d)", append([]any{p.o.Error}, append(args, p.i)...)...)
}

func (p *lector) espacios() {
	for p.i < len(p.s) {
		switch p.s[p.i] {
		case ' ', '\t', '\n', '\r':
			p.i++
		default:
			return
		}
	}
}

// objeto lee un objeto. profundidad 1 es el documento; más hondo que
// Opciones.Profundidad es error.
func (p *lector) objeto(profundidad int) ([]Miembro, error) {
	if profundidad > p.o.Profundidad {
		return nil, p.errorf("%s", p.o.MsgAnidado)
	}
	p.i++ // '{'
	var out []Miembro
	vistos := map[string]bool{}
	p.espacios()
	if p.i < len(p.s) && p.s[p.i] == '}' {
		p.i++
		return out, nil
	}
	for {
		p.espacios()
		if p.i >= len(p.s) || p.s[p.i] != '"' {
			return nil, p.errorf("se esperaba el nombre de un miembro")
		}
		nombre, err := p.cadena()
		if err != nil {
			return nil, err
		}
		if vistos[nombre] {
			return nil, p.errorf("el miembro %q está repetido", nombre)
		}
		vistos[nombre] = true
		p.espacios()
		if p.i >= len(p.s) || p.s[p.i] != ':' {
			return nil, p.errorf("se esperaba ':'")
		}
		p.i++
		p.espacios()
		v, err := p.valor(profundidad)
		if err != nil {
			return nil, err
		}
		out = append(out, Miembro{nombre, v})
		p.espacios()
		if p.i >= len(p.s) {
			return nil, p.errorf("objeto sin cerrar")
		}
		switch p.s[p.i] {
		case ',':
			p.i++
		case '}':
			p.i++
			return out, nil
		default:
			return nil, p.errorf("se esperaba ',' o '}'")
		}
	}
}

func (p *lector) valor(profundidad int) (Valor, error) {
	if p.i >= len(p.s) {
		return Valor{}, p.errorf("falta un valor")
	}
	switch c := p.s[p.i]; {
	case c == '"':
		s, err := p.cadena()
		return Valor{Tipo: 's', Cadena: s}, err
	case c == '{':
		o, err := p.objeto(profundidad + 1)
		return Valor{Tipo: 'o', Objeto: o}, err
	case c == '-' || (c >= '0' && c <= '9'):
		n, err := p.numero()
		return Valor{Tipo: 'n', Numero: n}, err
	default:
		return Valor{}, p.errorf("%s", p.o.MsgValor)
	}
}

// cadena lee una cadena JSON y devuelve su valor decodificado. Rechaza las secuencias
// \u que dejan un surrogate UTF-16 suelto: encoding/json las convierte en U+FFFD en
// silencio y JSON.parse las conserva, y ese desacuerdo sería una divergencia.
func (p *lector) cadena() (string, error) {
	p.i++ // '"'
	var b []byte
	for {
		if p.i >= len(p.s) {
			return "", p.errorf("cadena sin cerrar")
		}
		c := p.s[p.i]
		switch {
		case c == '"':
			p.i++
			return string(b), nil
		case c < 0x20:
			return "", p.errorf("carácter de control sin escapar dentro de una cadena")
		case c != '\\':
			b = append(b, c)
			p.i++
			continue
		}
		p.i++
		if p.i >= len(p.s) {
			return "", p.errorf("escape incompleto")
		}
		e := p.s[p.i]
		p.i++
		switch e {
		case '"', '\\', '/':
			b = append(b, e)
		case 'b':
			b = append(b, '\b')
		case 'f':
			b = append(b, '\f')
		case 'n':
			b = append(b, '\n')
		case 'r':
			b = append(b, '\r')
		case 't':
			b = append(b, '\t')
		case 'u':
			u, err := p.hex4()
			if err != nil {
				return "", err
			}
			r := rune(u)
			switch {
			case utf16.IsSurrogate(r) && u < 0xdc00:
				if p.i+1 >= len(p.s) || p.s[p.i] != '\\' || p.s[p.i+1] != 'u' {
					return "", p.errorf("surrogate UTF-16 alto sin su pareja")
				}
				p.i += 2
				bajo, err := p.hex4()
				if err != nil {
					return "", err
				}
				if bajo < 0xdc00 || bajo > 0xdfff {
					return "", p.errorf("surrogate UTF-16 alto sin su pareja")
				}
				r = utf16.DecodeRune(r, rune(bajo))
			case utf16.IsSurrogate(r):
				return "", p.errorf("surrogate UTF-16 bajo suelto")
			}
			b = utf8.AppendRune(b, r)
		default:
			return "", p.errorf("escape desconocido \\%c", e)
		}
	}
}

func (p *lector) hex4() (uint16, error) {
	if p.i+4 > len(p.s) {
		return 0, p.errorf("escape \\u incompleto")
	}
	v, err := strconv.ParseUint(string(p.s[p.i:p.i+4]), 16, 16)
	if err != nil {
		return 0, p.errorf("escape \\u con dígitos no hexadecimales")
	}
	p.i += 4
	return uint16(v), nil
}

// numero lee un número con la gramática completa de RFC 8259 y devuelve el literal.
func (p *lector) numero() (string, error) {
	ini := p.i
	digitos := func() int {
		n := 0
		for p.i < len(p.s) && p.s[p.i] >= '0' && p.s[p.i] <= '9' {
			p.i++
			n++
		}
		return n
	}
	if p.s[p.i] == '-' {
		p.i++
	}
	if p.i < len(p.s) && p.s[p.i] == '0' {
		p.i++
	} else if digitos() == 0 {
		return "", p.errorf("número mal formado")
	}
	if p.i < len(p.s) && p.s[p.i] == '.' {
		p.i++
		if digitos() == 0 {
			return "", p.errorf("número mal formado")
		}
	}
	if p.i < len(p.s) && (p.s[p.i] == 'e' || p.s[p.i] == 'E') {
		p.i++
		if p.i < len(p.s) && (p.s[p.i] == '+' || p.s[p.i] == '-') {
			p.i++
		}
		if digitos() == 0 {
			return "", p.errorf("número mal formado")
		}
	}
	return string(p.s[ini:p.i]), nil
}

// AsciiIgual compara sin distinguir mayúsculas ASCII. Solo decide el mensaje: una
// variante de mayúsculas y un nombre desconocido son error por igual.
func AsciiIgual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		x, y := a[i], b[i]
		if 'A' <= x && x <= 'Z' {
			x += 'a' - 'A'
		}
		if 'A' <= y && y <= 'Z' {
			y += 'a' - 'A'
		}
		if x != y {
			return false
		}
	}
	return true
}

// HexClave dice si s es una clave Ed25519 en hexadecimal en minúsculas: 64 caracteres.
func HexClave(s string) bool {
	if len(s) != 2*ed25519.PublicKeySize {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
