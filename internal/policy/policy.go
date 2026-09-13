// Package policy lee el fichero de política de verificación: el formato de cable de
// PROTOCOL.md §3.2 (ADR-018).
//
// La política es lo único en lo que confía quien verifica (ADR-017), y la CLI, el
// SDK de TypeScript y la página tienen que aceptar y rechazar exactamente los mismos
// documentos. La tercera auditoría enseñó por qué eso no se consigue con
// encoding/json: `{"signerKey": A, "signerkey": B}` le daba B a la CLI —empareja
// claves sin distinguir mayúsculas y gana la última— y A a la página. Cuando
// Unmarshal devuelve, el duplicado ya se ha perdido. Por eso aquí hay un lector
// propio, pequeño, que implementa la gramática de PROTOCOL.md literalmente, y su
// gemelo en sdk/ts/src/policy.ts. Los dos pasan por testdata/vectors/policy/ y por
// el diferencial.
package policy

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/nucleoledger/nucleo/internal/proof"
	"github.com/nucleoledger/nucleo/internal/store"
)

// MaxSize es el tamaño máximo de un documento de política, en bytes.
const MaxSize = 1 << 16

// ErrPolicy es la causa de todo rechazo de este paquete.
var ErrPolicy = errors.New("política inválida")

// File es una política ya validada. Las claves van en hexadecimal en minúsculas.
type File struct {
	Origin    string
	LogKey    string
	SignerKey string // "" si el documento no la trae
	Witnesses map[string]string
	Quorum    int
}

// miembros son los únicos nombres de miembro válidos del objeto de primer nivel.
var miembros = []string{"origin", "logKey", "signerKey", "witnesses", "quorum"}

// Parse lee y valida un documento de política. Cualquier desviación de PROTOCOL.md
// §3.2 es error: no hay reparaciones ni valores por omisión.
func Parse(raw []byte) (*File, error) {
	if len(raw) > MaxSize {
		return nil, fmt.Errorf("%w: mide %d bytes y el máximo es %d", ErrPolicy, len(raw), MaxSize)
	}
	if !utf8.Valid(raw) {
		return nil, fmt.Errorf("%w: no es UTF-8 válido", ErrPolicy)
	}
	if bytes.HasPrefix(raw, []byte("\xef\xbb\xbf")) {
		return nil, fmt.Errorf("%w: empieza con BOM", ErrPolicy)
	}
	p := &lector{s: raw}
	p.espacios()
	if p.i >= len(p.s) || p.s[p.i] != '{' {
		return nil, fmt.Errorf("%w: el documento tiene que ser un objeto JSON", ErrPolicy)
	}
	obj, err := p.objeto(1)
	if err != nil {
		return nil, err
	}
	p.espacios()
	if p.i != len(p.s) {
		return nil, fmt.Errorf("%w: hay contenido después del objeto (posición %d)", ErrPolicy, p.i)
	}
	return construir(obj)
}

// valor es un valor JSON leído. Solo existen los tipos que una política puede
// contener; arrays, booleanos y null son error en cuanto aparecen.
type valor struct {
	cadena string
	numero string // literal tal cual, si es número
	objeto []miembro
	tipo   byte // 's', 'n', 'o'
}

type miembro struct {
	nombre string
	valor  valor
}

type lector struct {
	s []byte
	i int
}

func (p *lector) errorf(format string, args ...any) error {
	return fmt.Errorf("%w: "+format+" (posición %d)", append([]any{ErrPolicy}, append(args, p.i)...)...)
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

// objeto lee un objeto. profundidad 1 es el documento; una política no tiene nada
// por debajo de la profundidad 2 (los testigos), así que más hondo es error.
func (p *lector) objeto(profundidad int) ([]miembro, error) {
	if profundidad > 2 {
		return nil, p.errorf("objeto anidado donde la política no admite ninguno")
	}
	p.i++ // '{'
	var out []miembro
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
		out = append(out, miembro{nombre, v})
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

func (p *lector) valor(profundidad int) (valor, error) {
	if p.i >= len(p.s) {
		return valor{}, p.errorf("falta un valor")
	}
	switch c := p.s[p.i]; {
	case c == '"':
		s, err := p.cadena()
		return valor{tipo: 's', cadena: s}, err
	case c == '{':
		o, err := p.objeto(profundidad + 1)
		return valor{tipo: 'o', objeto: o}, err
	case c == '-' || (c >= '0' && c <= '9'):
		n, err := p.numero()
		return valor{tipo: 'n', numero: n}, err
	default:
		return valor{}, p.errorf("valor no admitido en una política (solo cadenas, números y el objeto de testigos)")
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

// construir aplica la tabla de PROTOCOL.md §3.2 al objeto ya leído.
func construir(obj []miembro) (*File, error) {
	f := &File{}
	var tiene = map[string]bool{}
	var quorum string
	for _, m := range obj {
		if !conocido(m.nombre) {
			for _, k := range miembros {
				if asciiIgual(m.nombre, k) {
					return nil, fmt.Errorf("%w: el miembro %q es una variante de mayúsculas de %q", ErrPolicy, m.nombre, k)
				}
			}
			return nil, fmt.Errorf("%w: miembro desconocido %q", ErrPolicy, m.nombre)
		}
		tiene[m.nombre] = true
		switch m.nombre {
		case "origin":
			if m.valor.tipo != 's' || m.valor.cadena == "" {
				return nil, fmt.Errorf("%w: origin tiene que ser una cadena no vacía", ErrPolicy)
			}
			f.Origin = m.valor.cadena
		case "logKey", "signerKey":
			if m.valor.tipo != 's' || !hexClave(m.valor.cadena) {
				return nil, fmt.Errorf("%w: %s tiene que ser una clave de 64 caracteres hexadecimales en minúsculas", ErrPolicy, m.nombre)
			}
			if m.nombre == "logKey" {
				f.LogKey = m.valor.cadena
			} else {
				f.SignerKey = m.valor.cadena
			}
		case "witnesses":
			if m.valor.tipo != 'o' {
				return nil, fmt.Errorf("%w: witnesses tiene que ser un objeto", ErrPolicy)
			}
			if len(m.valor.objeto) == 0 {
				return nil, fmt.Errorf("%w: no trae ningún testigo; sin testigos no verifica nada", ErrPolicy)
			}
			f.Witnesses = map[string]string{}
			porClave := map[string]string{}
			for _, w := range m.valor.objeto {
				if w.nombre == "" {
					return nil, fmt.Errorf("%w: un testigo sin nombre", ErrPolicy)
				}
				if w.valor.tipo != 's' || !hexClave(w.valor.cadena) {
					return nil, fmt.Errorf("%w: la clave del testigo %q tiene que ser de 64 caracteres hexadecimales en minúsculas", ErrPolicy, w.nombre)
				}
				if otro, ok := porClave[w.valor.cadena]; ok {
					return nil, fmt.Errorf("%w: la misma clave está bajo dos nombres (%q y %q)", ErrPolicy, otro, w.nombre)
				}
				porClave[w.valor.cadena] = w.nombre
				f.Witnesses[w.nombre] = w.valor.cadena
			}
		case "quorum":
			if m.valor.tipo != 'n' {
				return nil, fmt.Errorf("%w: quorum tiene que ser un número entero", ErrPolicy)
			}
			quorum = m.valor.numero
		}
	}
	for _, req := range []string{"origin", "logKey", "witnesses", "quorum"} {
		if !tiene[req] {
			return nil, fmt.Errorf("%w: falta el miembro %q", ErrPolicy, req)
		}
	}
	if !enteroNatural(quorum) {
		return nil, fmt.Errorf("%w: quorum %s no es un entero sin fracción ni exponente", ErrPolicy, quorum)
	}
	if len(quorum) > 9 {
		return nil, fmt.Errorf("%w: quorum %s con %d testigos", ErrPolicy, quorum, len(f.Witnesses))
	}
	q, _ := strconv.Atoi(quorum)
	if q < 1 || q > len(f.Witnesses) {
		return nil, fmt.Errorf("%w: quorum %d con %d testigos", ErrPolicy, q, len(f.Witnesses))
	}
	f.Quorum = q
	return f, nil
}

func conocido(nombre string) bool {
	for _, k := range miembros {
		if nombre == k {
			return true
		}
	}
	return false
}

// asciiIgual compara sin distinguir mayúsculas ASCII. Solo decide el mensaje: una
// variante de mayúsculas y un nombre desconocido son error por igual.
func asciiIgual(a, b string) bool {
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

func hexClave(s string) bool {
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

// enteroNatural: el literal es 0 o un natural sin ceros a la izquierda.
func enteroNatural(s string) bool {
	if s == "0" {
		return true
	}
	if s == "" || s[0] < '1' || s[0] > '9' {
		return false
	}
	for i := 1; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func clave(s string) ed25519.PublicKey {
	b, _ := hex.DecodeString(s) // Parse ya garantizó 64 caracteres hexadecimales
	return ed25519.PublicKey(b)
}

// WitnessPolicy es la política de apertura del almacén.
func (f *File) WitnessPolicy() *store.WitnessPolicy {
	wp := &store.WitnessPolicy{Origin: f.Origin, LogKey: clave(f.LogKey), Quorum: f.Quorum,
		Witnesses: map[string]ed25519.PublicKey{}}
	if f.SignerKey != "" {
		wp.SignerKey = clave(f.SignerKey)
	}
	for n, k := range f.Witnesses {
		wp.Witnesses[n] = clave(k)
	}
	return wp
}

// ProofPolicy es la política con la que se verifica un recibo.
func (f *File) ProofPolicy() proof.Policy {
	p := proof.Policy{Origin: f.Origin, LogKey: clave(f.LogKey), Quorum: f.Quorum,
		Witnesses: map[string]ed25519.PublicKey{}}
	if f.SignerKey != "" {
		p.SignerKey = clave(f.SignerKey)
	}
	for n, k := range f.Witnesses {
		p.Witnesses[n] = clave(k)
	}
	return p
}
