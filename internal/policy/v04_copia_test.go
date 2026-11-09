package policy

// EL LECTOR DE POLÍTICAS DE v0.4.0-alpha, copiado tal cual para el fuzz diferencial
// (FuzzPoliticaFrenteAV04, Sprint 31). NO ES CÓDIGO DE PRODUCCIÓN y no se corrige: es
// la vara con la que se mide que la 0.8-draft no cambió nada para los documentos sin sus
// dos miembros nuevos.
//
// Procedencia: `git show v0.4.0-alpha:internal/estricto/estricto.go` y
// `git show v0.4.0-alpha:internal/policy/policy.go`, con estos únicos cambios mecánicos:
// los identificadores llevan el sufijo V04 y van en minúscula (para no chocar con los de
// hoy ni exportar nada), las llamadas a estricto.X pasan a ser las de esta copia, y de
// policy.go solo quedan File, Parse y lo que Parse llama (ni ErasureAuthority, ni
// WitnessPolicy, ni ProofPolicy, que no deciden si se acepta). Los comentarios son los
// de entonces.

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"strconv"
	"unicode/utf16"
	"unicode/utf8"
)

// errPolicyV04 es el ErrPolicy de v0.4.0-alpha.
var errPolicyV04 = errors.New("política inválida")

// opcionesV04 son lo que distingue un formato de otro al leerlo.
type opcionesV04 struct {
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

// leerV04 valida que raw sea un único objeto JSON bien formado según la gramática
// estricta y devuelve sus miembros en orden.
func leerV04(raw []byte, o opcionesV04) ([]miembroV04, error) {
	if len(raw) > o.Max {
		return nil, fmt.Errorf("%w: mide %d bytes y el máximo es %d", o.Error, len(raw), o.Max)
	}
	if !utf8.Valid(raw) {
		return nil, fmt.Errorf("%w: no es UTF-8 válido", o.Error)
	}
	if bytes.HasPrefix(raw, []byte("\xef\xbb\xbf")) {
		return nil, fmt.Errorf("%w: empieza con BOM", o.Error)
	}
	p := &lectorV04{s: raw, o: o}
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

// valorV04 es un valor JSON leído. Solo existen los tipos que estos formatos pueden
// contener; arrays, booleanos y null son error en cuanto aparecen.
type valorV04 struct {
	Cadena string
	Numero string // literal tal cual, si es número
	Objeto []miembroV04
	Tipo   byte // 's', 'n', 'o'
}

// miembroV04 es un par nombre–valor de un objeto, en el orden del documento.
type miembroV04 struct {
	Nombre string
	Valor  valorV04
}

type lectorV04 struct {
	s []byte
	i int
	o opcionesV04
}

func (p *lectorV04) errorf(format string, args ...any) error {
	return fmt.Errorf("%w: "+format+" (posición %d)", append([]any{p.o.Error}, append(args, p.i)...)...)
}

func (p *lectorV04) espacios() {
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
// opcionesV04.Profundidad es error.
func (p *lectorV04) objeto(profundidad int) ([]miembroV04, error) {
	if profundidad > p.o.Profundidad {
		return nil, p.errorf("%s", p.o.MsgAnidado)
	}
	p.i++ // '{'
	var out []miembroV04
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
		out = append(out, miembroV04{nombre, v})
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

func (p *lectorV04) valor(profundidad int) (valorV04, error) {
	if p.i >= len(p.s) {
		return valorV04{}, p.errorf("falta un valor")
	}
	switch c := p.s[p.i]; {
	case c == '"':
		s, err := p.cadena()
		return valorV04{Tipo: 's', Cadena: s}, err
	case c == '{':
		o, err := p.objeto(profundidad + 1)
		return valorV04{Tipo: 'o', Objeto: o}, err
	case c == '-' || (c >= '0' && c <= '9'):
		n, err := p.numero()
		return valorV04{Tipo: 'n', Numero: n}, err
	default:
		return valorV04{}, p.errorf("%s", p.o.MsgValor)
	}
}

// cadena lee una cadena JSON y devuelve su valor decodificado. Rechaza las secuencias
// \u que dejan un surrogate UTF-16 suelto: encoding/json las convierte en U+FFFD en
// silencio y JSON.parse las conserva, y ese desacuerdo sería una divergencia.
func (p *lectorV04) cadena() (string, error) {
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

func (p *lectorV04) hex4() (uint16, error) {
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
func (p *lectorV04) numero() (string, error) {
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

// asciiIgualV04 compara sin distinguir mayúsculas ASCII. Solo decide el mensaje: una
// variante de mayúsculas y un nombre desconocido son error por igual.
func asciiIgualV04(a, b string) bool {
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

// hexClaveV04 dice si s es una clave Ed25519 en hexadecimal en minúsculas: 64 caracteres.
func hexClaveV04(s string) bool {
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

// fileV04 es una política ya validada. Las claves van en hexadecimal en minúsculas.
type fileV04 struct {
	Origin    string
	LogKey    string
	SignerKey string // "" si el documento no la trae
	// ErasureKey es la clave que autoriza las supresiones (ADR-032), o "". No está en el
	// servidor: por eso no puede ser ninguna de las otras claves del documento.
	ErasureKey string
	Witnesses  map[string]string
	Quorum     int
}

// miembrosV04 son los únicos nombres de miembro válidos del objeto de primer nivel.
var miembrosV04 = []string{"origin", "logKey", "signerKey", "erasureKey", "witnesses", "quorum"}

// parseV04 lee y valida un documento de política. Cualquier desviación de PROTOCOL.md
// §3.2 es error: no hay reparaciones ni valores por omisión.
func parseV04(raw []byte) (*fileV04, error) {
	obj, err := leerV04(raw, opcionesV04{
		Error:       errPolicyV04,
		Max:         MaxSize,
		Profundidad: 2, // el documento y, debajo, el objeto de testigos
		MsgAnidado:  "objeto anidado donde la política no admite ninguno",
		MsgValor:    "valor no admitido en una política (solo cadenas, números y el objeto de testigos)",
	})
	if err != nil {
		return nil, err
	}
	return construirV04(obj)
}

// construirV04 aplica la tabla de PROTOCOL.md §3.2 al objeto ya leído.
func construirV04(obj []miembroV04) (*fileV04, error) {
	f := &fileV04{}
	var tiene = map[string]bool{}
	var quorum string
	for _, m := range obj {
		if !conocidoV04(m.Nombre) {
			for _, k := range miembrosV04 {
				if asciiIgualV04(m.Nombre, k) {
					return nil, fmt.Errorf("%w: el miembro %q es una variante de mayúsculas de %q", errPolicyV04, m.Nombre, k)
				}
			}
			return nil, fmt.Errorf("%w: miembro desconocido %q", errPolicyV04, m.Nombre)
		}
		tiene[m.Nombre] = true
		switch m.Nombre {
		case "origin":
			if m.Valor.Tipo != 's' || m.Valor.Cadena == "" {
				return nil, fmt.Errorf("%w: origin tiene que ser una cadena no vacía", errPolicyV04)
			}
			f.Origin = m.Valor.Cadena
		case "logKey", "signerKey", "erasureKey":
			if m.Valor.Tipo != 's' || !hexClaveV04(m.Valor.Cadena) {
				return nil, fmt.Errorf("%w: %s tiene que ser una clave de 64 caracteres hexadecimales en minúsculas", errPolicyV04, m.Nombre)
			}
			switch m.Nombre {
			case "logKey":
				f.LogKey = m.Valor.Cadena
			case "signerKey":
				f.SignerKey = m.Valor.Cadena
			default:
				f.ErasureKey = m.Valor.Cadena
			}
		case "witnesses":
			if m.Valor.Tipo != 'o' {
				return nil, fmt.Errorf("%w: witnesses tiene que ser un objeto", errPolicyV04)
			}
			if len(m.Valor.Objeto) == 0 {
				return nil, fmt.Errorf("%w: no trae ningún testigo; sin testigos no verifica nada", errPolicyV04)
			}
			f.Witnesses = map[string]string{}
			porClave := map[string]string{}
			for _, w := range m.Valor.Objeto {
				if w.Nombre == "" {
					return nil, fmt.Errorf("%w: un testigo sin nombre", errPolicyV04)
				}
				if w.Valor.Tipo != 's' || !hexClaveV04(w.Valor.Cadena) {
					return nil, fmt.Errorf("%w: la clave del testigo %q tiene que ser de 64 caracteres hexadecimales en minúsculas", errPolicyV04, w.Nombre)
				}
				if otro, ok := porClave[w.Valor.Cadena]; ok {
					return nil, fmt.Errorf("%w: la misma clave está bajo dos nombres (%q y %q)", errPolicyV04, otro, w.Nombre)
				}
				porClave[w.Valor.Cadena] = w.Nombre
				f.Witnesses[w.Nombre] = w.Valor.Cadena
			}
		case "quorum":
			if m.Valor.Tipo != 'n' {
				return nil, fmt.Errorf("%w: quorum tiene que ser un número entero", errPolicyV04)
			}
			quorum = m.Valor.Numero
		}
	}
	for _, req := range []string{"origin", "logKey", "witnesses", "quorum"} {
		if !tiene[req] {
			return nil, fmt.Errorf("%w: falta el miembro %q", errPolicyV04, req)
		}
	}
	if !enteroNaturalV04(quorum) {
		return nil, fmt.Errorf("%w: quorum %s no es un entero sin fracción ni exponente", errPolicyV04, quorum)
	}
	if len(quorum) > 9 {
		return nil, fmt.Errorf("%w: quorum %s con %d testigos", errPolicyV04, quorum, len(f.Witnesses))
	}
	q, _ := strconv.Atoi(quorum)
	if q < 1 || q > len(f.Witnesses) {
		return nil, fmt.Errorf("%w: quorum %d con %d testigos", errPolicyV04, q, len(f.Witnesses))
	}
	f.Quorum = q
	if err := claveDeSupresionPropiaV04(f); err != nil {
		return nil, err
	}
	return f, nil
}

// claveDeSupresionPropiaV04 exige que la clave de supresión no sea ninguna de las otras
// claves del documento (ADR-032 §B). La del log y la del firmante están en el servidor;
// una política que las nombra como clave de supresión es el hallazgo de ADR-032 escrito
// en un fichero. Y una clave de testigo en dos papeles es una clave en dos papeles.
func claveDeSupresionPropiaV04(f *fileV04) error {
	if f.ErasureKey == "" {
		return nil
	}
	switch f.ErasureKey {
	case f.LogKey:
		return fmt.Errorf("%w: erasureKey es la clave del log; la clave de supresión no puede estar en el servidor", errPolicyV04)
	case f.SignerKey:
		return fmt.Errorf("%w: erasureKey es la clave del firmante; la clave de supresión no puede estar en el servidor", errPolicyV04)
	}
	for n, k := range f.Witnesses {
		if k == f.ErasureKey {
			return fmt.Errorf("%w: erasureKey es la clave del testigo %q", errPolicyV04, n)
		}
	}
	return nil
}

func conocidoV04(nombre string) bool {
	for _, k := range miembrosV04 {
		if nombre == k {
			return true
		}
	}
	return false
}

// enteroNaturalV04: el literal es 0 o un natural sin ceros a la izquierda.
func enteroNaturalV04(s string) bool {
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
