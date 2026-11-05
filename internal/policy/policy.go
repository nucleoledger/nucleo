// Package policy lee el fichero de política de verificación: el formato de cable de
// PROTOCOL.md §3.2 (ADR-018).
//
// La política es lo único en lo que confía quien verifica (ADR-017), y la CLI, el
// SDK de TypeScript y la página tienen que aceptar y rechazar exactamente los mismos
// documentos. La tercera auditoría enseñó por qué eso no se consigue con
// encoding/json: `{"signerKey": A, "signerkey": B}` le daba B a la CLI —empareja
// claves sin distinguir mayúsculas y gana la última— y A a la página. Cuando
// Unmarshal devuelve, el duplicado ya se ha perdido. Por eso aquí hay un lector
// propio, pequeño, que implementa la gramática de PROTOCOL.md literalmente
// (internal/estricto, compartido con la configuración del testigo), y su gemelo en
// sdk/ts/src/policy.ts. Los dos pasan por testdata/vectors/policy/ y por
// el diferencial.
package policy

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strconv"

	"github.com/nucleoledger/nucleo/internal/erasure"
	"github.com/nucleoledger/nucleo/internal/estricto"
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
	// ErasureKey es la clave que autoriza las supresiones (ADR-032), o "". No está en el
	// servidor: por eso no puede ser ninguna de las otras claves del documento.
	ErasureKey string
	// RetiredErasureKeys son las claves de supresión retiradas, cada una con su corte: el
	// índice del último evento de supresión que todavía autoriza (ADR-033, PROTOCOL
	// 0.8-draft §3.2). nil si el documento no trae el miembro; si lo trae, no está vacío.
	RetiredErasureKeys map[string]uint64
	// LogMLDSAKey es la clave pública ML-DSA-44 del log, 2624 hexadecimales, o "" (ADR-034).
	// Este paquete la lee y la guarda; quien la coteja y la usa es otro (Sprint C2).
	LogMLDSAKey string
	Witnesses   map[string]string
	Quorum      int
}

// miembros son los únicos nombres de miembro válidos del objeto de primer nivel.
var miembros = []string{"origin", "logKey", "signerKey", "erasureKey", "retiredErasureKeys", "logMLDSAKey", "witnesses", "quorum"}

// MaxCutoff es el mayor corte de una clave retirada: 2^53 − 1, el índice máximo (PROTOCOL §1).
const MaxCutoff = 1<<53 - 1

// largoMLDSA es la longitud en hexadecimal de una clave pública ML-DSA-44: 1312 bytes.
const largoMLDSA = 2 * 1312

// Error es un rechazo de la tabla de §3.2, con su motivo. Envuelve ErrPolicy.
type Error struct {
	// Motivo es el nombre del motivo, el mismo que el "reason" de los vectores de
	// testdata/vectors/policy/.
	Motivo string
	msg    string
}

func (e *Error) Error() string { return ErrPolicy.Error() + ": " + e.msg }

func (e *Error) Unwrap() error { return ErrPolicy }

// rechazo es un *Error con el motivo dado.
func rechazo(motivo, format string, args ...any) error {
	return &Error{Motivo: motivo, msg: fmt.Sprintf(format, args...)}
}

// Motivo devuelve el nombre del motivo por el que Parse rechazó un documento: el de la
// tabla de §3.2, o el de la gramática si la rechazó el lector. Los nombres son los del
// campo "reason" de los vectores. "" si err no es un rechazo de Parse.
//
// El lector da el mismo mensaje a un null, un booleano, un array o un objeto demasiado
// hondo, y por eso su error lleva la clase y la ruta: lo que está mal en origin, en
// quorum o en un corte es de ese miembro, sea del tipo que sea; en lo demás, un null es
// un null y el resto es un tipo equivocado. Es la regla con la que están escritos los
// vectores.
func Motivo(err error) string {
	var pe *Error
	if errors.As(err, &pe) {
		return pe.Motivo
	}
	ee := estricto.Como(err)
	if ee == nil || !errors.Is(err, ErrPolicy) {
		return ""
	}
	switch ee.Clase {
	case estricto.ClaseTamano:
		return "size"
	case estricto.ClaseBOM:
		return "bom"
	case estricto.ClaseNoObjeto:
		return "type"
	case estricto.ClaseDetras:
		return "trailing"
	case estricto.ClaseRepetido:
		return "duplicate_member"
	case estricto.ClaseSurrogate:
		return "surrogate"
	case estricto.ClaseNumero:
		// Un número mal escrito es del miembro que lo lleva, si ese miembro es un número.
		switch {
		case len(ee.Ruta) > 0 && ee.Ruta[0] == "quorum":
			return "quorum"
		case len(ee.Ruta) == 2 && ee.Ruta[0] == "retiredErasureKeys":
			return "cutoff"
		}
		return "syntax"
	case estricto.ClaseNull, estricto.ClaseBooleano, estricto.ClaseArray, estricto.ClaseAnidado:
		switch {
		case len(ee.Ruta) > 0 && ee.Ruta[0] == "origin":
			return "origin"
		case len(ee.Ruta) > 0 && ee.Ruta[0] == "quorum":
			return "quorum"
		case len(ee.Ruta) == 2 && ee.Ruta[0] == "retiredErasureKeys":
			return "cutoff"
		case ee.Clase == estricto.ClaseNull:
			return "null"
		}
		return "type"
	}
	return "syntax"
}

// Parse lee y valida un documento de política. Cualquier desviación de PROTOCOL.md
// §3.2 es error: no hay reparaciones ni valores por omisión.
func Parse(raw []byte) (*File, error) {
	obj, err := estricto.Leer(raw, estricto.Opciones{
		Error:       ErrPolicy,
		Max:         MaxSize,
		Profundidad: 2, // el documento y, debajo, los objetos de testigos y de claves retiradas
		MsgAnidado:  "objeto anidado donde la política no admite ninguno",
		MsgValor:    "valor no admitido en una política (solo cadenas, números y los objetos de testigos y de claves retiradas)",
	})
	if err != nil {
		return nil, err
	}
	return construir(obj)
}

// construir aplica la tabla de PROTOCOL.md §3.2 al objeto ya leído.
func construir(obj []estricto.Miembro) (*File, error) {
	f := &File{}
	var tiene = map[string]bool{}
	var quorum string
	for _, m := range obj {
		if !conocido(m.Nombre) {
			for _, k := range miembros {
				if estricto.AsciiIgual(m.Nombre, k) {
					return nil, rechazo("case_variant", "el miembro %q es una variante de mayúsculas de %q", m.Nombre, k)
				}
			}
			return nil, rechazo("unknown_member", "miembro desconocido %q", m.Nombre)
		}
		tiene[m.Nombre] = true
		switch m.Nombre {
		case "origin":
			if m.Valor.Tipo != 's' || m.Valor.Cadena == "" {
				return nil, rechazo("origin", "origin tiene que ser una cadena no vacía")
			}
			f.Origin = m.Valor.Cadena
		case "logKey", "signerKey", "erasureKey":
			if m.Valor.Tipo != 's' || !estricto.HexClave(m.Valor.Cadena) {
				return nil, rechazo(motivoDeClave(m.Valor), "%s tiene que ser una clave de 64 caracteres hexadecimales en minúsculas", m.Nombre)
			}
			switch m.Nombre {
			case "logKey":
				f.LogKey = m.Valor.Cadena
			case "signerKey":
				f.SignerKey = m.Valor.Cadena
			default:
				f.ErasureKey = m.Valor.Cadena
			}
		case "retiredErasureKeys":
			r, err := clavesRetiradas(m.Valor)
			if err != nil {
				return nil, err
			}
			f.RetiredErasureKeys = r
		case "logMLDSAKey":
			if m.Valor.Tipo != 's' || len(m.Valor.Cadena) != largoMLDSA || !hexMinusculas(m.Valor.Cadena) {
				return nil, rechazo(motivoDeClave(m.Valor), "logMLDSAKey tiene que ser la clave pública ML-DSA-44 del log: %d caracteres hexadecimales en minúsculas", largoMLDSA)
			}
			f.LogMLDSAKey = m.Valor.Cadena
		case "witnesses":
			if m.Valor.Tipo != 'o' {
				return nil, rechazo("type", "witnesses tiene que ser un objeto")
			}
			if len(m.Valor.Objeto) == 0 {
				return nil, rechazo("no_witnesses", "no trae ningún testigo; sin testigos no verifica nada")
			}
			f.Witnesses = map[string]string{}
			porClave := map[string]string{}
			for _, w := range m.Valor.Objeto {
				if w.Nombre == "" {
					return nil, rechazo("witness_name", "un testigo sin nombre")
				}
				if w.Valor.Tipo != 's' || !estricto.HexClave(w.Valor.Cadena) {
					return nil, rechazo(motivoDeClave(w.Valor), "la clave del testigo %q tiene que ser de 64 caracteres hexadecimales en minúsculas", w.Nombre)
				}
				if otro, ok := porClave[w.Valor.Cadena]; ok {
					return nil, rechazo("duplicate_key", "la misma clave está bajo dos nombres (%q y %q)", otro, w.Nombre)
				}
				porClave[w.Valor.Cadena] = w.Nombre
				f.Witnesses[w.Nombre] = w.Valor.Cadena
			}
		case "quorum":
			if m.Valor.Tipo != 'n' {
				return nil, rechazo("quorum", "quorum tiene que ser un número entero")
			}
			quorum = m.Valor.Numero
		}
	}
	for _, req := range []string{"origin", "logKey", "witnesses", "quorum"} {
		if !tiene[req] {
			return nil, rechazo("missing", "falta el miembro %q", req)
		}
	}
	if !enteroNatural(quorum) {
		return nil, rechazo("quorum", "quorum %s no es un entero sin fracción ni exponente", quorum)
	}
	if len(quorum) > 9 {
		return nil, rechazo("quorum", "quorum %s con %d testigos", quorum, len(f.Witnesses))
	}
	q, _ := strconv.Atoi(quorum)
	if q < 1 || q > len(f.Witnesses) {
		return nil, rechazo("quorum", "quorum %d con %d testigos", q, len(f.Witnesses))
	}
	f.Quorum = q
	if err := claveDeSupresionPropia(f); err != nil {
		return nil, err
	}
	if err := clavesRetiradasPropias(f); err != nil {
		return nil, err
	}
	return f, nil
}

// motivoDeClave es el motivo de un valor que tenía que ser una clave en hexadecimal: un
// objeto es otro tipo; un número o una cadena que no es la clave, una clave mal escrita.
// (El null, el booleano y el array los rechaza antes el lector.)
func motivoDeClave(v estricto.Valor) string {
	if v.Tipo == 'o' {
		return "type"
	}
	return "hex"
}

// clavesRetiradas lee retiredErasureKeys (ADR-033 §A): un objeto con al menos un miembro;
// cada nombre, una clave Ed25519 en hexadecimal en minúsculas; cada valor, su corte. Una
// clave repetida ya la rechazó el lector: es un nombre repetido.
func clavesRetiradas(v estricto.Valor) (map[string]uint64, error) {
	if v.Tipo != 'o' {
		return nil, rechazo("type", "retiredErasureKeys tiene que ser un objeto {clave: corte}")
	}
	if len(v.Objeto) == 0 {
		return nil, rechazo("no_retired_keys", "retiredErasureKeys vacío: significaría lo mismo que no ponerlo; quítalo")
	}
	out := make(map[string]uint64, len(v.Objeto))
	for _, m := range v.Objeto {
		if !estricto.HexClave(m.Nombre) {
			return nil, rechazo("hex", "la clave retirada %q tiene que ser de 64 caracteres hexadecimales en minúsculas", recorta(m.Nombre))
		}
		if m.Valor.Tipo != 'n' {
			return nil, rechazo("cutoff", "el corte de la clave retirada %s… tiene que ser un número entero", m.Nombre[:16])
		}
		c, ok := corte(m.Valor.Numero)
		if !ok {
			return nil, rechazo("cutoff", "el corte %s de la clave retirada %s… no es un entero sin signo, sin fracción ni exponente, de como mucho 2^53 − 1",
				recorta(m.Valor.Numero), m.Nombre[:16])
		}
		out[m.Nombre] = c
	}
	return out, nil
}

// corte lee el corte de una clave retirada: el literal 0|[1-9][0-9]*, sin signo —ni
// «-0»—, sin fracción, sin exponente, como mucho 2^53 − 1. La gramática de quorum
// admite signo; esta no, y por eso no comparte función con ella más que enteroNatural,
// que tampoco lo admite.
func corte(s string) (uint64, bool) {
	if !enteroNatural(s) || len(s) > 16 {
		return 0, false
	}
	c, err := strconv.ParseUint(s, 10, 64)
	if err != nil || c > MaxCutoff {
		return 0, false
	}
	return c, true
}

// clavesRetiradasPropias es la regla de separación de las claves retiradas (ADR-033 §A):
// ninguna puede ser la erasureKey —¿retirada o actual?—, la del log, la del firmante ni la
// de un testigo. Vale también sin erasureKey. La que firma los bloques solo se ve al abrir
// el ledger (la comprueba quien abre).
func clavesRetiradasPropias(f *File) error {
	for _, k := range f.RetiredKeys() {
		switch k {
		case f.ErasureKey:
			return rechazo("erasure_key_reused", "la clave retirada %s… es la erasureKey: una clave no puede estar retirada y ser la actual", k[:16])
		case f.LogKey:
			return rechazo("erasure_key_reused", "la clave retirada %s… es la clave del log; una clave de supresión no puede estar en el servidor", k[:16])
		case f.SignerKey:
			return rechazo("erasure_key_reused", "la clave retirada %s… es la clave del firmante; una clave de supresión no puede estar en el servidor", k[:16])
		}
		for _, n := range nombresDeTestigos(f) {
			if f.Witnesses[n] == k {
				return rechazo("erasure_key_reused", "la clave retirada %s… es la clave del testigo %q", k[:16], n)
			}
		}
	}
	return nil
}

// RetiredKeys devuelve las claves retiradas en orden, para recorrerlas siempre igual.
func (f *File) RetiredKeys() []string {
	ks := make([]string, 0, len(f.RetiredErasureKeys))
	for k := range f.RetiredErasureKeys {
		ks = append(ks, k)
	}
	slices.Sort(ks)
	return ks
}

func nombresDeTestigos(f *File) []string {
	ns := make([]string, 0, len(f.Witnesses))
	for n := range f.Witnesses {
		ns = append(ns, n)
	}
	slices.Sort(ns)
	return ns
}

func hexMinusculas(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// recorta acorta un valor del documento para un mensaje.
func recorta(s string) string {
	if len(s) <= 24 {
		return s
	}
	return s[:24] + "…"
}

// claveDeSupresionPropia exige que la clave de supresión no sea ninguna de las otras
// claves del documento (ADR-032 §B). La del log y la del firmante están en el servidor;
// una política que las nombra como clave de supresión es el hallazgo de ADR-032 escrito
// en un fichero. Y una clave de testigo en dos papeles es una clave en dos papeles.
func claveDeSupresionPropia(f *File) error {
	if f.ErasureKey == "" {
		return nil
	}
	switch f.ErasureKey {
	case f.LogKey:
		return rechazo("erasure_key_reused", "erasureKey es la clave del log; la clave de supresión no puede estar en el servidor")
	case f.SignerKey:
		return rechazo("erasure_key_reused", "erasureKey es la clave del firmante; la clave de supresión no puede estar en el servidor")
	}
	for _, n := range nombresDeTestigos(f) {
		if f.Witnesses[n] == f.ErasureKey {
			return rechazo("erasure_key_reused", "erasureKey es la clave del testigo %q", n)
		}
	}
	return nil
}

// ErasureAuthority devuelve lo que la política aporta para decidir si una supresión está
// autorizada: el origin, la clave de supresión actual —nil si no la trae— y las retiradas
// con su corte (ADR-032 §D, ADR-033 §C). Sin ninguna clave, ninguna supresión cuenta.
func (f *File) ErasureAuthority() erasure.Authority {
	if f == nil || (f.ErasureKey == "" && len(f.RetiredErasureKeys) == 0) {
		return erasure.Authority{}
	}
	a := erasure.Authority{Origin: f.Origin}
	if f.ErasureKey != "" {
		a.Key = clave(f.ErasureKey)
	}
	if len(f.RetiredErasureKeys) > 0 {
		a.Retired = make(map[string]uint64, len(f.RetiredErasureKeys))
		for k, c := range f.RetiredErasureKeys {
			a.Retired[k] = c
		}
	}
	return a
}

func conocido(nombre string) bool {
	for _, k := range miembros {
		if nombre == k {
			return true
		}
	}
	return false
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
	if f.ErasureKey != "" {
		wp.ErasureKey = clave(f.ErasureKey)
	}
	for _, k := range f.RetiredKeys() {
		wp.RetiredErasureKeys = append(wp.RetiredErasureKeys, clave(k))
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
