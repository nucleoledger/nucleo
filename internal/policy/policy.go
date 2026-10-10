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
	"strconv"

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
	Witnesses map[string]string
	Quorum    int
}

// miembros son los únicos nombres de miembro válidos del objeto de primer nivel.
var miembros = []string{"origin", "logKey", "signerKey", "witnesses", "quorum"}

// Parse lee y valida un documento de política. Cualquier desviación de PROTOCOL.md
// §3.2 es error: no hay reparaciones ni valores por omisión.
func Parse(raw []byte) (*File, error) {
	obj, err := estricto.Leer(raw, estricto.Opciones{
		Error:       ErrPolicy,
		Max:         MaxSize,
		Profundidad: 2, // el documento y, debajo, el objeto de testigos
		MsgAnidado:  "objeto anidado donde la política no admite ninguno",
		MsgValor:    "valor no admitido en una política (solo cadenas, números y el objeto de testigos)",
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
					return nil, fmt.Errorf("%w: el miembro %q es una variante de mayúsculas de %q", ErrPolicy, m.Nombre, k)
				}
			}
			return nil, fmt.Errorf("%w: miembro desconocido %q", ErrPolicy, m.Nombre)
		}
		tiene[m.Nombre] = true
		switch m.Nombre {
		case "origin":
			if m.Valor.Tipo != 's' || m.Valor.Cadena == "" {
				return nil, fmt.Errorf("%w: origin tiene que ser una cadena no vacía", ErrPolicy)
			}
			f.Origin = m.Valor.Cadena
		case "logKey", "signerKey":
			if m.Valor.Tipo != 's' || !estricto.HexClave(m.Valor.Cadena) {
				return nil, fmt.Errorf("%w: %s tiene que ser una clave de 64 caracteres hexadecimales en minúsculas", ErrPolicy, m.Nombre)
			}
			if m.Nombre == "logKey" {
				f.LogKey = m.Valor.Cadena
			} else {
				f.SignerKey = m.Valor.Cadena
			}
		case "witnesses":
			if m.Valor.Tipo != 'o' {
				return nil, fmt.Errorf("%w: witnesses tiene que ser un objeto", ErrPolicy)
			}
			if len(m.Valor.Objeto) == 0 {
				return nil, fmt.Errorf("%w: no trae ningún testigo; sin testigos no verifica nada", ErrPolicy)
			}
			f.Witnesses = map[string]string{}
			porClave := map[string]string{}
			for _, w := range m.Valor.Objeto {
				if w.Nombre == "" {
					return nil, fmt.Errorf("%w: un testigo sin nombre", ErrPolicy)
				}
				if w.Valor.Tipo != 's' || !estricto.HexClave(w.Valor.Cadena) {
					return nil, fmt.Errorf("%w: la clave del testigo %q tiene que ser de 64 caracteres hexadecimales en minúsculas", ErrPolicy, w.Nombre)
				}
				if otro, ok := porClave[w.Valor.Cadena]; ok {
					return nil, fmt.Errorf("%w: la misma clave está bajo dos nombres (%q y %q)", ErrPolicy, otro, w.Nombre)
				}
				porClave[w.Valor.Cadena] = w.Nombre
				f.Witnesses[w.Nombre] = w.Valor.Cadena
			}
		case "quorum":
			if m.Valor.Tipo != 'n' {
				return nil, fmt.Errorf("%w: quorum tiene que ser un número entero", ErrPolicy)
			}
			quorum = m.Valor.Numero
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
