package erasure

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/nucleoledger/nucleo/internal/ledger"
)

// La autorización de una supresión (ADR-032, PROTOCOL §5.1).
//
// Un evento de supresión lo firma la clave del tenant, porque es un bloque de la
// cadena; pero esa clave la abre la passphrase, que vive en el servidor. Así que la
// firma del tenant no dice nada de si la supresión es legítima. Lo dice otra firma: la
// de la CLAVE DE SUPRESIÓN, que no está en el servidor y cuya pública va en la política.
//
// La firma va en el payload_cid del evento, que es parte del header: lo firma el
// tenant, lo fija la hoja y viaja en el recibo. El contenido del evento no cambia —sigue
// siendo determinista, que es lo que permite encontrarlo (ADR-031 §C)—.

// AuthPrefix es el principio del payload_cid de un evento autorizado.
const AuthPrefix = "nucleo-erasure-auth@v1:"

// authMagic es la primera línea del texto que firma la clave de supresión.
const authMagic = "nucleo.org/erasure-authorization@v1"

// ErrNotAuthorized es la causa de todo evento que no está autorizado.
var ErrNotAuthorized = errors.New("supresión no autorizada")

// AuthorizationText es el texto exacto que firma la clave de supresión: el origin del
// log, el contenido que se suprime y hasta qué bloque.
//
// through cierra la repetición: ADR-031 permite volver a sellar un contenido después de
// suprimirlo, y una autorización vieja no puede suprimir la copia nueva sin que la
// custodia lo sepa. Solo cubre los bloques con índice ≤ through.
func AuthorizationText(origin, payloadHash string, through uint64) ([]byte, error) {
	if !esHashHex(payloadHash) {
		return nil, fmt.Errorf("erasure: %q no es un payload_hash (64 hexadecimales en minúsculas)", payloadHash)
	}
	if origin == "" {
		return nil, fmt.Errorf("erasure: la autorización necesita el origin del log")
	}
	if through > ledger.MaxSafeIndex {
		return nil, fmt.Errorf("erasure: through %d supera el índice máximo", through)
	}
	return []byte(authMagic + "\n" +
		"origin " + origin + "\n" +
		"erased_payload_hash " + payloadHash + "\n" +
		"through " + strconv.FormatUint(through, 10) + "\n"), nil
}

// Authorize firma la autorización con la clave de supresión y devuelve el payload_cid
// que llevará el evento. La firma es Ed25519 sobre el SHA-256 del texto, como la de los
// bloques (PROTOCOL §1).
func Authorize(key ed25519.PrivateKey, origin, payloadHash string, through uint64) (string, error) {
	txt, err := AuthorizationText(origin, payloadHash, through)
	if err != nil {
		return "", err
	}
	d := sha256.Sum256(txt)
	return AuthPrefix + strconv.FormatUint(through, 10) + ":" + hex.EncodeToString(ed25519.Sign(key, d[:])), nil
}

// ParseCID lee el payload_cid de un evento: through y la firma. La forma es exacta: sin
// ceros a la izquierda, sin mayúsculas, sin nada de más. Una segunda forma de escribir la
// misma autorización sería una segunda representación de un dato firmado.
func ParseCID(cid string) (through uint64, sig []byte, err error) {
	rest, ok := strings.CutPrefix(cid, AuthPrefix)
	if !ok {
		return 0, nil, fmt.Errorf("%w: el payload_cid %q no lleva una autorización", ErrNotAuthorized, recorta(cid))
	}
	num, firma, ok := strings.Cut(rest, ":")
	if !ok || !decimalCanonico(num) || len(firma) != 2*ed25519.SignatureSize || !hexMinusculas(firma) {
		return 0, nil, fmt.Errorf("%w: el payload_cid %q no tiene la forma %s<through>:<firma>", ErrNotAuthorized, recorta(cid), AuthPrefix)
	}
	through, err = strconv.ParseUint(num, 10, 64)
	if err != nil || through > ledger.MaxSafeIndex {
		return 0, nil, fmt.Errorf("%w: through %s supera el índice máximo", ErrNotAuthorized, num)
	}
	sig, _ = hex.DecodeString(firma) // hexMinusculas ya lo garantizó
	return through, sig, nil
}

// VerifyCID comprueba que el payload_cid lleva una autorización de la clave key para
// suprimir el contenido payloadHash del log origin, y devuelve hasta qué bloque.
func VerifyCID(key ed25519.PublicKey, origin, payloadHash, cid string) (uint64, error) {
	if len(key) != ed25519.PublicKeySize {
		return 0, fmt.Errorf("%w: sin una política con erasureKey no hay contra qué comprobar la autorización", ErrNotAuthorized)
	}
	through, digest, sig, err := leeAutorizacion(origin, payloadHash, cid)
	if err != nil {
		return 0, err
	}
	if !ed25519.Verify(key, digest, sig) {
		return 0, fmt.Errorf("%w: la autorización no verifica con la erasureKey de la política "+
			"(otra clave, otro contenido, otro log u otro through)", ErrNotAuthorized)
	}
	return through, nil
}

// leeAutorizacion lee el payload_cid y devuelve through, el digest del texto que se firmó
// y la firma.
func leeAutorizacion(origin, payloadHash, cid string) (uint64, []byte, []byte, error) {
	through, sig, err := ParseCID(cid)
	if err != nil {
		return 0, nil, nil, err
	}
	txt, err := AuthorizationText(origin, payloadHash, through)
	if err != nil {
		return 0, nil, nil, fmt.Errorf("%w: %w", ErrNotAuthorized, err)
	}
	d := sha256.Sum256(txt)
	return through, d[:], sig, nil
}

// Authority es lo que la política aporta para comprobar autorizaciones: el origin del
// log, la clave de supresión actual y las retiradas con su corte (ADR-032, ADR-033). Sin
// ninguna clave, ningún evento está autorizado.
type Authority struct {
	Origin string
	// Key es la erasureKey, o nil. Autoriza eventos con cualquier índice.
	Key ed25519.PublicKey
	// Retired son las claves retiradas de la política, en hexadecimal, con su corte
	// (ADR-033): cada una autoriza solo los eventos con índice ≤ su corte.
	Retired map[string]uint64
}

// Verdict dice qué clave autorizó un evento y hasta qué bloque cubre su autorización.
type Verdict struct {
	// Through es el último bloque que la autorización cubre.
	Through uint64
	// Key es la clave que verificó, en hexadecimal.
	Key string
	// Retired es true si Key es una clave retirada; Cutoff es entonces su corte.
	Retired bool
	Cutoff  uint64
}

// CutoffError es el motivo de un evento firmado con una clave retirada cuyo corte es menor
// que el índice del evento (ADR-033 §C): la firma es buena y no autoriza nada. Es lo que
// distingue este hallazgo del de una clave ajena, y lo que hace que retirar sirva.
type CutoffError struct {
	Key    string // la clave retirada, en hexadecimal
	Cutoff uint64 // su corte
	Index  uint64 // el índice del evento
}

func (e *CutoffError) Error() string {
	return fmt.Sprintf("%v: firmado con una clave retirada después de su corte %d: la clave %s autoriza "+
		"los eventos hasta el índice %d, y este es el %d", ErrNotAuthorized, e.Cutoff, e.Key, e.Cutoff, e.Index)
}

// Is hace que errors.Is(err, ErrNotAuthorized) siga valiendo.
func (e *CutoffError) Is(target error) bool { return target == ErrNotAuthorized }

// Check decide si el evento ev, que dice suprimir el contenido payloadHash, está
// autorizado (PROTOCOL §5.1), y devuelve qué clave lo autorizó y hasta qué bloque cubre.
// Quien llama aporta payloadHash: el contenido del evento no está en la cadena, y lo da
// un bloque anterior cuyo hash, puesto en el evento, da el payload_hash del evento.
//
// Vale la clave actual, con cualquier índice, y después —en orden de clave— cada retirada
// cuyo corte sea ≥ el índice del evento. Si varias verificaran, se nombra la primera en
// ese orden: el veredicto es el mismo y el informe, determinista.
func (a Authority) Check(ev *ledger.Block, payloadHash string) (Verdict, error) {
	if ev.Header.Type != Type {
		return Verdict{}, fmt.Errorf("%w: el bloque %d no es un evento de supresión", ErrNotAuthorized, ev.Header.Index)
	}
	eph, err := EventPayloadHash(payloadHash)
	if err != nil {
		return Verdict{}, fmt.Errorf("%w: %w", ErrNotAuthorized, err)
	}
	if ev.Header.PayloadHash != eph {
		return Verdict{}, fmt.Errorf("%w: el evento no suprime el contenido %s", ErrNotAuthorized, payloadHash)
	}
	if len(a.Key) != ed25519.PublicKeySize && len(a.Retired) == 0 {
		return Verdict{}, fmt.Errorf("%w: sin una política con erasureKey no hay contra qué comprobar la autorización", ErrNotAuthorized)
	}
	through, digest, sig, err := leeAutorizacion(a.Origin, payloadHash, ev.Header.PayloadCID)
	if err != nil {
		return Verdict{}, err
	}
	idx := ev.Header.Index
	v, ok := Verdict{}, false
	if len(a.Key) == ed25519.PublicKeySize && ed25519.Verify(a.Key, digest, sig) {
		v, ok = Verdict{Through: through, Key: hex.EncodeToString(a.Key)}, true
	}
	var fueraDeCorte *CutoffError
	for _, k := range a.retiradas() {
		if ok {
			break
		}
		pub, err := hex.DecodeString(k)
		if err != nil || len(pub) != ed25519.PublicKeySize || !ed25519.Verify(pub, digest, sig) {
			continue
		}
		c := a.Retired[k]
		if idx <= c {
			v, ok = Verdict{Through: through, Key: k, Retired: true, Cutoff: c}, true
		} else if fueraDeCorte == nil {
			fueraDeCorte = &CutoffError{Key: k, Cutoff: c, Index: idx}
		}
	}
	switch {
	case ok:
	case fueraDeCorte != nil:
		return Verdict{}, fueraDeCorte
	case len(a.Retired) == 0:
		// El mensaje de siempre: con una política 0.7-draft, nada cambia.
		return Verdict{}, fmt.Errorf("%w: la autorización no verifica con la erasureKey de la política "+
			"(otra clave, otro contenido, otro log u otro through)", ErrNotAuthorized)
	case len(a.Key) != ed25519.PublicKeySize:
		return Verdict{}, fmt.Errorf("%w: la autorización no verifica con ninguna clave retirada de la política, "+
			"y la política no trae erasureKey (otra clave, otro contenido, otro log u otro through)", ErrNotAuthorized)
	default:
		return Verdict{}, fmt.Errorf("%w: la autorización no verifica con ninguna clave de la política, ni la "+
			"erasureKey ni las retiradas (otra clave, otro contenido, otro log u otro through)", ErrNotAuthorized)
	}
	if through >= idx {
		return Verdict{}, fmt.Errorf("%w: through %d no es anterior al evento (bloque %d)", ErrNotAuthorized, through, idx)
	}
	return v, nil
}

// retiradas devuelve las claves retiradas en orden.
func (a Authority) retiradas() []string {
	ks := make([]string, 0, len(a.Retired))
	for k := range a.Retired {
		ks = append(ks, k)
	}
	slices.Sort(ks)
	return ks
}

func decimalCanonico(s string) bool {
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

func hexMinusculas(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// recorta acorta un payload_cid para un mensaje: viene de la cadena, y su longitud no
// la decide quien lee el mensaje.
func recorta(s string) string {
	const n = 48
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
