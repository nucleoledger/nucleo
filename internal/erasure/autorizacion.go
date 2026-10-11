package erasure

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
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
	through, sig, err := ParseCID(cid)
	if err != nil {
		return 0, err
	}
	txt, err := AuthorizationText(origin, payloadHash, through)
	if err != nil {
		return 0, fmt.Errorf("%w: %w", ErrNotAuthorized, err)
	}
	d := sha256.Sum256(txt)
	if !ed25519.Verify(key, d[:], sig) {
		return 0, fmt.Errorf("%w: la autorización no verifica con la erasureKey de la política "+
			"(otra clave, otro contenido, otro log u otro through)", ErrNotAuthorized)
	}
	return through, nil
}

// Authority es lo que la política aporta para comprobar autorizaciones: el origin del
// log y la clave de supresión. Sin clave, ningún evento está autorizado.
type Authority struct {
	Origin string
	Key    ed25519.PublicKey
}

// Check decide si el evento ev, que dice suprimir el contenido payloadHash, está
// autorizado (PROTOCOL §5.1), y devuelve hasta qué bloque cubre. Quien llama aporta
// payloadHash: el contenido del evento no está en la cadena, y lo da un bloque anterior
// cuyo hash, puesto en el evento, da el payload_hash del evento.
func (a Authority) Check(ev *ledger.Block, payloadHash string) (uint64, error) {
	if ev.Header.Type != Type {
		return 0, fmt.Errorf("%w: el bloque %d no es un evento de supresión", ErrNotAuthorized, ev.Header.Index)
	}
	eph, err := EventPayloadHash(payloadHash)
	if err != nil {
		return 0, fmt.Errorf("%w: %w", ErrNotAuthorized, err)
	}
	if ev.Header.PayloadHash != eph {
		return 0, fmt.Errorf("%w: el evento no suprime el contenido %s", ErrNotAuthorized, payloadHash)
	}
	through, err := VerifyCID(a.Key, a.Origin, payloadHash, ev.Header.PayloadCID)
	if err != nil {
		return 0, err
	}
	if through >= ev.Header.Index {
		return 0, fmt.Errorf("%w: through %d no es anterior al evento (bloque %d)", ErrNotAuthorized, through, ev.Header.Index)
	}
	return through, nil
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
