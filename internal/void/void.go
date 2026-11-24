// Package void define el evento de anulación (ADR-035, PROTOCOL 0.9-draft §5.2).
//
// Anular no es suprimir. Una factura anulada no se borra: el SRI la marca «ANULADO», el
// emisor la conserva siete años y su emisión tiene que seguir verificable. Así que anular
// no toca el bloque de la emisión: sella uno más después, el evento, que dice «el emisor
// declara anulada la emisión del bloque i». Es la DECLARACIÓN del emisor, no el estado del
// SRI (L24 de GARANTIAS), y no disculpa ningún hallazgo de la reconciliación: por eso basta
// la firma del tenant, sin la clave de supresión.
//
// El contenido del evento son dos datos que ya son públicos en la cadena, el índice y el
// payload_hash del bloque anulado, en JCS. Es determinista, sin campo aleatorio (la segunda
// excepción de PROTOCOL §5): no oculta nada, y así se reconstruye en vez de guardarse. Su
// payload_cid repite el índice, nucleo-void@v1:<i>, para que el recibo del evento diga solo
// a qué apunta. La clave de acceso de la factura no va nunca, ni en claro ni como hash: solo
// 8 de sus 49 dígitos son desconocidos (ADR-035, decisión 2).
package void

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	"github.com/nucleoledger/nucleo/internal/jcs"
	"github.com/nucleoledger/nucleo/internal/ledger"
)

// Type es el tipo de registro de los eventos de anulación. Va bajo el prefijo reservado
// nucleo. (erasure.ReservedPrefix): un integrador no lo puede sellar con seal.
const Type = "nucleo.void.v1"

// CIDPrefix es el principio del payload_cid de un evento de anulación.
const CIDPrefix = "nucleo-void@v1:"

// Payload devuelve el contenido del evento que anula el bloque index, cuyo payload_hash
// es payloadHash: {"voided_index":"<i>","voided_payload_hash":"<h>"} en JCS (RFC 8785).
// El índice va como cadena, como manda PROTOCOL §5 para los identificadores.
func Payload(index uint64, payloadHash string) ([]byte, error) {
	if index > ledger.MaxSafeIndex {
		return nil, fmt.Errorf("void: el índice %d supera el máximo (2^53 − 1)", index)
	}
	if !esHashHex(payloadHash) {
		return nil, fmt.Errorf("void: %q no es un payload_hash (64 hexadecimales en minúsculas)", payloadHash)
	}
	return jcs.Marshal(map[string]string{
		"voided_index":        strconv.FormatUint(index, 10),
		"voided_payload_hash": payloadHash,
	})
}

// EventPayloadHash es el payload_hash que lleva el evento que anula el bloque index.
func EventPayloadHash(index uint64, payloadHash string) (string, error) {
	p, err := Payload(index, payloadHash)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(p)
	return hex.EncodeToString(sum[:]), nil
}

// CID es el payload_cid del evento que anula el bloque index.
func CID(index uint64) string {
	return CIDPrefix + strconv.FormatUint(index, 10)
}

// ParseCID lee el índice de un payload_cid de anulación. La forma es exacta (R1): el
// prefijo y un decimal sin signo, sin ceros a la izquierda y como mucho 2^53 − 1; nada
// antes ni después. Una segunda forma de escribir el mismo índice sería una segunda
// representación de un dato firmado.
func ParseCID(cid string) (uint64, error) {
	num, ok := strings.CutPrefix(cid, CIDPrefix)
	if !ok || !decimalCanonico(num) {
		return 0, fmt.Errorf("void: el payload_cid %q no tiene la forma %s<índice>", recorta(cid), CIDPrefix)
	}
	// Con 17 cifras o más ya no cabe; ParseUint con 64 bits detecta el resto.
	i, err := strconv.ParseUint(num, 10, 64)
	if err != nil || i > ledger.MaxSafeIndex {
		return 0, fmt.Errorf("void: el índice del payload_cid %q supera el máximo (2^53 − 1)", recorta(cid))
	}
	return i, nil
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

func esHashHex(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// recorta acorta un payload_cid ajeno para un mensaje: viene de la cadena, y la cadena la
// puede haber escrito cualquiera con la clave del tenant.
func recorta(s string) string {
	if len(s) > 80 {
		return s[:80] + "…"
	}
	return s
}
