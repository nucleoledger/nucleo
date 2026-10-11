// Package erasure define el evento de supresión (ADR-031).
//
// Suprimir es borrar el contenido de un registro —su copia cifrada y sus
// compromisos— y dejar la cadena intacta. Lo que no puede ser es que el contenido
// desaparezca sin rastro: entonces la reconciliación vería un registro que falta y
// no podría distinguir un borrado legítimo de uno que alguien quiere esconder. Por
// eso cada supresión sella un bloque más, el evento, cuyo contenido es solo el hash
// del contenido suprimido: nada que no estuviera ya en la cadena.
//
// El contenido del evento no se guarda, porque no hace falta: se reconstruye a partir
// del hash suprimido. Su payload_cid no apunta a ningún contenido: lleva la autorización
// de la clave de supresión, con la forma exacta nucleo-erasure-auth@v1:<through>:<firma>
// (ADR-032, PROTOCOL 0.7-draft §5.1; ver autorizacion.go). Quien quiera saber si
// el contenido H de un bloque se suprimió calcula EventPayloadHash(H) y busca un
// bloque posterior de tipo Type con ese payload_hash. Lo hace la reconciliación sin
// abrir el vault, y lo puede hacer un tercero con el recibo del evento.
package erasure

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/nucleoledger/nucleo/internal/jcs"
)

// Type es el tipo de registro de los eventos de supresión.
const Type = "nucleo.erasure.v1"

// ReservedPrefix es el prefijo de los tipos que sella Núcleo por su cuenta. Un
// integrador no puede sellar un registro con ese tipo: un evento de supresión
// falsificado haría pasar un registro desaparecido por uno suprimido.
const ReservedPrefix = "nucleo."

// Reserved dice si un tipo de registro está reservado a Núcleo.
func Reserved(typ string) bool {
	return strings.HasPrefix(typ, ReservedPrefix)
}

// Payload devuelve el contenido del evento que suprime el contenido payloadHash:
// el objeto {"erased_payload_hash": "<hash>"} en JCS (RFC 8785).
func Payload(payloadHash string) ([]byte, error) {
	if !esHashHex(payloadHash) {
		return nil, fmt.Errorf("erasure: %q no es un payload_hash (64 hexadecimales en minúsculas)", payloadHash)
	}
	return jcs.Marshal(map[string]string{"erased_payload_hash": payloadHash})
}

// EventPayloadHash es el payload_hash que lleva el evento que suprime payloadHash.
func EventPayloadHash(payloadHash string) (string, error) {
	p, err := Payload(payloadHash)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(p)
	return hex.EncodeToString(sum[:]), nil
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
