// Package commit implementa los compromisos de PROTOCOL.md §5 y ADR-003 en su
// vía interna: HMAC-SHA-256 con una clave por tenant derivada de la DEK.
//
// # Por qué no basta con un hash
//
// Un hash desnudo de un dato adivinable no oculta nada. Una cédula ecuatoriana
// tiene 10 dígitos: son diez mil millones de combinaciones, y con la estructura
// del número —provincia, tercer dígito, dígito verificador— quedan bastantes
// menos. Un atacante con el hash prueba el espacio entero en minutos y sabe de
// quién era. Lo mismo vale para un importe, un RUC o un estado: el conjunto de
// valores posibles es pequeño y el hash es una función pública.
//
// Un HMAC con clave cambia el problema por completo. Sin la clave, el
// diccionario no sirve: probar "1712345678" no produce nada comparable, porque
// el atacante no puede computar HMAC(k, "1712345678") sin k. Con la clave, el
// tenant y quien él autorice pueden comprobar que un valor concreto es el
// comprometido.
//
// # Lo que esto NO da
//
// Un tercero SIN la clave no puede verificar nada: solo puede constatar que hay
// un compromiso. Para que un auditor compruebe el compromiso de una cédula sin
// conocer la clave del tenant hace falta un VRF, que es la otra vía de ADR-003
// y no está implementada. Ver ADR-012.
package commit

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

// Alg identifica el esquema y su versión. Viaja con el compromiso porque el día
// que entre el VRF habrá dos, y un compromiso sin decir de qué tipo es obliga a
// adivinar.
const Alg = "hmac-sha256/v1"

// KeySize es el tamaño de la clave de compromisos.
const KeySize = 32

// hkdfSalt y el prefijo de info separan esta derivación de cualquier otra que
// se haga con la misma DEK. Sin separación de dominio, una clave derivada para
// compromisos podría coincidir con otra derivada para otra cosa.
const (
	hkdfInfoPrefix = "nucleo/commit/hmac-sha256/v1"
)

var (
	// ErrKey indica una clave de tamaño incorrecto.
	ErrKey = errors.New("commit: clave de compromisos inválida")
	// ErrFormat indica un compromiso mal formado.
	ErrFormat = errors.New("commit: compromiso mal formado")
)

// DeriveKey obtiene la clave de compromisos de un tenant a partir de la DEK del
// vault, con HKDF-SHA-256.
//
// Se deriva y no se reutiliza la DEK directamente por el motivo de siempre: una
// clave, un uso. La DEK cifra blobs; si además calculara compromisos, un fallo
// en cualquiera de los dos usos comprometería el otro. HKDF cuesta un par de
// microsegundos y elimina esa dependencia.
//
// El tenant entra en el `info`, así que dos tenants del mismo vault obtienen
// claves distintas: el compromiso de una cédula para un tenant no es igual al
// de la misma cédula para otro, y comparar los ledgers no revela coincidencias.
func DeriveKey(dek []byte, tenant string) ([]byte, error) {
	if len(dek) == 0 {
		return nil, fmt.Errorf("%w: DEK vacía", ErrKey)
	}
	if tenant == "" {
		return nil, fmt.Errorf("%w: tenant vacío", ErrKey)
	}
	info := append([]byte(hkdfInfoPrefix+"\x00"), tenant...)
	r := hkdf.New(sha256.New, dek, nil, info)
	key := make([]byte, KeySize)
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, fmt.Errorf("commit: derivación de clave: %w", err)
	}
	return key, nil
}

// CommitField calcula el compromiso de un valor para un campo concreto.
//
// El nombre del campo entra en el mensaje autenticado, no solo el valor. Sin
// eso, el compromiso de la cédula "1712345678" y el de un número de orden
// "1712345678" serían idénticos, y quien viera los dos sabría que coinciden
// aunque signifiquen cosas distintas.
func CommitField(key []byte, field, value string) (string, error) {
	if len(key) != KeySize {
		return "", fmt.Errorf("%w: %d bytes, se esperaban %d", ErrKey, len(key), KeySize)
	}
	if field == "" {
		return "", fmt.Errorf("%w: nombre de campo vacío", ErrFormat)
	}
	m := hmac.New(sha256.New, key)
	m.Write([]byte(field))
	m.Write([]byte{0x00})
	m.Write([]byte(value))
	return Alg + ":" + hex.EncodeToString(m.Sum(nil)), nil
}

// VerifyField comprueba que un valor sea el comprometido.
//
// La comparación es de tiempo constante. Un compromiso no es un secreto, pero
// comparar con == permitiría, en un servicio que verifique valores propuestos,
// medir cuántos bytes acertó cada intento.
func VerifyField(key []byte, field, value, commitment string) bool {
	want, err := CommitField(key, field, value)
	if err != nil {
		return false
	}
	return hmac.Equal([]byte(want), []byte(commitment))
}

// Raw devuelve los 32 bytes del compromiso, sin el prefijo del algoritmo.
func Raw(commitment string) ([]byte, error) {
	prefix := Alg + ":"
	if len(commitment) <= len(prefix) || commitment[:len(prefix)] != prefix {
		return nil, fmt.Errorf("%w: no empieza por %q", ErrFormat, prefix)
	}
	raw, err := hex.DecodeString(commitment[len(prefix):])
	if err != nil || len(raw) != sha256.Size {
		return nil, fmt.Errorf("%w: %q", ErrFormat, commitment)
	}
	return raw, nil
}
