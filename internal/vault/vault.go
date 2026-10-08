// Package vault implementa la jerarquía de claves en reposo de PROTOCOL.md §6:
// passphrase → Argon2id → KEK, y una DEK aleatoria por vault envuelta bajo esa
// KEK. Los payloads sensibles se cifran con XChaCha20-Poly1305 y viven fuera del
// ledger, en blobs borrables (PROTOCOL.md §5).
//
// La propiedad que sostiene el modelo: borrar el blob y su clave satisface el
// derecho de supresión sin tocar la cadena. El compromiso —el payload_hash que
// demuestra qué se selló y cuándo— sigue en el ledger, y las pruebas de
// inclusión siguen verificando. El dato desaparece; la prueba de que existió, no.
package vault

import (
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

var (
	// ErrParams indica parámetros de derivación inválidos.
	ErrParams = errors.New("vault: parámetros de derivación inválidos")
	// ErrUnwrap indica que la DEK no se pudo desenvolver: passphrase incorrecta,
	// vault distinto o material corrupto. Nunca devuelve "otra" clave.
	ErrUnwrap = errors.New("vault: no se pudo desenvolver la DEK")
	// ErrDecrypt indica que un blob no se pudo descifrar bajo el AAD dado.
	ErrDecrypt = errors.New("vault: no se pudo descifrar el blob")
	// ErrKeySize indica una clave de tamaño incorrecto.
	ErrKeySize = errors.New("vault: tamaño de clave incorrecto")
	// ErrNoVault indica que la base no contiene un vault.
	ErrNoVault = errors.New("vault: la base no contiene un vault")
	// ErrAAD indica un tenant o un payload_hash que no pueden formar un AAD
	// no ambiguo. Ver blobAAD.
	ErrAAD = errors.New("vault: AAD inválido")
)

// seal cifra con XChaCha20-Poly1305 y un nonce aleatorio de 24 bytes.
func seal(key, aad, plaintext []byte) (ciphertext, nonce []byte, err error) {
	if len(key) != chacha20poly1305.KeySize {
		return nil, nil, fmt.Errorf("%w: %d bytes, se esperaban %d", ErrKeySize, len(key), chacha20poly1305.KeySize)
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, nil, err
	}
	nonce = make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, fmt.Errorf("vault: nonce aleatorio: %w", err)
	}
	return aead.Seal(nil, nonce, plaintext, aad), nonce, nil
}

// open descifra y autentica. Un fallo aquí es un fallo RUIDOSO: el AEAD no
// devuelve texto plano "aproximado", devuelve error.
func open(key, aad, ciphertext, nonce []byte) ([]byte, error) {
	if len(key) != chacha20poly1305.KeySize {
		return nil, fmt.Errorf("%w: %d bytes, se esperaban %d", ErrKeySize, len(key), chacha20poly1305.KeySize)
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	if len(nonce) != aead.NonceSize() {
		return nil, fmt.Errorf("vault: nonce de %d bytes, se esperaban %d", len(nonce), aead.NonceSize())
	}
	return aead.Open(nil, nonce, ciphertext, aad)
}

// Wipe sobrescribe con ceros un secreto que ya no hace falta: una passphrase, una KEK.
//
// Reduce la ventana en la que el secreto está en memoria; no la cierra. Lo que Go
// garantiza es que ESTE slice queda a cero, no que no haya copias: el recolector puede
// haber movido o duplicado el array antes, un string creado a partir de los bytes es
// inmutable y no se puede borrar, y lo que el sistema operativo llevara a swap o a un
// volcado de memoria queda fuera de su alcance. Ver la enmienda de ADR-029.
func Wipe(b []byte) { zero(b) }

// zero sobrescribe material sensible.
func zero(b []byte) {
	if len(b) == 0 {
		return
	}
	for i := range b {
		b[i] = 0
	}
	// Lectura con tiempo constante para que el compilador no elimine el bucle
	// anterior por considerarlo escritura muerta.
	_ = subtle.ConstantTimeByteEq(b[0], 0)
}
