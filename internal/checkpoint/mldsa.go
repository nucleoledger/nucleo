package checkpoint

import (
	"crypto/mldsa"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
)

// Segunda firma del log con ML-DSA-44 (FIPS 204), según ADR-007.
//
// El motivo es que las firmas Ed25519 de hoy dejarán de valer el día que exista
// un computador cuántico capaz de romperlas, y un ledger existe para ser creído
// dentro de veinte años. Añadir hoy una firma post-cuántica no cuesta nada a
// quien no la entiende —las notas firmadas obligan a ignorar las firmas
// desconocidas— y lo cuesta todo no haberla añadido cuando haga falta.
//
// # El byte 0xff y por qué
//
// c2sp.org/signed-note no asigna ningún byte a una firma de log ML-DSA-44
// llana. Asigna 0x01 a Ed25519, 0x04 a las cosignatures Ed25519 con timestamp y
// 0x06 a las cosignatures ML-DSA-44 con timestamp. El 0x06 NO sirve aquí: es de
// cosignatures, c2sp.org/tlog-cosignature lo define sobre el mensaje
// "cosignature/v1\ntime <unix>\n" y habla de cosigner public key. Usarlo haría
// que el log firmara como testigo de sí mismo, que es falso.
//
// El spec destina el 0xff a los tipos sin byte asignado y recomienda seguirlo de
// un identificador más largo que sea improbable que colisione. Ese identificador
// es MLDSAExtensionID, decidido por el dev y fijado en ADR-007.
//
// El formato del key ID no se cambia sin rotar la clave: el key ID identifica la
// clave en cada línea de firma, así que tocarlo convierte en ilegibles todas las
// firmas ya emitidas con ella.

// MLDSAExtensionID es el identificador largo que sigue al byte 0xff.
const MLDSAExtensionID = "nucleoledger.com/sig/ml-dsa-44@v1"

// AlgMLDSA44Ext es el byte de extensión de c2sp.org/signed-note.
const AlgMLDSA44Ext = 0xff

// Tamaños de ML-DSA-44 (FIPS 204), comprobados contra crypto/mldsa.
const (
	// MLDSASeedSize es la semilla de la que se deriva la clave privada.
	MLDSASeedSize = mldsa.PrivateKeySize
	// MLDSAPublicKeySize es la clave pública codificada.
	MLDSAPublicKeySize = 1312
	// MLDSASignatureSize es la firma.
	MLDSASignatureSize = 2420
)

// ErrMLDSAKey indica material de clave ML-DSA-44 inválido.
var ErrMLDSAKey = errors.New("checkpoint: clave ML-DSA-44 inválida")

// MLDSASigner firma notas con ML-DSA-44. Implementa note.Signer.
type MLDSASigner struct {
	name string
	hash uint32
	key  *mldsa.PrivateKey
}

// NewMLDSASigner construye un firmante desde su semilla de 32 bytes.
func NewMLDSASigner(name string, seed []byte) (*MLDSASigner, error) {
	if err := validOrigin(name); err != nil {
		return nil, err
	}
	if len(seed) != MLDSASeedSize {
		return nil, fmt.Errorf("%w: semilla de %d bytes, se esperaban %d",
			ErrMLDSAKey, len(seed), MLDSASeedSize)
	}
	sk, err := mldsa.NewPrivateKey(mldsa.MLDSA44(), seed)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMLDSAKey, err)
	}
	return &MLDSASigner{
		name: name,
		hash: MLDSAKeyHash(name, sk.PublicKey().Bytes()),
		key:  sk,
	}, nil
}

// Name devuelve el nombre de la clave.
func (s *MLDSASigner) Name() string { return s.name }

// KeyHash devuelve el key ID.
func (s *MLDSASigner) KeyHash() uint32 { return s.hash }

// PublicKey devuelve la clave pública codificada.
func (s *MLDSASigner) PublicKey() []byte { return s.key.PublicKey().Bytes() }

// Sign firma el texto de la nota.
//
// Se usa SignDeterministic para que la misma nota y la misma clave produzcan
// siempre los mismos bytes, igual que ya ocurre con Ed25519. Un checkpoint que
// cambiara de bytes en cada emisión rompería los goldens y, peor, impediría
// comparar dos copias del mismo checkpoint byte a byte.
func (s *MLDSASigner) Sign(msg []byte) ([]byte, error) {
	return s.key.SignDeterministic(msg, &mldsa.Options{})
}

// MLDSAVerifier verifica firmas ML-DSA-44 de notas. Implementa note.Verifier.
type MLDSAVerifier struct {
	name string
	hash uint32
	key  *mldsa.PublicKey
}

// NewMLDSAVerifier construye un verificador desde la clave pública codificada.
func NewMLDSAVerifier(name string, pub []byte) (*MLDSAVerifier, error) {
	if err := validOrigin(name); err != nil {
		return nil, err
	}
	if len(pub) != MLDSAPublicKeySize {
		return nil, fmt.Errorf("%w: pública de %d bytes, se esperaban %d",
			ErrMLDSAKey, len(pub), MLDSAPublicKeySize)
	}
	pk, err := mldsa.NewPublicKey(mldsa.MLDSA44(), pub)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMLDSAKey, err)
	}
	return &MLDSAVerifier{name: name, hash: MLDSAKeyHash(name, pub), key: pk}, nil
}

// Name devuelve el nombre de la clave.
func (v *MLDSAVerifier) Name() string { return v.name }

// KeyHash devuelve el key ID.
func (v *MLDSAVerifier) KeyHash() uint32 { return v.hash }

// Verify comprueba la firma sobre el texto de la nota.
func (v *MLDSAVerifier) Verify(msg, sig []byte) bool {
	if len(sig) != MLDSASignatureSize {
		return false
	}
	return mldsa.Verify(v.key, msg, sig, &mldsa.Options{}) == nil
}

// MLDSAKeyHash calcula el key ID de una clave ML-DSA-44 del log, con el formato
// que fija ADR-007:
//
//	SHA-256(name ‖ "\n" ‖ 0xff ‖ MLDSAExtensionID ‖ "\n" ‖ pubkey)[:4]
//
// El identificador largo va DENTRO del hash, no solo en el byte de tipo: es lo
// que impide que dos extensiones distintas que compartan el 0xff produzcan el
// mismo key ID para la misma clave.
func MLDSAKeyHash(name string, pub []byte) uint32 {
	h := sha256.New()
	h.Write([]byte(name))
	h.Write([]byte("\n"))
	h.Write([]byte{AlgMLDSA44Ext})
	h.Write([]byte(MLDSAExtensionID))
	h.Write([]byte("\n"))
	h.Write(pub)
	return binary.BigEndian.Uint32(h.Sum(nil))
}

// keyHashBytes calcula el key ID clásico de signed-note:
// SHA-256(name ‖ "\n" ‖ alg ‖ pubkey), truncado a 4 bytes big-endian.
func keyHashBytes(name string, pub []byte, alg byte) uint32 {
	h := sha256.New()
	h.Write([]byte(name))
	h.Write([]byte("\n"))
	h.Write([]byte{alg})
	h.Write(pub)
	return binary.BigEndian.Uint32(h.Sum(nil))
}
