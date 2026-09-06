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
// SPEC-CHECK — EL BYTE DE ALGORITMO ESTÁ PENDIENTE DE DECISIÓN DEL DEV.
//
// c2sp.org/signed-note (sha256 0aaa21aad2cd77cdba27c3c0da59d58bf77a264e7de45cff5fb41b8795bcf4a7)
// asigna estos bytes: 0x01 Ed25519, 0x02 ECDSA, 0x03 reservado, 0x04
// cosignature Ed25519 con timestamp, 0x05 TreeHeadSignature, 0x06 cosignature
// ML-DSA-44 con timestamp, 0xfa–0xfe reservados, 0xff "para tipos de firma sin
// byte asignado por esta especificación".
//
// NO hay byte asignado para una firma de log ML-DSA-44 llana. El 0x06 es de
// COSIGNATURES: c2sp.org/tlog-cosignature lo define sobre el mensaje
// "cosignature/v1\ntime <unix>\n" y habla de "cosigner public key". Usarlo aquí
// haría que el log firmara como si fuera testigo de sí mismo, que es falso.
//
// Queda el 0xff, que el spec destina justamente a este caso, pero recomienda
// seguirlo de "un identificador más largo que sea improbable que colisione" sin
// fijar cuál. Ese identificador sería una extensión de Núcleo, no algo que el
// spec determine, así que la decisión es del dev y no se toma aquí.
//
// Mientras tanto el byte es un parámetro con un valor provisional, y NO hay
// golden de key ID: fijar uno ahora sería exactamente el error de SC-2, cuando
// un key ID equivocado pasó los tests porque los tests lo calculaban con la
// misma función que verificaban. Lo que sí está probado es la propiedad que
// ADR-007 promete y que no depende de este byte: un verificador que solo conoce
// la clave Ed25519 sigue verificando la nota.
const AlgMLDSA44Provisional = 0xff

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
//
// El byte de algoritmo entra en el key ID y por eso se pide explícitamente: no
// es un detalle interno, es parte de la identidad de la clave. Ver el
// SPEC-CHECK de arriba.
func NewMLDSASigner(name string, seed []byte, alg byte) (*MLDSASigner, error) {
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
		hash: keyHashBytes(name, sk.PublicKey().Bytes(), alg),
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
func NewMLDSAVerifier(name string, pub []byte, alg byte) (*MLDSAVerifier, error) {
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
	return &MLDSAVerifier{name: name, hash: keyHashBytes(name, pub, alg), key: pk}, nil
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

// keyHashBytes calcula el key ID sobre material de clave de cualquier tamaño:
// SHA-256(name ‖ "\n" ‖ alg ‖ pubkey), truncado a 4 bytes big-endian. Es la
// misma fórmula de KeyHashAlg, sin atarse a una pública de 32 bytes.
func keyHashBytes(name string, pub []byte, alg byte) uint32 {
	h := sha256.New()
	h.Write([]byte(name))
	h.Write([]byte("\n"))
	h.Write([]byte{alg})
	h.Write(pub)
	return binary.BigEndian.Uint32(h.Sum(nil))
}
