// Package keys encapsula la generación y codificación de claves Ed25519 del tenant.
//
// La clave privada representa a la empresa (tenant). En el daemon real la semilla
// se persiste cifrada con XChaCha20-Poly1305 y una clave derivada por Argon2id;
// aquí solo se expone el material en hex para que las capas superiores lo manejen.
package keys

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
)

var (
	// ErrInvalidPublicKey indica que el hex no decodifica a 32 bytes.
	ErrInvalidPublicKey = errors.New("keys: clave pública Ed25519 inválida")
	// ErrInvalidSeed indica que el hex no decodifica a una semilla de 32 bytes.
	ErrInvalidSeed = errors.New("keys: semilla Ed25519 inválida")
)

// Generate crea un par de claves Ed25519 usando el CSPRNG del sistema.
func Generate() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("keys: generación de par de claves: %w", err)
	}
	return pub, priv, nil
}

// PublicKeyHex codifica la clave pública en hexadecimal (64 caracteres).
func PublicKeyHex(pub ed25519.PublicKey) string {
	return hex.EncodeToString(pub)
}

// SeedHex codifica la semilla privada (32 bytes) en hexadecimal. Es lo único que
// hace falta persistir: la clave privada completa se reconstruye desde la semilla.
func SeedHex(priv ed25519.PrivateKey) string {
	return hex.EncodeToString(priv.Seed())
}

// ParsePublicKeyHex reconstruye una clave pública desde su representación hex.
func ParsePublicKeyHex(s string) (ed25519.PublicKey, error) {
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != ed25519.PublicKeySize {
		return nil, ErrInvalidPublicKey
	}
	return ed25519.PublicKey(b), nil
}

// PrivateKeyFromSeedHex reconstruye la clave privada completa desde la semilla hex.
func PrivateKeyFromSeedHex(s string) (ed25519.PrivateKey, error) {
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != ed25519.SeedSize {
		return nil, ErrInvalidSeed
	}
	return ed25519.NewKeyFromSeed(b), nil
}
