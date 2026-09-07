package vault

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/nucleoledger/nucleo/internal/commit"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

// Parámetros de derivación fijados para esta versión. Se guardan en vault_meta
// junto al salt para poder subirlos en el futuro sin dejar ilegibles los vaults
// viejos: un vault se abre con los parámetros con los que se creó, no con los
// que estén de moda.
const (
	ArgonTime    uint32 = 3
	ArgonMemory  uint32 = 64 * 1024 // KiB, es decir 64 MiB
	ArgonThreads uint8  = 4
	KeyLen       uint32 = 32
	SaltLen             = 16
	DEKLen              = 32
)

// Claves de vault_meta.
const (
	MetaParamsKey = "vault/params/v1"
	MetaDEKKey    = "vault/dek/v1"
	MetaIDKey     = "vault/id/v1"
)

// dekAADPrefix separa el dominio del envoltorio de la DEK del de los blobs: una
// DEK envuelta nunca puede descifrarse como si fuera un payload, ni al revés.
const dekAADPrefix = "nucleo/dek/v1"

// Params son los parámetros de Argon2id con los que se derivó la KEK.
type Params struct {
	Time    uint32 `json:"time"`
	Memory  uint32 `json:"memory_kib"`
	Threads uint8  `json:"threads"`
	KeyLen  uint32 `json:"key_len"`
	Salt    []byte `json:"salt"`
}

// DefaultParams devuelve los parámetros de esta versión con el salt dado.
func DefaultParams(salt []byte) Params {
	return Params{Time: ArgonTime, Memory: ArgonMemory, Threads: ArgonThreads, KeyLen: KeyLen, Salt: salt}
}

// Validate rechaza parámetros que no derivarían una clave utilizable.
func (p Params) Validate() error {
	switch {
	case p.Time == 0:
		return fmt.Errorf("%w: time = 0", ErrParams)
	case p.Memory < 8:
		return fmt.Errorf("%w: memory = %d KiB", ErrParams, p.Memory)
	case p.Threads == 0:
		return fmt.Errorf("%w: threads = 0", ErrParams)
	case p.KeyLen < 16:
		return fmt.Errorf("%w: key_len = %d", ErrParams, p.KeyLen)
	case len(p.Salt) < 8:
		return fmt.Errorf("%w: salt de %d bytes", ErrParams, len(p.Salt))
	}
	return nil
}

// DeriveKEK deriva la clave de cifrado de claves desde la passphrase.
func DeriveKEK(passphrase []byte, p Params) ([]byte, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return argon2.IDKey(passphrase, p.Salt, p.Time, p.Memory, p.Threads, p.KeyLen), nil
}

// dekAAD ata el envoltorio de la DEK a este vault concreto: la DEK envuelta de
// un vault no se desenvuelve en otro aunque compartieran passphrase.
func dekAAD(vaultID string) []byte {
	return append([]byte(dekAADPrefix), vaultID...)
}

// WrapDEK envuelve la DEK bajo la KEK. El resultado es nonce ‖ ciphertext.
func WrapDEK(kek, dek []byte, vaultID string) ([]byte, error) {
	if len(dek) != DEKLen {
		return nil, fmt.Errorf("%w: DEK de %d bytes, se esperaban %d", ErrKeySize, len(dek), DEKLen)
	}
	ct, nonce, err := seal(kek, dekAAD(vaultID), dek)
	if err != nil {
		return nil, err
	}
	return append(nonce, ct...), nil
}

// UnwrapDEK recupera la DEK.
//
// Aquí está la lección de la semilla silenciosa, que este proyecto ya aprendió
// con Ed25519: una semilla corrupta produce OTRA identidad sin avisar. Con la
// DEK no puede pasar, y no por suerte: XChaCha20-Poly1305 es autenticado, así
// que un solo bit alterado en el material envuelto —o una passphrase
// equivocada— falla ruidosamente en vez de entregar una clave distinta con la
// que se cifrarían datos irrecuperables.
func UnwrapDEK(kek, wrapped []byte, vaultID string) ([]byte, error) {
	const nonceLen = chacha20poly1305.NonceSizeX
	if len(wrapped) <= nonceLen {
		return nil, fmt.Errorf("%w: material de %d bytes", ErrUnwrap, len(wrapped))
	}
	dek, err := open(kek, dekAAD(vaultID), wrapped[nonceLen:], wrapped[:nonceLen])
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnwrap, err)
	}
	if len(dek) != DEKLen {
		return nil, fmt.Errorf("%w: DEK de %d bytes", ErrUnwrap, len(dek))
	}
	return dek, nil
}

// MetaStore es lo que el vault necesita de la persistencia. Se declara aquí, y
// no se importa internal/store, para que el vault se pueda probar sin base.
type MetaStore interface {
	PutMeta(key string, value []byte) error
	GetMeta(key string) ([]byte, error)
}

// Vault es un vault abierto: guarda la DEK en memoria mientras dure la sesión.
type Vault struct {
	id  string
	dek []byte
}

// ID devuelve el identificador del vault.
func (v *Vault) ID() string { return v.id }

// Create genera un vault nuevo: salt aleatorio de 16 bytes, DEK aleatoria de 32
// y la DEK envuelta bajo la KEK derivada de la passphrase. Persiste parámetros,
// identificador y DEK envuelta; la DEK en claro nunca toca el disco.
func Create(ms MetaStore, vaultID string, passphrase []byte) (*Vault, error) {
	if vaultID == "" {
		return nil, errors.New("vault: identificador de vault vacío")
	}
	if len(passphrase) == 0 {
		return nil, errors.New("vault: passphrase vacía")
	}
	salt := make([]byte, SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("vault: salt aleatorio: %w", err)
	}
	dek := make([]byte, DEKLen)
	if _, err := rand.Read(dek); err != nil {
		return nil, fmt.Errorf("vault: DEK aleatoria: %w", err)
	}

	params := DefaultParams(salt)
	kek, err := DeriveKEK(passphrase, params)
	if err != nil {
		return nil, err
	}
	defer zero(kek)

	wrapped, err := WrapDEK(kek, dek, vaultID)
	if err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(params)
	if err != nil {
		return nil, err
	}
	if err := ms.PutMeta(MetaParamsKey, encoded); err != nil {
		return nil, err
	}
	if err := ms.PutMeta(MetaIDKey, []byte(vaultID)); err != nil {
		return nil, err
	}
	if err := ms.PutMeta(MetaDEKKey, wrapped); err != nil {
		return nil, err
	}
	return &Vault{id: vaultID, dek: dek}, nil
}

// Unlock abre un vault existente con su passphrase.
func Unlock(ms MetaStore, passphrase []byte) (*Vault, error) {
	encoded, err := ms.GetMeta(MetaParamsKey)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNoVault, err)
	}
	var params Params
	if err := json.Unmarshal(encoded, &params); err != nil {
		return nil, fmt.Errorf("%w: parámetros ilegibles: %v", ErrNoVault, err)
	}
	rawID, err := ms.GetMeta(MetaIDKey)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNoVault, err)
	}
	wrapped, err := ms.GetMeta(MetaDEKKey)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNoVault, err)
	}

	kek, err := DeriveKEK(passphrase, params)
	if err != nil {
		return nil, err
	}
	defer zero(kek)

	dek, err := UnwrapDEK(kek, wrapped, string(rawID))
	if err != nil {
		return nil, err
	}
	return &Vault{id: string(rawID), dek: dek}, nil
}

// Close borra la DEK de memoria. No es una garantía absoluta —Go puede haber
// copiado el slice— pero reduce la ventana.
func (v *Vault) Close() {
	zero(v.dek)
	v.dek = nil
}

// CommitKey deriva la clave de compromisos de un tenant a partir de la DEK.
//
// El vault NO expone la DEK, ni siquiera a otros paquetes de este repositorio.
// Una clave que se puede pedir acaba copiada en algún sitio; una que solo se
// puede USAR a través de métodos como este, no. Lo que sale de aquí es una
// subclave para un uso concreto, derivada con HKDF, e inservible para descifrar
// blobs.
func (v *Vault) CommitKey(tenant string) ([]byte, error) {
	if len(v.dek) == 0 {
		return nil, errors.New("vault: el vault está cerrado")
	}
	return commit.DeriveKey(v.dek, tenant)
}
