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

// Parámetros del perfil "constrained", para hosting compartido.
//
// Son el MÍNIMO de la guía de almacenamiento de contraseñas de OWASP: 19 MiB de
// memoria, 2 iteraciones y 1 grado de paralelismo. No es una cifra inventada
// para que quepa: es el punto más bajo que una guía reconocida respalda.
//
// Conviene ser muy claro sobre lo que se pierde, porque este perfil es más débil
// y no hay forma de presentarlo de otro modo. Los parámetros por omisión de
// Núcleo (t=3, p=4, m=64 MiB) son EXACTAMENTE la segunda opción recomendada del
// RFC 9106 §4, la que el propio RFC da para entornos con poca memoria. El perfil
// constrained queda por debajo de eso: deja de cumplir la recomendación del RFC
// y se apoya en el mínimo de OWASP.
//
// La razón para aceptarlo es operativa, no criptográfica. ADR-005 eligió la CLI
// precisamente porque en hosting compartido no se pueden tener daemons; en ese
// mismo entorno, 64 MiB × 4 lanes choca con los límites de LVE/CageFS y el
// resultado no es "un vault más lento", es un proceso que el hosting mata. La
// alternativa real a este perfil no es uno más fuerte: es que esa persona no use
// cifrado en absoluto, o no pueda abrir su propio vault.
//
// Con p=1 además se evita repartir el trabajo en cuatro lanes, que es lo que un
// límite de procesos por usuario castiga primero.
const (
	ConstrainedTime    uint32 = 2
	ConstrainedMemory  uint32 = 19 * 1024 // KiB, es decir 19 MiB
	ConstrainedThreads uint8  = 1
)

// KDFProfile nombra un juego de parámetros de Argon2id.
//
// Existen nombres y no números sueltos porque quien elige esto al crear un vault
// no está en condiciones de razonar sobre m, t y p: está decidiendo entre "mi
// portátil o un VPS" y "un plan compartido de 10 dólares". El nombre se guarda
// con los parámetros para que un vault diga con qué se creó.
type KDFProfile string

const (
	// ProfileDefault es t=3, p=4, m=64 MiB: la segunda opción del RFC 9106 §4.
	ProfileDefault KDFProfile = "default"
	// ProfileConstrained es t=2, p=1, m=19 MiB: el mínimo de OWASP. Más débil.
	ProfileConstrained KDFProfile = "constrained"
)

// ErrProfile indica un perfil de KDF desconocido.
var ErrProfile = errors.New("vault: perfil de KDF desconocido")

// ParamsFor devuelve los parámetros del perfil con el salt dado.
func ParamsFor(profile KDFProfile, salt []byte) (Params, error) {
	switch profile {
	case ProfileDefault, "":
		return DefaultParams(salt), nil
	case ProfileConstrained:
		return Params{
			Time: ConstrainedTime, Memory: ConstrainedMemory,
			Threads: ConstrainedThreads, KeyLen: KeyLen, Salt: salt,
		}, nil
	default:
		return Params{}, fmt.Errorf("%w: %q", ErrProfile, profile)
	}
}

// Profile nombra el perfil al que corresponden estos parámetros, o "personalizado"
// si no coincide con ninguno conocido.
//
// Se deduce de los valores en vez de guardarse como etiqueta aparte a propósito:
// una etiqueta puede mentir sobre los parámetros con los que se derivó de verdad
// la KEK, y lo que se usa para abrir el vault son los números.
func (p Params) Profile() string {
	switch {
	case p.Time == ArgonTime && p.Memory == ArgonMemory && p.Threads == ArgonThreads:
		return string(ProfileDefault)
	case p.Time == ConstrainedTime && p.Memory == ConstrainedMemory && p.Threads == ConstrainedThreads:
		return string(ProfileConstrained)
	default:
		return "personalizado"
	}
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
		return nil, fmt.Errorf("%w: %w", ErrUnwrap, err)
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
	return CreateWithProfile(ms, vaultID, passphrase, ProfileDefault)
}

// CreateWithProfile es Create con un perfil de KDF explícito. Los parámetros
// quedan en vault_meta y son los que Unlock usará: un vault se abre con los
// parámetros con los que se creó, no con los que estén de moda.
func CreateWithProfile(ms MetaStore, vaultID string, passphrase []byte, profile KDFProfile) (*Vault, error) {
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

	params, err := ParamsFor(profile, salt)
	if err != nil {
		return nil, err
	}
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
		return nil, fmt.Errorf("%w: %w", ErrNoVault, err)
	}
	var params Params
	if err := json.Unmarshal(encoded, &params); err != nil {
		return nil, fmt.Errorf("%w: parámetros ilegibles: %w", ErrNoVault, err)
	}
	rawID, err := ms.GetMeta(MetaIDKey)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrNoVault, err)
	}
	wrapped, err := ms.GetMeta(MetaDEKKey)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrNoVault, err)
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
