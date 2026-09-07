// Package identity guarda las claves de firma de un despliegue de Núcleo dentro
// del propio vault, cifradas bajo la DEK.
//
// Las claves privadas nunca tocan el disco en claro. Viven en vault_meta,
// cifradas con XChaCha20-Poly1305 en un dominio propio, así que abrir el fichero
// sin la passphrase no da acceso a ellas y usarlas exige haber desbloqueado el
// vault. Es la misma propiedad que ya tenían los payloads, aplicada a lo que
// firma.
package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/nucleoledger/nucleo/internal/checkpoint"
	"github.com/nucleoledger/nucleo/internal/vault"
)

// MetaKey es la clave de vault_meta donde vive el material cifrado.
const MetaKey = "identity/v1"

// secretDomain separa este material de cualquier otro secreto del vault.
const secretDomain = "identity/v1"

// ErrNoIdentity indica que la base no tiene identidades guardadas.
var ErrNoIdentity = errors.New("identity: la base no tiene identidades")

// Identity son las tres claves que un despliegue necesita para operar.
type Identity struct {
	// Origin identifica al log ante los testigos.
	Origin string
	// Tenant firma los bloques.
	Tenant ed25519.PrivateKey
	// Log firma los checkpoints.
	Log ed25519.PrivateKey
	// LogPQSeed deriva la segunda firma ML-DSA-44 del log (ADR-007).
	LogPQSeed []byte
}

// stored es la forma serializada. Se guardan SEMILLAS de 32 bytes y no claves
// expandidas: una semilla es la forma canónica y mínima, y reconstruir la clave
// desde ella es determinista.
type stored struct {
	Origin      string `json:"origin"`
	TenantSeed  []byte `json:"tenant_seed"`
	LogSeed     []byte `json:"log_seed"`
	LogPQSeed   []byte `json:"log_pq_seed"`
	FormatLabel string `json:"format"`
}

// Generate crea identidades nuevas con material aleatorio.
func Generate(origin string) (*Identity, error) {
	seeds := make([][]byte, 3)
	for i := range seeds {
		seeds[i] = make([]byte, ed25519.SeedSize)
		if _, err := rand.Read(seeds[i]); err != nil {
			return nil, fmt.Errorf("identity: material aleatorio: %w", err)
		}
	}
	return fromSeeds(origin, seeds[0], seeds[1], seeds[2])
}

// FromSeeds reconstruye identidades desde semillas conocidas. Existe para los
// tests, que necesitan salidas reproducibles.
func FromSeeds(origin string, tenant, log, pq []byte) (*Identity, error) {
	return fromSeeds(origin, tenant, log, pq)
}

func fromSeeds(origin string, tenant, log, pq []byte) (*Identity, error) {
	if origin == "" {
		return nil, errors.New("identity: origin vacío")
	}
	for _, s := range [][]byte{tenant, log, pq} {
		if len(s) != ed25519.SeedSize {
			return nil, fmt.Errorf("identity: semilla de %d bytes, se esperaban %d", len(s), ed25519.SeedSize)
		}
	}
	return &Identity{
		Origin:    origin,
		Tenant:    ed25519.NewKeyFromSeed(tenant),
		Log:       ed25519.NewKeyFromSeed(log),
		LogPQSeed: append([]byte(nil), pq...),
	}, nil
}

// TenantPublic devuelve la pública del tenant.
func (i *Identity) TenantPublic() ed25519.PublicKey { return i.Tenant.Public().(ed25519.PublicKey) }

// LogPublic devuelve la pública del log.
func (i *Identity) LogPublic() ed25519.PublicKey { return i.Log.Public().(ed25519.PublicKey) }

// NewLog construye el emisor de checkpoints con sus DOS firmas: la Ed25519 y la
// ML-DSA-44 de ADR-007.
func (i *Identity) NewLog() (*checkpoint.Log, error) {
	signer, err := checkpoint.NewSigner(i.Origin, i.Log)
	if err != nil {
		return nil, err
	}
	l, err := checkpoint.NewLog(i.Origin, signer)
	if err != nil {
		return nil, err
	}
	pq, err := i.PQSigner()
	if err != nil {
		return nil, err
	}
	if err := l.AddSigner(pq); err != nil {
		return nil, err
	}
	return l, nil
}

// PQSigner construye el firmante post-cuántico del log.
func (i *Identity) PQSigner() (*checkpoint.MLDSASigner, error) {
	return checkpoint.NewMLDSASigner(i.Origin, i.LogPQSeed)
}

// Save cifra las identidades bajo la DEK y las guarda en vault_meta.
func (i *Identity) Save(v *vault.Vault, ms vault.MetaStore) error {
	raw, err := json.Marshal(stored{
		Origin:      i.Origin,
		TenantSeed:  i.Tenant.Seed(),
		LogSeed:     i.Log.Seed(),
		LogPQSeed:   i.LogPQSeed,
		FormatLabel: MetaKey,
	})
	if err != nil {
		return err
	}
	ct, nonce, err := v.EncryptSecret(secretDomain, raw)
	if err != nil {
		return err
	}
	return ms.PutMeta(MetaKey, append(nonce, ct...))
}

// Load recupera las identidades. Exige el vault abierto: sin la passphrase no
// hay claves.
func Load(v *vault.Vault, ms vault.MetaStore) (*Identity, error) {
	blob, err := ms.GetMeta(MetaKey)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNoIdentity, err)
	}
	const nonceLen = 24
	if len(blob) <= nonceLen {
		return nil, fmt.Errorf("%w: material de %d bytes", ErrNoIdentity, len(blob))
	}
	raw, err := v.DecryptSecret(secretDomain, blob[nonceLen:], blob[:nonceLen])
	if err != nil {
		return nil, err
	}
	var st stored
	if err := json.Unmarshal(raw, &st); err != nil {
		return nil, fmt.Errorf("identity: material ilegible: %w", err)
	}
	return fromSeeds(st.Origin, st.TenantSeed, st.LogSeed, st.LogPQSeed)
}
