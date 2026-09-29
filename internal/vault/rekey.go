package vault

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
)

// AtomicMetaStore es un MetaStore capaz de sustituir varias filas en una sola
// transacción, y solo si las esperadas siguen como se leyeron. Lo implementa
// internal/store con ReplaceMeta.
type AtomicMetaStore interface {
	MetaStore
	ReplaceMeta(expected, updates map[string][]byte) error
}

// Rekey es un cambio de passphrase preparado y todavía SIN escribir (ADR-029).
//
// Se separa en dos pasos —PrepareRekey y Commit— porque entre ellos hay algo que no es
// del vault: enseñar las tarjetas nuevas y que alguien confirme que las copió. Si eso
// no ocurre, no se llama a Commit y el vault queda exactamente como estaba.
type Rekey struct {
	vaultID  string
	newKEK   []byte
	expected map[string][]byte
	updates  map[string][]byte
}

// PrepareRekey prepara el cambio de la passphrase de un vault a partir de su KEK
// actual, la que reconstruyen las tarjetas.
//
//  1. Con oldKEK se desenvuelve la DEK de ESTE vault: es lo que prueba que la clave es
//     suya y no una cualquiera (ErrUnwrap si no).
//  2. Se deriva una KEK nueva de newPassphrase con los MISMOS parámetros guardados y
//     un salt nuevo: la passphrase cambia, el coste de derivarla no.
//  3. La misma DEK se envuelve bajo la KEK nueva, y se comprueba que se desenvuelve
//     con ella antes de devolver nada.
//
// No escribe nada.
func PrepareRekey(ms MetaStore, oldKEK, newPassphrase []byte) (*Rekey, error) {
	if len(newPassphrase) == 0 {
		return nil, errors.New("vault: passphrase nueva vacía")
	}
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
	vaultID := string(rawID)

	dek, err := UnwrapDEK(oldKEK, wrapped, vaultID)
	if err != nil {
		return nil, err
	}
	defer zero(dek)

	salt := make([]byte, SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("vault: salt aleatorio: %w", err)
	}
	newParams := params
	newParams.Salt = salt
	newKEK, err := DeriveKEK(newPassphrase, newParams)
	if err != nil {
		return nil, err
	}
	newWrapped, err := WrapDEK(newKEK, dek, vaultID)
	if err != nil {
		zero(newKEK)
		return nil, err
	}
	// Antes de devolver nada: la DEK envuelta nueva se desenvuelve con la KEK nueva y
	// es la misma DEK. Un fallo aquí es un error en pantalla; descubierto después del
	// Commit, sería un vault que no abre nada.
	check, err := UnwrapDEK(newKEK, newWrapped, vaultID)
	if err != nil {
		zero(newKEK)
		return nil, fmt.Errorf("vault: el envoltorio nuevo no se desenvuelve: %w", err)
	}
	igual := bytes.Equal(check, dek)
	zero(check)
	if !igual {
		zero(newKEK)
		return nil, errors.New("vault: el envoltorio nuevo devuelve OTRA DEK")
	}

	newEncoded, err := json.Marshal(newParams)
	if err != nil {
		zero(newKEK)
		return nil, err
	}
	return &Rekey{
		vaultID: vaultID,
		newKEK:  newKEK,
		expected: map[string][]byte{
			MetaParamsKey: encoded,
			MetaDEKKey:    wrapped,
		},
		updates: map[string][]byte{
			MetaParamsKey: newEncoded,
			MetaDEKKey:    newWrapped,
		},
	}, nil
}

// NewKEK devuelve la KEK nueva, la que hay que respaldar con tarjetas nuevas. Es la
// del Rekey: no la guardes más allá de BackupKEK, y llama a Close al terminar.
func (r *Rekey) NewKEK() []byte { return r.newKEK }

// VaultID devuelve el identificador del vault que se está cambiando.
func (r *Rekey) VaultID() string { return r.vaultID }

// Commit escribe el cambio: parámetros con el salt nuevo y DEK envuelta nueva, JUNTOS
// y en una transacción, y solo si siguen siendo los que se leyeron al preparar
// (ADR-029 §C). A partir de aquí la passphrase vieja y las tarjetas viejas ya no
// abren este vault.
func (r *Rekey) Commit(ms AtomicMetaStore) error {
	return ms.ReplaceMeta(r.expected, r.updates)
}

// Close borra la KEK nueva de memoria.
func (r *Rekey) Close() {
	zero(r.newKEK)
	r.newKEK = nil
}
