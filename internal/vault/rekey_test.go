package vault

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"
)

// errCambio simula el ErrMetaChanged de internal/store, que el vault no importa.
var errCambio = errors.New("memStore: vault_meta cambió")

// ReplaceMeta hace de memStore un AtomicMetaStore: comprueba las esperadas y escribe
// todas o ninguna, como la transacción de internal/store.
func (s *memStore) ReplaceMeta(expected, updates map[string][]byte) error {
	for k, v := range expected {
		if !bytes.Equal(s.m[k], v) {
			return errCambio
		}
	}
	for k, v := range updates {
		s.m[k] = append([]byte(nil), v...)
	}
	return nil
}

// kekDe rederiva la KEK con los parámetros guardados, como hace la CLI para respaldarla.
func kekDe(t *testing.T, ms MetaStore, pass string) []byte {
	t.Helper()
	raw, err := ms.GetMeta(MetaParamsKey)
	if err != nil {
		t.Fatal(err)
	}
	var p Params
	if err := json.Unmarshal(raw, &p); err != nil {
		t.Fatal(err)
	}
	kek, err := DeriveKEK([]byte(pass), p)
	if err != nil {
		t.Fatal(err)
	}
	return kek
}

func paramsDe(t *testing.T, ms MetaStore) Params {
	t.Helper()
	raw, err := ms.GetMeta(MetaParamsKey)
	if err != nil {
		t.Fatal(err)
	}
	var p Params
	if err := json.Unmarshal(raw, &p); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestRekeyPerderLaPassphraseYFijarOtra es ADR-029 de punta a punta en el vault:
// se pierde la passphrase, dos tarjetas reconstruyen la KEK, se fija una passphrase
// nueva, y a partir de ahí la vieja y las tarjetas viejas ya no abren nada.
func TestRekeyPerderLaPassphraseYFijarOtra(t *testing.T) {
	ms := newMemStore()
	v, err := CreateWithProfile(ms, testVaultID, []byte("la-que-se-perdio"), ProfileConstrained)
	if err != nil {
		t.Fatal(err)
	}
	claveAntes, err := v.CommitKey("1790012345001")
	if err != nil {
		t.Fatal(err)
	}
	v.Close()
	antes := paramsDe(t, ms)
	viejas, err := BackupKEK(kekDe(t, ms, "la-que-se-perdio"), 3, 2)
	if err != nil {
		t.Fatal(err)
	}

	// La passphrase se perdió: solo quedan dos tarjetas.
	oldKEK, err := RestoreKEK(viejas[:2])
	if err != nil {
		t.Fatal(err)
	}
	r, err := PrepareRekey(ms, oldKEK, []byte("la-nueva"))
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	nuevas, err := BackupKEK(r.NewKEK(), 3, 2)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Commit(ms); err != nil {
		t.Fatal(err)
	}

	// La nueva abre, y la DEK es la MISMA: la subclave de compromisos no cambió.
	v, err = Unlock(ms, []byte("la-nueva"))
	if err != nil {
		t.Fatalf("la passphrase nueva no abre: %v", err)
	}
	claveDespues, err := v.CommitKey("1790012345001")
	v.Close()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(claveAntes, claveDespues) {
		t.Error("la DEK cambió: todo lo cifrado antes quedaría ilegible")
	}
	// La vieja ya no.
	if _, err := Unlock(ms, []byte("la-que-se-perdio")); !errors.Is(err, ErrUnwrap) {
		t.Errorf("la passphrase vieja: %v; want ErrUnwrap", err)
	}
	// Las tarjetas viejas reconstruyen su KEK… que ya no desenvuelve la DEK de este vault.
	wrapped, _ := ms.GetMeta(MetaDEKKey)
	kv, err := RestoreKEK(viejas[1:])
	if err != nil {
		t.Fatal(err)
	}
	if _, err := UnwrapDEK(kv, wrapped, testVaultID); !errors.Is(err, ErrUnwrap) {
		t.Errorf("las tarjetas viejas siguen abriendo: %v", err)
	}
	// Las nuevas sí, con cualquier par.
	kn, err := RestoreKEK([]string{nuevas[0], nuevas[2]})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := UnwrapDEK(kn, wrapped, testVaultID); err != nil {
		t.Errorf("las tarjetas nuevas no abren: %v", err)
	}

	// Mismo perfil de KDF, salt nuevo.
	despues := paramsDe(t, ms)
	if despues.Profile() != string(ProfileConstrained) || despues.Time != antes.Time ||
		despues.Memory != antes.Memory || despues.Threads != antes.Threads || despues.KeyLen != antes.KeyLen {
		t.Errorf("los parámetros cambiaron: %+v → %+v", antes, despues)
	}
	if bytes.Equal(antes.Salt, despues.Salt) {
		t.Error("el salt no cambió")
	}
}

// TestRekeySinCommitNoCambiaNada: preparar no escribe. Es lo que permite abandonar el
// cambio si nadie confirma las tarjetas nuevas.
func TestRekeySinCommitNoCambiaNada(t *testing.T) {
	ms := newMemStore()
	if _, err := CreateWithProfile(ms, testVaultID, []byte("vieja"), ProfileConstrained); err != nil {
		t.Fatal(err)
	}
	antes := map[string][]byte{}
	for k, v := range ms.m {
		antes[k] = append([]byte(nil), v...)
	}
	r, err := PrepareRekey(ms, kekDe(t, ms, "vieja"), []byte("nueva"))
	if err != nil {
		t.Fatal(err)
	}
	r.Close()
	for k, v := range antes {
		if !bytes.Equal(ms.m[k], v) {
			t.Errorf("PrepareRekey escribió %s", k)
		}
	}
	if _, err := Unlock(ms, []byte("vieja")); err != nil {
		t.Errorf("la passphrase vieja dejó de abrir sin Commit: %v", err)
	}
}

// TestRekeyConLaClaveDeOtroVault: unas tarjetas de otro vault reconstruyen una clave
// válida, pero no la de este. PrepareRekey lo dice y no escribe nada.
func TestRekeyConLaClaveDeOtroVault(t *testing.T) {
	ms := newMemStore()
	if _, err := CreateWithProfile(ms, testVaultID, []byte("esta"), ProfileConstrained); err != nil {
		t.Fatal(err)
	}
	otro := newMemStore()
	if _, err := CreateWithProfile(otro, testVaultID, []byte("otra"), ProfileConstrained); err != nil {
		t.Fatal(err)
	}
	if _, err := PrepareRekey(ms, kekDe(t, otro, "otra"), []byte("nueva")); !errors.Is(err, ErrUnwrap) {
		t.Fatalf("PrepareRekey con la KEK de otro vault = %v; want ErrUnwrap", err)
	}
	if _, err := Unlock(ms, []byte("esta")); err != nil {
		t.Errorf("el vault cambió: %v", err)
	}
}

// TestRekeyNoPisaUnCambioAjeno: dos cambios preparados sobre el mismo estado; el
// segundo en escribir no pisa al primero.
func TestRekeyNoPisaUnCambioAjeno(t *testing.T) {
	ms := newMemStore()
	if _, err := CreateWithProfile(ms, testVaultID, []byte("vieja"), ProfileConstrained); err != nil {
		t.Fatal(err)
	}
	kek := kekDe(t, ms, "vieja")
	a, err := PrepareRekey(ms, kek, []byte("de-a"))
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := PrepareRekey(ms, kek, []byte("de-b"))
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if err := a.Commit(ms); err != nil {
		t.Fatal(err)
	}
	if err := b.Commit(ms); !errors.Is(err, errCambio) {
		t.Fatalf("el segundo Commit = %v; want el cambio detectado", err)
	}
	if _, err := Unlock(ms, []byte("de-a")); err != nil {
		t.Errorf("el cambio de a se perdió: %v", err)
	}
}

// TestRekeyPassphraseVacia: no se fija una passphrase vacía.
func TestRekeyPassphraseVacia(t *testing.T) {
	ms := newMemStore()
	if _, err := CreateWithProfile(ms, testVaultID, []byte("vieja"), ProfileConstrained); err != nil {
		t.Fatal(err)
	}
	if _, err := PrepareRekey(ms, kekDe(t, ms, "vieja"), nil); err == nil {
		t.Fatal("se aceptó una passphrase nueva vacía")
	}
}
