package identity

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"path/filepath"
	"testing"

	"github.com/nucleoledger/nucleo/internal/checkpoint"
	"github.com/nucleoledger/nucleo/internal/store"
	"github.com/nucleoledger/nucleo/internal/vault"
	"golang.org/x/mod/sumdb/note"
)

const (
	testOrigin = "nucleoledger.com/identidad"
	testPass   = "una passphrase larga y aburrida"
)

// openVault deja un vault abierto sobre una base nueva.
func openVault(t *testing.T) (*store.Store, *vault.Vault) {
	t.Helper()
	s, _, err := store.Open(filepath.Join(t.TempDir(), "nucleo.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	v, err := vault.Create(s, testOrigin, []byte(testPass))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(v.Close)
	return s, v
}

// TestRoundTrip: lo que se guarda es lo que se recupera, y hace falta el vault
// abierto para recuperarlo.
func TestRoundTrip(t *testing.T) {
	s, v := openVault(t)

	id, err := Generate(testOrigin)
	if err != nil {
		t.Fatal(err)
	}
	if err := id.Save(v, s); err != nil {
		t.Fatal(err)
	}

	back, err := Load(v, s)
	if err != nil {
		t.Fatal(err)
	}
	if back.Origin != id.Origin {
		t.Errorf("origin = %q, want %q", back.Origin, id.Origin)
	}
	if !back.Tenant.Equal(id.Tenant) || !back.Log.Equal(id.Log) {
		t.Error("las claves recuperadas no son las guardadas")
	}
	if !bytes.Equal(back.LogPQSeed, id.LogPQSeed) {
		t.Error("la semilla ML-DSA recuperada no es la guardada")
	}
}

// TestSecretsAreNotReadableWithoutThePassphrase es la propiedad que justifica
// este paquete: las claves privadas están en el fichero, pero cifradas. Quien
// abra la base sin la passphrase ve bytes, no claves.
func TestSecretsAreNotReadableWithoutThePassphrase(t *testing.T) {
	s, v := openVault(t)
	id, err := Generate(testOrigin)
	if err != nil {
		t.Fatal(err)
	}
	if err := id.Save(v, s); err != nil {
		t.Fatal(err)
	}

	blob, err := s.GetMeta(MetaKey)
	if err != nil {
		t.Fatal(err)
	}
	// La semilla del tenant NO puede aparecer en claro dentro del material.
	if bytes.Contains(blob, id.Tenant.Seed()) {
		t.Fatal("la semilla privada está en claro en vault_meta")
	}

	// Y con otra passphrase no se abre: el AEAD falla ruidosamente en vez de
	// devolver "otras" claves.
	other, err := vault.Unlock(s, []byte("passphrase equivocada"))
	if err == nil {
		other.Close()
		t.Fatal("se abrió el vault con una passphrase equivocada")
	}
}

// TestLoadRejectsAnotherVault: las identidades de un vault no se cargan en otro,
// aunque alguien copie la fila. El AAD lleva el identificador del vault.
func TestLoadRejectsAnotherVault(t *testing.T) {
	s1, v1 := openVault(t)
	id, err := Generate(testOrigin)
	if err != nil {
		t.Fatal(err)
	}
	if err := id.Save(v1, s1); err != nil {
		t.Fatal(err)
	}
	blob, err := s1.GetMeta(MetaKey)
	if err != nil {
		t.Fatal(err)
	}

	s2, _, err := store.Open(filepath.Join(t.TempDir(), "otro.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	v2, err := vault.Create(s2, "nucleoledger.com/otro", []byte(testPass))
	if err != nil {
		t.Fatal(err)
	}
	defer v2.Close()
	if err := s2.PutMeta(MetaKey, blob); err != nil {
		t.Fatal(err)
	}

	if _, err := Load(v2, s2); err == nil {
		t.Fatal("las identidades de un vault se cargaron en otro")
	}
}

// TestNewLogSignsWithBothKeys comprueba que el log que arma la identidad emite
// checkpoints con las DOS firmas de ADR-007, y que quien solo conoce la Ed25519
// sigue verificando.
func TestNewLogSignsWithBothKeys(t *testing.T) {
	id, err := Generate(testOrigin)
	if err != nil {
		t.Fatal(err)
	}
	lg, err := id.NewLog()
	if err != nil {
		t.Fatal(err)
	}
	root := make([]byte, 32)
	msg, err := lg.Sign(checkpoint.Checkpoint{Origin: testOrigin, Size: 3, RootHash: root})
	if err != nil {
		t.Fatal(err)
	}

	edVerifier, err := checkpoint.NewVerifier(testOrigin, id.LogPublic())
	if err != nil {
		t.Fatal(err)
	}
	n, err := note.Open(msg, note.VerifierList(edVerifier))
	if err != nil {
		t.Fatalf("un verificador solo-Ed25519 no abrió el checkpoint: %v", err)
	}
	if len(n.UnverifiedSigs) != 1 {
		t.Errorf("%d firmas ignoradas, want 1 (la ML-DSA)", len(n.UnverifiedSigs))
	}

	pq, err := id.PQSigner()
	if err != nil {
		t.Fatal(err)
	}
	pqVerifier, err := checkpoint.NewMLDSAVerifier(testOrigin, pq.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := note.Open(msg, note.VerifierList(edVerifier, pqVerifier)); err != nil {
		t.Errorf("el verificador completo falló: %v", err)
	}
}

// TestFromSeedsRejectsBadInput cubre las entradas que no forman identidades.
func TestFromSeedsRejectsBadInput(t *testing.T) {
	good := make([]byte, ed25519.SeedSize)
	if _, err := FromSeeds("", good, good, good); err == nil {
		t.Error("se aceptó un origin vacío")
	}
	if _, err := FromSeeds(testOrigin, good[:16], good, good); err == nil {
		t.Error("se aceptó una semilla corta")
	}
}

// TestLoadWithoutIdentity: una base sin identidades lo dice con un error propio.
func TestLoadWithoutIdentity(t *testing.T) {
	s, v := openVault(t)
	if _, err := Load(v, s); !errors.Is(err, ErrNoIdentity) {
		t.Errorf("err = %v, want %v", err, ErrNoIdentity)
	}
}
