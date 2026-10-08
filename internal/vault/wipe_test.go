package vault

import (
	"bytes"
	"errors"
	"testing"
)

// TestWipeDejaCeros: lo único que Wipe puede prometer es que ESE slice queda a cero.
func TestWipeDejaCeros(t *testing.T) {
	b := []byte("correcta caballo bateria grapa")
	Wipe(b)
	if !bytes.Equal(b, make([]byte, len(b))) {
		t.Fatalf("Wipe dejó %q", b)
	}
	Wipe(nil) // no entra en pánico con un slice vacío
}

// TestCheckKEK: dice si la KEK es la de este vault sin devolver la DEK.
func TestCheckKEK(t *testing.T) {
	ms := newMemStore()
	if _, err := CreateWithProfile(ms, testVaultID, []byte("esta"), ProfileConstrained); err != nil {
		t.Fatal(err)
	}
	wrapped, _ := ms.GetMeta(MetaDEKKey)
	if err := CheckKEK(kekDe(t, ms, "esta"), wrapped, testVaultID); err != nil {
		t.Errorf("la KEK de este vault: %v", err)
	}
	if err := CheckKEK(kekDe(t, ms, "otra"), wrapped, testVaultID); !errors.Is(err, ErrUnwrap) {
		t.Errorf("otra KEK = %v; want ErrUnwrap", err)
	}
	if err := CheckKEK(kekDe(t, ms, "esta"), wrapped, "otro-vault"); !errors.Is(err, ErrUnwrap) {
		t.Errorf("otro vault = %v; want ErrUnwrap", err)
	}
}
