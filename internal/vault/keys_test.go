package vault

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"testing"
)

const testVaultID = "vault-poc-1"

// memStore es un MetaStore en memoria: el vault no necesita una base para
// probarse.
type memStore struct{ m map[string][]byte }

func newMemStore() *memStore { return &memStore{m: map[string][]byte{}} }

func (s *memStore) PutMeta(k string, v []byte) error {
	s.m[k] = append([]byte(nil), v...)
	return nil
}

func (s *memStore) GetMeta(k string) ([]byte, error) {
	v, ok := s.m[k]
	if !ok {
		return nil, fmt.Errorf("no existe %q", k)
	}
	return append([]byte(nil), v...), nil
}

// TestArgon2idGolden ata la derivación de la KEK a un valor calculado FUERA de
// Go, con la implementación C de referencia (phc-winner-argon2), enlazada contra
// libargon2.so.1 del sistema y compilada aparte.
//
// Es la regla anti-circularidad aplicada donde más importa: si el golden se
// hubiera generado con este mismo x/crypto/argon2, el test solo comprobaría que
// la función es determinista, no que deriva lo que debe.
func TestArgon2idGolden(t *testing.T) {
	const (
		passphrase = "correcta caballo bateria grapa"
		saltHex    = "000102030405060708090a0b0c0d0e0f"
		wantKEK    = "3147cf7f096f69da25e30f15cf160b6dc974e704c450a5dd2b504d5b06ab2be2"
	)
	salt, err := hex.DecodeString(saltHex)
	if err != nil {
		t.Fatal(err)
	}

	params := DefaultParams(salt)
	if params.Time != 3 || params.Memory != 64*1024 || params.Threads != 4 || params.KeyLen != 32 {
		t.Fatalf("los parámetros por defecto cambiaron: %+v", params)
	}

	kek, err := DeriveKEK([]byte(passphrase), params)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(kek); got != wantKEK {
		t.Errorf("KEK = %s\nwant  %s", got, wantKEK)
	}

	// Cambiar cualquier parámetro debe cambiar la clave: si no, el parámetro no
	// estaría llegando a la derivación.
	variants := []struct {
		name string
		mut  func(*Params)
	}{
		{"time", func(p *Params) { p.Time = 4 }},
		{"memory", func(p *Params) { p.Memory = 32 * 1024 }},
		{"threads", func(p *Params) { p.Threads = 2 }},
		{"salt", func(p *Params) { p.Salt[0] ^= 0xff }},
	}
	for _, v := range variants {
		p := DefaultParams(append([]byte(nil), salt...))
		v.mut(&p)
		other, err := DeriveKEK([]byte(passphrase), p)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Equal(other, kek) {
			t.Errorf("cambiar %s no cambió la KEK: el parámetro no llega a Argon2id", v.name)
		}
	}
	other, err := DeriveKEK([]byte(passphrase+"!"), params)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(other, kek) {
		t.Error("cambiar la passphrase no cambió la KEK")
	}
}

// TestDeriveKEKRejectsBadParams cubre la validación.
func TestDeriveKEKRejectsBadParams(t *testing.T) {
	salt := bytes.Repeat([]byte{1}, SaltLen)
	cases := []struct {
		name string
		p    Params
	}{
		{"time cero", Params{Time: 0, Memory: 65536, Threads: 4, KeyLen: 32, Salt: salt}},
		{"memoria insuficiente", Params{Time: 3, Memory: 4, Threads: 4, KeyLen: 32, Salt: salt}},
		{"threads cero", Params{Time: 3, Memory: 65536, Threads: 0, KeyLen: 32, Salt: salt}},
		{"clave corta", Params{Time: 3, Memory: 65536, Threads: 4, KeyLen: 8, Salt: salt}},
		{"salt corto", Params{Time: 3, Memory: 65536, Threads: 4, KeyLen: 32, Salt: []byte{1}}},
		{"sin salt", Params{Time: 3, Memory: 65536, Threads: 4, KeyLen: 32}},
	}
	for _, c := range cases {
		if _, err := DeriveKEK([]byte("x"), c.p); !errors.Is(err, ErrParams) {
			t.Errorf("%s: err = %v, want %v", c.name, err, ErrParams)
		}
	}
}

// TestWrappedDEKFailsLoudlyWhenCorrupt es LA LECCIÓN DE LA SEMILLA SILENCIOSA
// aplicada a la DEK.
//
// Con Ed25519 aprendimos que una semilla corrupta no da error: da otra
// identidad, en silencio. Con la DEK eso sería peor —se cifrarían datos con una
// clave que nadie podrá reproducir— y no puede ocurrir, porque el envoltorio es
// autenticado. Este test lo comprueba volteando un bit en CADA byte del material
// envuelto: todas las variantes deben fallar, y ninguna devolver una clave.
func TestWrappedDEKFailsLoudlyWhenCorrupt(t *testing.T) {
	kek, err := DeriveKEK([]byte("passphrase de prueba"), DefaultParams(bytes.Repeat([]byte{2}, SaltLen)))
	if err != nil {
		t.Fatal(err)
	}
	dek := bytes.Repeat([]byte{0xAB}, DEKLen)

	wrapped, err := WrapDEK(kek, dek, testVaultID)
	if err != nil {
		t.Fatal(err)
	}
	got, err := UnwrapDEK(kek, wrapped, testVaultID)
	if err != nil {
		t.Fatalf("el envoltorio legítimo no se abre: %v", err)
	}
	if !bytes.Equal(got, dek) {
		t.Fatal("la DEK desenvuelta no es la original")
	}

	for i := range wrapped {
		corrupt := append([]byte(nil), wrapped...)
		corrupt[i] ^= 0x01 // un solo bit
		out, err := UnwrapDEK(kek, corrupt, testVaultID)
		if err == nil {
			t.Errorf("byte %d: el envoltorio corrupto se abrió sin error", i)
			continue
		}
		if !errors.Is(err, ErrUnwrap) {
			t.Errorf("byte %d: err = %v, want %v", i, err, ErrUnwrap)
		}
		if out != nil {
			t.Errorf("byte %d: devolvió material (%d bytes) además del error", i, len(out))
		}
	}

	for _, n := range []int{0, 1, 24, len(wrapped) - 1} {
		if _, err := UnwrapDEK(kek, wrapped[:n], testVaultID); !errors.Is(err, ErrUnwrap) {
			t.Errorf("truncado a %d: err = %v, want %v", n, err, ErrUnwrap)
		}
	}
}

// TestUnwrapRejectsWrongKeyAndVault comprueba que el AAD ate el envoltorio a su
// vault y que otra KEK no sirva.
func TestUnwrapRejectsWrongKeyAndVault(t *testing.T) {
	params := DefaultParams(bytes.Repeat([]byte{3}, SaltLen))
	kek, err := DeriveKEK([]byte("la buena"), params)
	if err != nil {
		t.Fatal(err)
	}
	otherKEK, err := DeriveKEK([]byte("la mala"), params)
	if err != nil {
		t.Fatal(err)
	}
	dek := bytes.Repeat([]byte{0xCD}, DEKLen)
	wrapped, err := WrapDEK(kek, dek, testVaultID)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := UnwrapDEK(otherKEK, wrapped, testVaultID); !errors.Is(err, ErrUnwrap) {
		t.Errorf("otra KEK: err = %v, want %v", err, ErrUnwrap)
	}
	if _, err := UnwrapDEK(kek, wrapped, "otro-vault"); !errors.Is(err, ErrUnwrap) {
		t.Errorf("otro vaultID: err = %v, want %v", err, ErrUnwrap)
	}
	if _, err := WrapDEK(kek, dek[:16], testVaultID); !errors.Is(err, ErrKeySize) {
		t.Errorf("DEK corta: err = %v, want %v", err, ErrKeySize)
	}
	if _, err := WrapDEK(kek[:16], dek, testVaultID); !errors.Is(err, ErrKeySize) {
		t.Errorf("KEK corta: err = %v, want %v", err, ErrKeySize)
	}
}

// TestCreateAndUnlock cubre el ciclo con persistencia simulada.
func TestCreateAndUnlock(t *testing.T) {
	ms := newMemStore()
	pass := []byte("passphrase del tenant")

	v, err := Create(ms, testVaultID, pass)
	if err != nil {
		t.Fatal(err)
	}
	if v.ID() != testVaultID {
		t.Errorf("ID = %q", v.ID())
	}
	// La DEK en claro no puede haber tocado el almacén.
	for k, stored := range ms.m {
		if bytes.Contains(stored, v.dek) {
			t.Fatalf("la DEK en claro aparece en vault_meta[%s]", k)
		}
	}

	reopened, err := Unlock(ms, pass)
	if err != nil {
		t.Fatalf("Unlock con la passphrase correcta: %v", err)
	}
	if !bytes.Equal(reopened.dek, v.dek) {
		t.Error("el vault reabierto no recuperó la misma DEK")
	}
	if reopened.ID() != testVaultID {
		t.Errorf("ID tras reabrir = %q", reopened.ID())
	}

	// Passphrase incorrecta: falla limpio, sin devolver un vault utilizable.
	bad, err := Unlock(ms, []byte("passphrase equivocada"))
	if !errors.Is(err, ErrUnwrap) {
		t.Errorf("passphrase incorrecta: err = %v, want %v", err, ErrUnwrap)
	}
	if bad != nil {
		t.Error("Unlock devolvió un vault pese al error")
	}

	if _, err := Unlock(newMemStore(), pass); !errors.Is(err, ErrNoVault) {
		t.Errorf("base sin vault: err = %v, want %v", err, ErrNoVault)
	}

	// Entradas inválidas al crear.
	if _, err := Create(newMemStore(), "", pass); err == nil {
		t.Error("creó un vault sin identificador")
	}
	if _, err := Create(newMemStore(), testVaultID, nil); err == nil {
		t.Error("creó un vault sin passphrase")
	}

	reopened.Close()
	if reopened.dek != nil {
		t.Error("Close no soltó la DEK")
	}
}
