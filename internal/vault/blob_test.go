package vault

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"
)

const testTenant = "1790012345001"

// hashHex devuelve un payload_hash de prueba con la forma correcta.
func hashHex(s string) string {
	h := make([]byte, 32)
	copy(h, s)
	return hex.EncodeToString(h)
}

// TestBlobRoundTrip cubre el ciclo básico y que sobreviva a reabrir el vault.
func TestBlobRoundTrip(t *testing.T) {
	ms := newMemStore()
	pass := []byte("passphrase del tenant")
	v, err := Create(ms, testVaultID, pass)
	if err != nil {
		t.Fatal(err)
	}
	plain := []byte("<autorizacion>XML de la factura</autorizacion>")
	h := hashHex("factura")

	ct, nonce, err := v.EncryptBlob(testTenant, h, plain)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(ct, plain) {
		t.Fatal("el texto plano aparece dentro del texto cifrado")
	}
	if len(nonce) != 24 {
		t.Errorf("nonce de %d bytes, want 24", len(nonce))
	}

	// El vault reabierto con la passphrase correcta descifra lo del original.
	reopened, err := Unlock(ms, pass)
	if err != nil {
		t.Fatal(err)
	}
	got, err := reopened.DecryptBlob(testTenant, h, ct, nonce)
	if err != nil {
		t.Fatalf("el vault reabierto no descifra lo que cifró el original: %v", err)
	}
	if !bytes.Equal(got, plain) {
		t.Errorf("texto plano = %q, want %q", got, plain)
	}

	// Payload vacío: cifrar nada sigue produciendo un texto autenticado.
	ctEmpty, nonceEmpty, err := v.EncryptBlob(testTenant, h, nil)
	if err != nil {
		t.Fatal(err)
	}
	back, err := v.DecryptBlob(testTenant, h, ctEmpty, nonceEmpty)
	if err != nil {
		t.Fatalf("no descifra un payload vacío: %v", err)
	}
	if len(back) != 0 {
		t.Errorf("payload vacío devolvió %d bytes", len(back))
	}
}

// TestBlobAADBinding es el ataque de intercambio de blobs: el texto cifrado de
// la factura A no debe descifrarse bajo el AAD de la factura B, aunque el
// atacante controle la base y pueda mover filas de sitio.
func TestBlobAADBinding(t *testing.T) {
	dek := bytes.Repeat([]byte{0x11}, DEKLen)
	hashA, hashB := hashHex("factura-A"), hashHex("factura-B")
	plainA := []byte("importe 1000")

	ctA, nonceA, err := EncryptBlob(dek, testTenant, hashA, plainA)
	if err != nil {
		t.Fatal(err)
	}
	// Control: bajo su propio AAD sí abre. Sin esto, el resto pasaría aunque
	// DecryptBlob fallara siempre.
	if _, err := DecryptBlob(dek, testTenant, hashA, ctA, nonceA); err != nil {
		t.Fatalf("no descifra bajo su propio AAD: %v", err)
	}

	cases := []struct {
		name          string
		tenant, pHash string
	}{
		{"payload_hash de otra factura", testTenant, hashB},
		{"otro tenant", "9999999999001", hashA},
		{"tenant y hash de otra factura", "9999999999001", hashB},
		{"tenant vacío", "", hashA},
		{"hash vacío", testTenant, ""},
	}
	for _, c := range cases {
		if _, err := DecryptBlob(dek, c.tenant, c.pHash, ctA, nonceA); !errors.Is(err, ErrDecrypt) {
			t.Errorf("%s: err = %v, want %v", c.name, err, ErrDecrypt)
		}
	}

	if _, err := DecryptBlob(bytes.Repeat([]byte{0x22}, DEKLen), testTenant, hashA, ctA, nonceA); !errors.Is(err, ErrDecrypt) {
		t.Error("otra DEK descifró el blob")
	}
	tampered := append([]byte(nil), ctA...)
	tampered[0] ^= 0xff
	if _, err := DecryptBlob(dek, testTenant, hashA, tampered, nonceA); !errors.Is(err, ErrDecrypt) {
		t.Error("un texto cifrado alterado se descifró")
	}
	_, nonceB, err := EncryptBlob(dek, testTenant, hashB, []byte("importe 2000"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecryptBlob(dek, testTenant, hashA, ctA, nonceB); !errors.Is(err, ErrDecrypt) {
		t.Error("un nonce ajeno descifró el blob")
	}
	if _, err := DecryptBlob(dek, testTenant, hashA, ctA, nonceA[:12]); !errors.Is(err, ErrDecrypt) {
		t.Error("un nonce de tamaño incorrecto no se rechazó")
	}

	// El AAD es obligatorio al cifrar: no se permite un blob sin amarre.
	if _, _, err := EncryptBlob(dek, "", hashA, plainA); err == nil {
		t.Error("cifró sin tenant en el AAD")
	}
	if _, _, err := EncryptBlob(dek, testTenant, "", plainA); err == nil {
		t.Error("cifró sin payload_hash en el AAD")
	}
	if _, _, err := EncryptBlob(dek[:16], testTenant, hashA, plainA); !errors.Is(err, ErrKeySize) {
		t.Errorf("DEK corta: err = %v, want %v", err, ErrKeySize)
	}
}

// TestNonceIsFresh comprueba que cifrar dos veces lo mismo no dé el mismo
// resultado: reutilizar un nonce en XChaCha20-Poly1305 sería catastrófico.
func TestNonceIsFresh(t *testing.T) {
	dek := bytes.Repeat([]byte{0x33}, DEKLen)
	h := hashHex("misma factura")
	seen := make(map[string]bool, 128)
	for i := 0; i < 64; i++ {
		ct, nonce, err := EncryptBlob(dek, testTenant, h, []byte("mismo contenido"))
		if err != nil {
			t.Fatal(err)
		}
		if seen[string(nonce)] {
			t.Fatal("nonce repetido")
		}
		seen[string(nonce)] = true
		if seen[string(ct)] {
			t.Fatal("texto cifrado repetido para el mismo texto plano")
		}
		seen[string(ct)] = true
	}
}
