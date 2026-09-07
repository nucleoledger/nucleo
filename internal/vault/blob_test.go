package vault

import (
	"bytes"
	"encoding/hex"
	"errors"
	"strings"
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
		want          error
	}{
		{"payload_hash de otra factura", testTenant, hashB, ErrDecrypt},
		{"otro tenant", "9999999999001", hashA, ErrDecrypt},
		{"tenant y hash de otra factura", "9999999999001", hashB, ErrDecrypt},
		// Estos dos ni llegan al AEAD: un AAD mal formado se rechaza antes.
		{"tenant vacío", "", hashA, ErrAAD},
		{"hash vacío", testTenant, "", ErrAAD},
	}
	for _, c := range cases {
		if _, err := DecryptBlob(dek, c.tenant, c.pHash, ctA, nonceA); !errors.Is(err, c.want) {
			t.Errorf("%s: err = %v, want %v", c.name, err, c.want)
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
	if _, _, err := EncryptBlob(dek, "", hashA, plainA); !errors.Is(err, ErrAAD) {
		t.Errorf("cifró sin tenant en el AAD: err = %v", err)
	}
	if _, _, err := EncryptBlob(dek, testTenant, "", plainA); !errors.Is(err, ErrAAD) {
		t.Errorf("cifró sin payload_hash en el AAD: err = %v", err)
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

// TestAADCollisionIsRejected reproduce el hallazgo de la auditoría externa.
//
// El AAD de PROTOCOL §5 es tenant ‖ payload_hash sin separador, así que por sí
// sola la concatenación es ambigua: el tenant "A" con el hash "B…" produce
// EXACTAMENTE los mismos bytes que el tenant "AB" con el hash "…". Sin
// validación, un blob cifrado bajo un par se descifraría bajo el otro, y el
// amarre al compromiso —que es lo que el AAD existe para garantizar— dejaría de
// significar nada.
//
// La primera mitad del test demuestra que la colisión es real a nivel de bytes.
// La segunda, que ya no se puede alcanzar: el sufijo tiene longitud fija de 64
// caracteres, así que la frontera entre tenant y hash está determinada y solo
// hay una lectura posible. El formato de PROTOCOL §5 no cambia.
func TestAADCollisionIsRejected(t *testing.T) {
	h := hashHex("factura-colisión")
	if len(h) != PayloadHashLen {
		t.Fatalf("el hash de prueba mide %d caracteres", len(h))
	}

	// Par legítimo y par colisionante: distintos argumentos, mismos bytes.
	legit := blobAAD("AB", h)
	collide := blobAAD("A", "B"+h)
	if !bytes.Equal(legit, collide) {
		t.Fatalf("la colisión no se reproduce: %q vs %q", legit, collide)
	}

	dek := bytes.Repeat([]byte{0x33}, DEKLen)
	ct, nonce, err := EncryptBlob(dek, "AB", h, []byte("importe 1000"))
	if err != nil {
		t.Fatal(err)
	}
	// Sin la validación, esto DEVOLVERÍA el texto en claro: el AEAD ve el mismo
	// AAD. Con ella, ni se intenta.
	if _, err := DecryptBlob(dek, "A", "B"+h, ct, nonce); !errors.Is(err, ErrAAD) {
		t.Fatalf("el par colisionante no se rechazó: err = %v, want %v", err, ErrAAD)
	}
	if _, _, err := EncryptBlob(dek, "A", "B"+h, []byte("importe 1000")); !errors.Is(err, ErrAAD) {
		t.Errorf("se cifró bajo el par colisionante: err = %v", err)
	}
}

// TestAADRejectsMalformedPayloadHash cubre el resto de la regla: longitud exacta
// y hexadecimal en minúscula.
func TestAADRejectsMalformedPayloadHash(t *testing.T) {
	dek := bytes.Repeat([]byte{0x44}, DEKLen)
	// Un hash con letras de verdad: el hashHex de estos tests rellena con ceros
	// y saldrían solo dígitos, con lo que ToUpper no cambiaría nada y el caso
	// de las mayúsculas no probaría nada.
	h := strings.Repeat("ab", 32)
	if strings.ToUpper(h) == h {
		t.Fatal("el hash de prueba no tiene letras: el caso de mayúsculas no probaría nada")
	}

	cases := []struct {
		name  string
		pHash string
	}{
		{"63 caracteres", h[:63]},
		{"65 caracteres", h + "0"},
		{"vacío", ""},
		{"hex en mayúscula", strings.ToUpper(h)},
		{"una mayúscula suelta", strings.ToUpper(h[:1]) + h[1:]},
		{"carácter no hexadecimal", "z" + h[1:]},
		{"con espacio", " " + h[1:]},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, _, err := EncryptBlob(dek, testTenant, c.pHash, []byte("x")); !errors.Is(err, ErrAAD) {
				t.Errorf("EncryptBlob: err = %v, want %v", err, ErrAAD)
			}
			if _, err := DecryptBlob(dek, testTenant, c.pHash, []byte("x"), make([]byte, 24)); !errors.Is(err, ErrAAD) {
				t.Errorf("DecryptBlob: err = %v, want %v", err, ErrAAD)
			}
		})
	}

	// Control negativo: el hash bien formado sí pasa la validación.
	if _, _, err := EncryptBlob(dek, testTenant, h, []byte("x")); err != nil {
		t.Errorf("un payload_hash correcto se rechazó: %v", err)
	}
}

// TestSecretDomainSeparation comprueba que el material interno del vault viva
// en un dominio propio, incompatible con el de los payloads de bloque.
//
// Sin esa separación, un secreto interno podría descifrarse como si fuera un
// payload —o al revés— y dos cosas con significados distintos compartirían
// clave y AAD. Es el mismo razonamiento que separa 0x01 de 0x04 en los key ID.
func TestSecretDomainSeparation(t *testing.T) {
	v := newVaultForTest(t, "vault-a")

	secreto := []byte("semilla de firma, nada que deba salir de aquí")
	ct, nonce, err := v.EncryptSecret("identity/v1", secreto)
	if err != nil {
		t.Fatal(err)
	}

	back, err := v.DecryptSecret("identity/v1", ct, nonce)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(back, secreto) {
		t.Error("el round-trip no devolvió el secreto")
	}

	// Otro dominio NO abre lo del primero.
	if _, err := v.DecryptSecret("otro/v1", ct, nonce); !errors.Is(err, ErrDecrypt) {
		t.Errorf("otro dominio descifró el secreto: %v", err)
	}
	// Y el camino de los blobs tampoco, ni con el AAD mejor elegido.
	if _, err := v.DecryptBlob(testTenant, strings.Repeat("ab", 32), ct, nonce); err == nil {
		t.Error("un secreto interno se descifró como si fuera un payload")
	}
	// Un dominio vacío se rechaza: sería un secreto sin dominio.
	if _, _, err := v.EncryptSecret("", secreto); !errors.Is(err, ErrAAD) {
		t.Errorf("dominio vacío: err = %v, want %v", err, ErrAAD)
	}
	if _, err := v.DecryptSecret("", ct, nonce); !errors.Is(err, ErrAAD) {
		t.Errorf("dominio vacío: err = %v, want %v", err, ErrAAD)
	}
}

// TestSecretsAreBoundToTheirVault: el AAD lleva el identificador del vault, así
// que copiar el material cifrado a otro vault no sirve de nada aunque compartan
// passphrase.
func TestSecretsAreBoundToTheirVault(t *testing.T) {
	v1 := newVaultForTest(t, "vault-a")
	v2 := newVaultForTest(t, "vault-b")
	if v1.ID() == v2.ID() {
		t.Fatal("los dos vaults comparten identificador: el test no probaría nada")
	}

	ct, nonce, err := v1.EncryptSecret("identity/v1", []byte("secreto"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v2.DecryptSecret("identity/v1", ct, nonce); !errors.Is(err, ErrDecrypt) {
		t.Errorf("otro vault descifró el secreto: %v", err)
	}
}

// newVaultForTest crea un vault en memoria con el identificador dado.
func newVaultForTest(t *testing.T, id string) *Vault {
	t.Helper()
	v, err := Create(newMemStore(), id, []byte("passphrase del tenant"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(v.Close)
	return v
}
