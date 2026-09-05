package keys

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

// Vectores oficiales de RFC 8032 §7.1, verificados con OpenSSL antes de
// escribirlos aquí: la clave pública se derivó con `openssl pkey -pubout` sobre
// un PKCS#8 armado con la semilla cruda, y la firma con `openssl pkeyutl -sign
// -rawin`. Ninguno de estos valores sale del código que se está probando.
const (
	rfc8032Test1SeedHex = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
	rfc8032Test1PubHex  = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"

	rfc8032Test2SeedHex = "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"
	rfc8032Test2PubHex  = "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"
	rfc8032Test2MsgHex  = "72"
	rfc8032Test2SigHex  = "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da" +
		"085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
)

// TestRFC8032Vectors ata la reconstrucción desde semilla a los vectores
// oficiales: si PrivateKeyFromSeedHex derivara mal, la clave pública no
// coincidiría con la que produce OpenSSL para la misma semilla.
func TestRFC8032Vectors(t *testing.T) {
	cases := []struct {
		name    string
		seedHex string
		pubHex  string
	}{
		{"RFC 8032 TEST 1", rfc8032Test1SeedHex, rfc8032Test1PubHex},
		{"RFC 8032 TEST 2", rfc8032Test2SeedHex, rfc8032Test2PubHex},
	}
	for _, c := range cases {
		priv, err := PrivateKeyFromSeedHex(c.seedHex)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		pub, ok := priv.Public().(ed25519.PublicKey)
		if !ok {
			t.Fatalf("%s: la clave privada no expone una pública Ed25519", c.name)
		}
		if got := PublicKeyHex(pub); got != c.pubHex {
			t.Errorf("%s: pública = %s, want %s", c.name, got, c.pubHex)
		}
		if got := SeedHex(priv); got != c.seedHex {
			t.Errorf("%s: semilla = %s, want %s", c.name, got, c.seedHex)
		}
	}

	// La firma también debe coincidir con el vector: es lo que demuestra que la
	// clave reconstruida es la misma, no solo una del mismo tamaño.
	priv, err := PrivateKeyFromSeedHex(rfc8032Test2SeedHex)
	if err != nil {
		t.Fatal(err)
	}
	msg, err := hex.DecodeString(rfc8032Test2MsgHex)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(ed25519.Sign(priv, msg)); got != rfc8032Test2SigHex {
		t.Errorf("firma = %s, want %s", got, rfc8032Test2SigHex)
	}
}

// TestParsePublicKeyHexRoundTrip comprueba el camino hex -> clave -> hex.
func TestParsePublicKeyHexRoundTrip(t *testing.T) {
	pub, err := ParsePublicKeyHex(rfc8032Test1PubHex)
	if err != nil {
		t.Fatal(err)
	}
	if len(pub) != ed25519.PublicKeySize {
		t.Fatalf("longitud = %d, want %d", len(pub), ed25519.PublicKeySize)
	}
	if got := PublicKeyHex(pub); got != rfc8032Test1PubHex {
		t.Errorf("round-trip = %s, want %s", got, rfc8032Test1PubHex)
	}
	// El hexadecimal en mayúsculas decodifica al mismo material, y vuelve a
	// serializarse en minúsculas: la forma canónica es la que emite el paquete.
	upper, err := ParsePublicKeyHex(strings.ToUpper(rfc8032Test1PubHex))
	if err != nil {
		t.Fatalf("mayúsculas: %v", err)
	}
	if PublicKeyHex(upper) != rfc8032Test1PubHex {
		t.Error("el hex en mayúsculas no normaliza a la misma clave")
	}
}

// TestGenerateRoundTrip es el ciclo real de uso: generar, serializar a hex,
// reconstruir, y comprobar que la clave reconstruida firma igual que la
// original y que su firma verifica con la pública parseada.
func TestGenerateRoundTrip(t *testing.T) {
	pub, priv, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	if len(pub) != ed25519.PublicKeySize || len(priv) != ed25519.PrivateKeySize {
		t.Fatalf("tamaños: pub=%d priv=%d", len(pub), len(priv))
	}

	pubHex := PublicKeyHex(pub)
	seedHex := SeedHex(priv)
	if len(pubHex) != ed25519.PublicKeySize*2 {
		t.Errorf("pubHex mide %d caracteres, want %d", len(pubHex), ed25519.PublicKeySize*2)
	}
	if len(seedHex) != ed25519.SeedSize*2 {
		t.Errorf("seedHex mide %d caracteres, want %d", len(seedHex), ed25519.SeedSize*2)
	}

	restored, err := PrivateKeyFromSeedHex(seedHex)
	if err != nil {
		t.Fatal(err)
	}
	if !restored.Equal(priv) {
		t.Error("la clave privada reconstruida no es igual a la original")
	}

	parsedPub, err := ParsePublicKeyHex(pubHex)
	if err != nil {
		t.Fatal(err)
	}
	if !parsedPub.Equal(pub) {
		t.Error("la clave pública parseada no es igual a la original")
	}

	// La reconstruida firma y la pública parseada verifica: es lo único que
	// importa de verdad para el ledger, que persiste solo la semilla.
	msg := []byte("bloque a sellar")
	sig := ed25519.Sign(restored, msg)
	if !ed25519.Verify(parsedPub, msg, sig) {
		t.Error("la firma de la clave reconstruida no verifica con la pública parseada")
	}
	if !ed25519.Verify(pub, msg, sig) {
		t.Error("la firma de la clave reconstruida no verifica con la pública original")
	}
	// Y Ed25519 es determinista: ambas claves producen los mismos bytes.
	if hex.EncodeToString(ed25519.Sign(priv, msg)) != hex.EncodeToString(sig) {
		t.Error("original y reconstruida producen firmas distintas")
	}
}

// TestGenerateProducesDistinctKeys comprueba que Generate no devuelva siempre lo
// mismo, que sería el fallo más grave posible en este paquete.
func TestGenerateProducesDistinctKeys(t *testing.T) {
	seen := make(map[string]bool, 16)
	for i := 0; i < 16; i++ {
		_, priv, err := Generate()
		if err != nil {
			t.Fatal(err)
		}
		s := SeedHex(priv)
		if seen[s] {
			t.Fatalf("Generate repitió una semilla: %s", s)
		}
		seen[s] = true
	}
}

// TestParsePublicKeyHexRejects recorre las entradas inválidas.
func TestParsePublicKeyHexRejects(t *testing.T) {
	cases := []struct {
		name string
		in   string
	}{
		{"vacío", ""},
		{"no hexadecimal", strings.Repeat("z", 64)},
		{"longitud impar", rfc8032Test1PubHex[:63]},
		{"demasiado corto", rfc8032Test1PubHex[:62]},
		{"demasiado largo", rfc8032Test1PubHex + "ab"},
		{"tamaño de semilla, no de clave", rfc8032Test1PubHex[:32]},
		{"con espacios", " " + rfc8032Test1PubHex[1:]},
		{"con prefijo 0x", "0x" + rfc8032Test1PubHex[2:]},
	}
	for _, c := range cases {
		if _, err := ParsePublicKeyHex(c.in); !errors.Is(err, ErrInvalidPublicKey) {
			t.Errorf("%s: err = %v, want %v", c.name, err, ErrInvalidPublicKey)
		}
	}
}

// TestPrivateKeyFromSeedHexRejects recorre las semillas inválidas.
func TestPrivateKeyFromSeedHexRejects(t *testing.T) {
	cases := []struct {
		name string
		in   string
	}{
		{"vacía", ""},
		{"no hexadecimal", strings.Repeat("g", 64)},
		{"longitud impar", rfc8032Test1SeedHex[:63]},
		{"demasiado corta", rfc8032Test1SeedHex[:62]},
		{"demasiado larga", rfc8032Test1SeedHex + "ff"},
		{"clave privada completa en vez de semilla", rfc8032Test1SeedHex + rfc8032Test1PubHex},
		{"con espacios", rfc8032Test1SeedHex[:63] + " "},
		{"con prefijo 0x", "0x" + rfc8032Test1SeedHex[2:]},
	}
	for _, c := range cases {
		if _, err := PrivateKeyFromSeedHex(c.in); !errors.Is(err, ErrInvalidSeed) {
			t.Errorf("%s: err = %v, want %v", c.name, err, ErrInvalidSeed)
		}
	}
}

// TestCorruptSeedYieldsDifferentIdentity comprueba lo que de verdad importa de
// una semilla corrupta: no da error —cualquier cadena de 32 bytes es una semilla
// válida— sino OTRA identidad, cuyas firmas no pasan con la clave original.
// Quien restaure un respaldo dañado no obtiene un fallo ruidoso, obtiene una
// identidad distinta; de ahí que el respaldo SLIP-0039 lleve su propia suma de
// verificación.
func TestCorruptSeedYieldsDifferentIdentity(t *testing.T) {
	original, err := PrivateKeyFromSeedHex(rfc8032Test1SeedHex)
	if err != nil {
		t.Fatal(err)
	}
	originalPub := original.Public().(ed25519.PublicKey)

	// Un solo carácter distinto en la semilla.
	corrupt := []byte(rfc8032Test1SeedHex)
	if corrupt[0] == 'a' {
		corrupt[0] = 'b'
	} else {
		corrupt[0] = 'a'
	}
	restored, err := PrivateKeyFromSeedHex(string(corrupt))
	if err != nil {
		t.Fatalf("una semilla corrupta pero bien formada no debería dar error: %v", err)
	}
	if restored.Equal(original) {
		t.Fatal("una semilla distinta produjo la misma clave")
	}
	corruptPub := restored.Public().(ed25519.PublicKey)
	if PublicKeyHex(corruptPub) == PublicKeyHex(originalPub) {
		t.Fatal("una semilla distinta produjo la misma clave pública")
	}

	msg := []byte("bloque a sellar")
	if ed25519.Verify(originalPub, msg, ed25519.Sign(restored, msg)) {
		t.Error("una firma de la identidad corrupta verifica con la clave original")
	}
	if ed25519.Verify(corruptPub, msg, ed25519.Sign(original, msg)) {
		t.Error("una firma de la identidad original verifica con la clave corrupta")
	}
}
