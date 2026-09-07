package commit

import (
	"bytes"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

// Los goldens de este fichero se calcularon FUERA de este código:
//
//   - El HMAC, con `openssl dgst -sha256 -mac HMAC -macopt hexkey:...` y
//     comprobado además con el módulo hmac de python. Las dos herramientas
//     coinciden byte a byte.
//   - El HKDF, con una implementación de RFC 5869 escrita en python sobre
//     hashlib, independiente de golang.org/x/crypto/hkdf.
//
// Es la regla anti-circularidad. Un golden calculado con la misma función que
// se verifica no prueba que la función sea correcta, solo que es consistente
// consigo misma.

const (
	// tenant y dek fijos de los goldens.
	goldenTenant = "1790012345001"
	// clave derivada con HKDF-SHA256(dek=0x11×32, salt vacío,
	// info="nucleo/commit/hmac-sha256/v1\x00"+tenant)
	goldenKey = "16b62b73666f94792480ed54b9503adab9404ef861c1101e6713e4d455578dd8"
)

func goldenDEK() []byte { return bytes.Repeat([]byte{0x11}, 32) }

// TestDeriveKeyGolden fija la derivación contra un HKDF calculado en python.
func TestDeriveKeyGolden(t *testing.T) {
	key, err := DeriveKey(goldenDEK(), goldenTenant)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(key); got != goldenKey {
		t.Errorf("clave = %s\nwant  %s (HKDF calculado en python sobre hashlib)", got, goldenKey)
	}
}

// TestCommitFieldGolden fija el HMAC contra openssl.
func TestCommitFieldGolden(t *testing.T) {
	key, err := DeriveKey(goldenDEK(), goldenTenant)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ field, value, want string }{
		{"cedula", "1712345678", "hmac-sha256/v1:6258c00ce72e474a837e152866d49ed201916e86ce189105717f5223192b873c"},
		{"importe", "10000.00", "hmac-sha256/v1:595953d797ef62fa2b0f5a200553ca4aa8b295b6e95b28f6b9a4e8b33be866ae"},
	} {
		got, err := CommitField(key, c.field, c.value)
		if err != nil {
			t.Fatal(err)
		}
		if got != c.want {
			t.Errorf("%s=%s\n got  %s\n want %s", c.field, c.value, got, c.want)
		}
		if !VerifyField(key, c.field, c.value, c.want) {
			t.Errorf("%s=%s: el compromiso golden no verifica", c.field, c.value)
		}
	}

	// Y el HMAC crudo, sin el prefijo del algoritmo, contra el que dio openssl
	// para el mensaje "cedula\x001712345678" con la clave 0x42×32.
	raw, err := CommitField(bytes.Repeat([]byte{0x42}, 32), "cedula", "1712345678")
	if err != nil {
		t.Fatal(err)
	}
	const opensslGolden = "f949b114a53c75a97a07c3933f3b911de37c858dd4a77e8872771af38fa71a0f"
	if raw != Alg+":"+opensslGolden {
		t.Errorf("HMAC = %s, want %s (openssl dgst -mac HMAC)", raw, opensslGolden)
	}
}

// TestDifferentTenantsDifferentCommitments: el mismo valor con claves distintas
// da compromisos distintos. Es lo que impide cruzar los ledgers de dos empresas
// buscando coincidencias: que la misma cédula aparezca en ambos no se nota.
func TestDifferentTenantsDifferentCommitments(t *testing.T) {
	a, err := DeriveKey(goldenDEK(), goldenTenant)
	if err != nil {
		t.Fatal(err)
	}
	b, err := DeriveKey(goldenDEK(), "0999999999001")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a, b) {
		t.Fatal("dos tenants de la misma DEK obtuvieron la misma clave")
	}

	ca, _ := CommitField(a, "cedula", "1712345678")
	cb, _ := CommitField(b, "cedula", "1712345678")
	if ca == cb {
		t.Error("el mismo valor produjo el mismo compromiso con claves distintas")
	}
	// El segundo también está fijado desde fuera.
	const golden = "hmac-sha256/v1:db51202c273ee6fdbee9e7bc3f78b44ae01ada5fa9deb02517442da163e8bb81"
	if cb != golden {
		t.Errorf("otro tenant: %s, want %s", cb, golden)
	}
}

// TestDeterministic: mismo valor y misma clave, mismo compromiso. Sin esto no
// se podría comprobar nada después.
func TestDeterministic(t *testing.T) {
	key, _ := DeriveKey(goldenDEK(), goldenTenant)
	first, _ := CommitField(key, "cedula", "1712345678")
	for i := 0; i < 5; i++ {
		again, _ := CommitField(key, "cedula", "1712345678")
		if again != first {
			t.Fatalf("iteración %d dio otro compromiso", i)
		}
	}
}

// TestFieldNameIsAuthenticated: el nombre del campo entra en el mensaje. Sin
// eso, el compromiso de una cédula "1712345678" y el de un número de orden con
// el mismo texto serían idénticos, y quien viera los dos sabría que coinciden
// aunque signifiquen cosas distintas.
func TestFieldNameIsAuthenticated(t *testing.T) {
	key, _ := DeriveKey(goldenDEK(), goldenTenant)
	a, _ := CommitField(key, "cedula", "1712345678")
	b, _ := CommitField(key, "orden", "1712345678")
	if a == b {
		t.Error("el nombre del campo no entra en el compromiso")
	}

	// Y el separador impide la ambigüedad por concatenación: sin el 0x00,
	// ("ceduula","x") y ("cedu","ulax") producirían el mismo mensaje.
	c, _ := CommitField(key, "ab", "cd")
	d, _ := CommitField(key, "a", "bcd")
	if c == d {
		t.Error("la concatenación campo‖valor es ambigua: falta el separador")
	}
}

// TestDictionaryIsUselessWithoutTheKey documenta POR QUÉ existe este paquete.
//
// Una cédula ecuatoriana tiene diez dígitos. Con un hash desnudo, recorrer el
// espacio entero es cuestión de minutos y el dato queda al descubierto. Aquí se
// recorre un diccionario pequeño con la clave EQUIVOCADA —que es lo que tiene
// un atacante— y no acierta ninguno; con la clave correcta, acierta el que es.
func TestDictionaryIsUselessWithoutTheKey(t *testing.T) {
	real, _ := DeriveKey(goldenDEK(), goldenTenant)
	attacker, _ := DeriveKey(bytes.Repeat([]byte{0x99}, 32), goldenTenant)

	const secreto = "1712345678"
	objetivo, _ := CommitField(real, "cedula", secreto)

	// El diccionario del atacante incluye el valor correcto.
	diccionario := []string{"1700000000", "1712345678", "0999999999", "1799999999"}
	for _, candidato := range diccionario {
		if VerifyField(attacker, "cedula", candidato, objetivo) {
			t.Fatalf("sin la clave se adivinó el valor %q", candidato)
		}
	}

	// Con la clave, el mismo diccionario lo encuentra a la primera pasada.
	var encontrado string
	for _, candidato := range diccionario {
		if VerifyField(real, "cedula", candidato, objetivo) {
			encontrado = candidato
		}
	}
	if encontrado != secreto {
		t.Fatalf("con la clave correcta no se encontró el valor: %q", encontrado)
	}
}

// TestRejectsBadInput cubre las entradas que no forman un compromiso.
func TestRejectsBadInput(t *testing.T) {
	if _, err := DeriveKey(nil, goldenTenant); !errors.Is(err, ErrKey) {
		t.Errorf("DEK vacía: err = %v", err)
	}
	if _, err := DeriveKey(goldenDEK(), ""); !errors.Is(err, ErrKey) {
		t.Errorf("tenant vacío: err = %v", err)
	}
	if _, err := CommitField(make([]byte, 16), "c", "v"); !errors.Is(err, ErrKey) {
		t.Errorf("clave corta: err = %v", err)
	}
	key, _ := DeriveKey(goldenDEK(), goldenTenant)
	if _, err := CommitField(key, "", "v"); !errors.Is(err, ErrFormat) {
		t.Errorf("campo vacío: err = %v", err)
	}
	if VerifyField(key, "cedula", "x", "no-es-un-compromiso") {
		t.Error("verificó contra un compromiso mal formado")
	}
}

// TestRaw comprueba la extracción de los bytes.
func TestRaw(t *testing.T) {
	key, _ := DeriveKey(goldenDEK(), goldenTenant)
	c, _ := CommitField(key, "cedula", "1712345678")
	raw, err := Raw(c)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) != 32 {
		t.Errorf("%d bytes, want 32", len(raw))
	}
	if !strings.HasPrefix(c, Alg+":") {
		t.Errorf("el compromiso no lleva el algoritmo: %q", c)
	}
	for _, malo := range []string{"", "otro:aabb", Alg + ":zz", Alg + ":aabb"} {
		if _, err := Raw(malo); !errors.Is(err, ErrFormat) {
			t.Errorf("%q: err = %v, want %v", malo, err, ErrFormat)
		}
	}
}
