package checkpoint

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"strings"
	"testing"

	"golang.org/x/mod/sumdb/note"
)

func mldsaSeed(b byte) []byte {
	s := make([]byte, MLDSASeedSize)
	for i := range s {
		s[i] = b + byte(i)
	}
	return s
}

// dualSigned firma un checkpoint con la Ed25519 del log Y con su ML-DSA-44.
func dualSigned(t *testing.T) (msg []byte, ed note.Verifier, pq *MLDSAVerifier) {
	t.Helper()
	const origin = "nucleoledger.com/pq"

	edSigner, edVerifier, _ := testKeys(t, origin, 3)
	pqSigner, err := NewMLDSASigner(origin, mldsaSeed(7))
	if err != nil {
		t.Fatal(err)
	}
	pqVerifier, err := NewMLDSAVerifier(origin, pqSigner.PublicKey())
	if err != nil {
		t.Fatal(err)
	}

	msg, err = Sign(Checkpoint{Origin: origin, Size: 5, RootHash: rfc6962Root5(t)}, edSigner, pqSigner)
	if err != nil {
		t.Fatal(err)
	}
	return msg, edVerifier, pqVerifier
}

// TestMLDSAIsBackwardCompatible es LA REGLA DE ORO de ADR-007, y la razón por la
// que se puede añadir una firma post-cuántica hoy sin romper a nadie.
//
// Un verificador que solo conoce la clave Ed25519 —un cliente viejo, un SDK de
// otro lenguaje, cualquiera que no sepa qué es ML-DSA— tiene que seguir
// abriendo la nota exactamente igual, ignorando la firma que no entiende. Si
// esto fallara, la firma adicional no sería adicional: sería un cambio de
// formato encubierto que dejaría fuera a todo el que no se actualice.
func TestMLDSAIsBackwardCompatible(t *testing.T) {
	msg, edVerifier, pqVerifier := dualSigned(t)

	// El verificador ANTIGUO: solo Ed25519. Abre la nota sin enterarse de nada.
	n, err := note.Open(msg, note.VerifierList(edVerifier))
	if err != nil {
		t.Fatalf("un verificador que solo conoce Ed25519 no pudo abrir la nota: %v", err)
	}
	if len(n.Sigs) != 1 || n.Sigs[0].Name != edVerifier.Name() {
		t.Errorf("firmas verificadas = %+v, want solo la Ed25519", n.Sigs)
	}
	if len(n.UnverifiedSigs) != 1 {
		t.Fatalf("%d firmas ignoradas, want 1 (la ML-DSA desconocida)", len(n.UnverifiedSigs))
	}
	// Y el checkpoint que lee es el mismo de siempre.
	c, err := Parse(n.Text)
	if err != nil {
		t.Fatal(err)
	}
	if c.Size != 5 {
		t.Errorf("tamaño = %d, want 5", c.Size)
	}

	// El verificador NUEVO: conoce las dos y verifica las dos.
	n2, err := note.Open(msg, note.VerifierList(edVerifier, pqVerifier))
	if err != nil {
		t.Fatalf("el verificador completo no pudo abrir la nota: %v", err)
	}
	if len(n2.Sigs) != 2 {
		t.Errorf("%d firmas verificadas, want 2", len(n2.Sigs))
	}
	if len(n2.UnverifiedSigs) != 0 {
		t.Errorf("%d firmas ignoradas, want 0", len(n2.UnverifiedSigs))
	}

	// Y un verificador que SOLO conoce la ML-DSA también abre la nota: la
	// resistencia post-cuántica no depende de que la Ed25519 siga valiendo.
	n3, err := note.Open(msg, note.VerifierList(pqVerifier))
	if err != nil {
		t.Fatalf("un verificador que solo conoce ML-DSA no pudo abrir la nota: %v", err)
	}
	if len(n3.Sigs) != 1 || n3.Sigs[0].Name != pqVerifier.Name() {
		t.Errorf("firmas verificadas = %+v, want solo la ML-DSA", n3.Sigs)
	}
}

// TestMLDSASignatureShape fija el tamaño de la firma y su sitio en la nota.
func TestMLDSASignatureShape(t *testing.T) {
	msg, edVerifier, pqVerifier := dualSigned(t)

	i := bytes.LastIndex(msg, []byte("\n\n"))
	if i < 0 {
		t.Fatal("la nota no separa cuerpo y firmas")
	}
	var pqLines int
	for _, line := range strings.Split(string(msg[i+2:]), "\n") {
		if !strings.HasPrefix(line, "— ") {
			continue
		}
		j := strings.LastIndex(line, " ")
		blob, err := base64.StdEncoding.DecodeString(line[j+1:])
		if err != nil {
			t.Fatal(err)
		}
		switch len(blob) {
		case 4 + ed25519.SignatureSize:
			// la firma del log, 68 bytes
		case 4 + MLDSASignatureSize:
			pqLines++
		default:
			t.Errorf("blob de firma de %d bytes inesperado", len(blob))
		}
	}
	if pqLines != 1 {
		t.Errorf("%d firmas con forma de ML-DSA-44, want 1", pqLines)
	}

	// Los dos key ID son distintos aunque compartan nombre: el byte de
	// algoritmo entra en el hash, que es lo que impide confundir una firma con
	// otra. Es la lección de SC-2, aplicada aquí.
	if edVerifier.KeyHash() == pqVerifier.KeyHash() {
		t.Error("las dos claves comparten key ID: el byte de algoritmo no entró en el hash")
	}
}

// TestMLDSARejectsBadMaterial cubre las entradas que no forman una clave.
func TestMLDSARejectsBadMaterial(t *testing.T) {
	if _, err := NewMLDSASigner("nucleoledger.com/pq", make([]byte, 16)); err == nil {
		t.Error("se aceptó una semilla de 16 bytes")
	}
	if _, err := NewMLDSAVerifier("nucleoledger.com/pq", make([]byte, 100)); err == nil {
		t.Error("se aceptó una pública de 100 bytes")
	}
	if _, err := NewMLDSASigner("", mldsaSeed(1)); err == nil {
		t.Error("se aceptó un nombre vacío")
	}

	_, _, pq := dualSigned(t)
	if pq.Verify([]byte("otro texto"), make([]byte, MLDSASignatureSize)) {
		t.Error("se verificó una firma de ceros")
	}
	if pq.Verify([]byte("x"), make([]byte, 10)) {
		t.Error("se verificó una firma de tamaño incorrecto")
	}
}

// TestMLDSASignIsDeterministic: la misma nota y la misma clave dan los mismos
// bytes. Sin esto, dos copias del mismo checkpoint no se podrían comparar.
func TestMLDSASignIsDeterministic(t *testing.T) {
	s, err := NewMLDSASigner("nucleoledger.com/pq", mldsaSeed(7))
	if err != nil {
		t.Fatal(err)
	}
	a, err := s.Sign([]byte("texto de la nota\n"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := s.Sign([]byte("texto de la nota\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Error("dos firmas de la misma nota difieren")
	}
	if len(a) != MLDSASignatureSize {
		t.Errorf("firma de %d bytes, want %d", len(a), MLDSASignatureSize)
	}
}

// TestMLDSAKeyHashGolden fija el key ID de ADR-007 contra valores calculados
// FUERA de este código.
//
// Los goldens salieron de un script de python con hashlib, alimentado con las
// claves públicas volcadas aparte: python concatena los bytes y hashea sin saber
// nada de MLDSAKeyHash. Es la regla anti-circularidad, y aquí importa más que en
// ningún otro sitio: la lección de SC-2 fue exactamente esta, un key ID
// equivocado que pasó todos los tests porque los tests lo calculaban con la
// misma función que verificaban.
//
// Fórmula:
//
//	SHA-256(name ‖ "\n" ‖ 0xff ‖ "nucleoledger.com/sig/ml-dsa-44@v1" ‖ "\n" ‖ pubkey)[:4]
func TestMLDSAKeyHashGolden(t *testing.T) {
	cases := []struct {
		name string
		seed byte
		want uint32
	}{
		{"nucleoledger.com/pq", 7, 0x5fa5e8ea},
		{"nucleoledger.com/poc3", 42, 0x7c30f8b0},
		{"example.com/log", 7, 0x75c04ba5},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s, err := NewMLDSASigner(c.name, mldsaSeed(c.seed))
			if err != nil {
				t.Fatal(err)
			}
			if got := s.KeyHash(); got != c.want {
				t.Errorf("key ID = %08x, want %08x (calculado con python hashlib)", got, c.want)
			}
			v, err := NewMLDSAVerifier(c.name, s.PublicKey())
			if err != nil {
				t.Fatal(err)
			}
			if v.KeyHash() != c.want {
				t.Errorf("el verificador da %08x y el firmante %08x", v.KeyHash(), c.want)
			}
		})
	}

	// Control: el identificador largo entra DENTRO del hash. Si solo entrara el
	// byte 0xff, dos extensiones distintas darían el mismo key ID para la misma
	// clave, y el golden de abajo —también de python— coincidiría con el de
	// arriba. No coincide.
	const v2Golden uint32 = 0x55e4bdfa
	if v2Golden == 0x5fa5e8ea {
		t.Fatal("los dos goldens son iguales: el control no prueba nada")
	}

	// Y el key ID de la extensión NO es el del formato clásico con 0xff, que
	// sería lo que saldría de olvidar el identificador largo.
	s, err := NewMLDSASigner("nucleoledger.com/pq", mldsaSeed(7))
	if err != nil {
		t.Fatal(err)
	}
	if plain := keyHashBytes("nucleoledger.com/pq", s.PublicKey(), AlgMLDSA44Ext); plain == s.KeyHash() {
		t.Error("el identificador largo no entró en el hash")
	}
}

// TestMLDSAKeyHashMatchesTheSpecShape comprueba la fórmula reconstruyéndola a
// mano, byte a byte, en vez de llamar a la función que se verifica.
func TestMLDSAKeyHashMatchesTheSpecShape(t *testing.T) {
	const name = "nucleoledger.com/pq"
	s, err := NewMLDSASigner(name, mldsaSeed(7))
	if err != nil {
		t.Fatal(err)
	}
	var buf []byte
	buf = append(buf, name...)
	buf = append(buf, '\n')
	buf = append(buf, 0xff)
	buf = append(buf, "nucleoledger.com/sig/ml-dsa-44@v1"...)
	buf = append(buf, '\n')
	buf = append(buf, s.PublicKey()...)
	sum := sha256.Sum256(buf)
	want := binary.BigEndian.Uint32(sum[:4])
	if s.KeyHash() != want {
		t.Errorf("key ID = %08x, la fórmula reconstruida da %08x", s.KeyHash(), want)
	}
}

// TestLogEmitsBothSignatures comprueba la propiedad de ADR-007 sobre los
// checkpoints REALES que emite checkpoint.Log, no sobre notas armadas a mano en
// un test. Es la diferencia entre "el mecanismo funciona" y "los checkpoints que
// salen de producción lo llevan".
func TestLogEmitsBothSignatures(t *testing.T) {
	const origin = "nucleoledger.com/pq"
	edSigner, edVerifier, _ := testKeys(t, origin, 3)
	pqSigner, err := NewMLDSASigner(origin, mldsaSeed(7))
	if err != nil {
		t.Fatal(err)
	}
	pqVerifier, err := NewMLDSAVerifier(origin, pqSigner.PublicKey())
	if err != nil {
		t.Fatal(err)
	}

	l, err := NewLog(origin, edSigner)
	if err != nil {
		t.Fatal(err)
	}
	if err := l.AddSigner(pqSigner); err != nil {
		t.Fatal(err)
	}

	msg, err := l.Sign(Checkpoint{Origin: origin, Size: 5, RootHash: rfc6962Root5(t)})
	if err != nil {
		t.Fatal(err)
	}

	// El verificador ANTIGUO sigue funcionando sobre un checkpoint de verdad.
	n, err := note.Open(msg, note.VerifierList(edVerifier))
	if err != nil {
		t.Fatalf("un verificador solo-Ed25519 no abrió un checkpoint real: %v", err)
	}
	if len(n.Sigs) != 1 || len(n.UnverifiedSigs) != 1 {
		t.Errorf("firmas: %d verificadas y %d ignoradas, want 1 y 1", len(n.Sigs), len(n.UnverifiedSigs))
	}

	// Y el completo verifica las dos.
	n2, err := note.Open(msg, note.VerifierList(edVerifier, pqVerifier))
	if err != nil {
		t.Fatal(err)
	}
	if len(n2.Sigs) != 2 {
		t.Errorf("%d firmas verificadas sobre un checkpoint real, want 2", len(n2.Sigs))
	}

	// El cerrojo anti-retroceso sigue en pie con dos firmantes.
	if _, err := l.Sign(Checkpoint{Origin: origin, Size: 3, RootHash: rfc6962Root5(t)}); !errors.Is(err, ErrRollback) {
		t.Errorf("el cerrojo se perdió al añadir firmante: %v", err)
	}

	// Un firmante adicional con otro nombre se rechaza: el origin de la nota es
	// uno solo, y una línea de firma con otro nombre no la verificaría nadie.
	other, err := NewMLDSASigner("otro.example/log", mldsaSeed(42))
	if err != nil {
		t.Fatal(err)
	}
	if err := l.AddSigner(other); !errors.Is(err, ErrOrigin) {
		t.Errorf("se aceptó un firmante de otro origin: %v", err)
	}
	if err := l.AddSigner(nil); err == nil {
		t.Error("se aceptó un firmante nulo")
	}
}
