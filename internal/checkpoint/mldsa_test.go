package checkpoint

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
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
	pqSigner, err := NewMLDSASigner(origin, mldsaSeed(7), AlgMLDSA44Provisional)
	if err != nil {
		t.Fatal(err)
	}
	pqVerifier, err := NewMLDSAVerifier(origin, pqSigner.PublicKey(), AlgMLDSA44Provisional)
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

// TestMLDSASignatureShape fija lo que NO depende del byte de algoritmo
// pendiente: el tamaño de la firma y su sitio en la nota.
//
// El key ID no se fija con un golden a propósito. Depende del byte de algoritmo,
// que está pendiente de decisión (ver el SPEC-CHECK de mldsa.go), y fijar ahora
// un valor calculado con la misma función que verifica sería repetir el error de
// SC-2: un key ID equivocado que pasa los tests porque los tests lo calculan
// igual que el código.
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
	if _, err := NewMLDSASigner("nucleoledger.com/pq", make([]byte, 16), AlgMLDSA44Provisional); err == nil {
		t.Error("se aceptó una semilla de 16 bytes")
	}
	if _, err := NewMLDSAVerifier("nucleoledger.com/pq", make([]byte, 100), AlgMLDSA44Provisional); err == nil {
		t.Error("se aceptó una pública de 100 bytes")
	}
	if _, err := NewMLDSASigner("", mldsaSeed(1), AlgMLDSA44Provisional); err == nil {
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
	s, err := NewMLDSASigner("nucleoledger.com/pq", mldsaSeed(7), AlgMLDSA44Provisional)
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
