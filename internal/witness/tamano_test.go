package witness

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"testing"
	"time"
)

// TestCuerpoDeNotaEnElLimite fija el tope de MaxNoteBody por los dos lados: un
// cuerpo de exactamente MaxNoteBody bytes se cosigna y verifica, y uno de un
// byte más se rechaza al firmar y al verificar.
//
// La firma del cuerpo que se pasa del tope se construye a mano, sin
// cosignedMessage, siguiendo c2sp.org/tlog-cosignature@v1 al pie de la letra.
// Así el test prueba el tope y no otra cosa: sin él, esa firma verificaría.
func TestCuerpoDeNotaEnElLimite(t *testing.T) {
	const name = "witness.example/limite"
	priv := ed25519.NewKeyFromSeed(seed(7))
	pub := priv.Public().(ed25519.PublicKey)
	fixed := time.Unix(1_800_000_000, 0)
	s, err := NewSigner(name, priv, func() time.Time { return fixed })
	if err != nil {
		t.Fatal(err)
	}
	v, err := NewVerifier(name, pub)
	if err != nil {
		t.Fatal(err)
	}

	enElLimite := bytes.Repeat([]byte("a"), MaxNoteBody)
	sig, err := s.Sign(enElLimite)
	if err != nil {
		t.Fatalf("un cuerpo de exactamente %d bytes se rechazó: %v", MaxNoteBody, err)
	}
	if !v.Verify(enElLimite, sig) {
		t.Fatalf("la cosignature de un cuerpo de exactamente %d bytes no verifica", MaxNoteBody)
	}

	pasado := bytes.Repeat([]byte("a"), MaxNoteBody+1)
	if _, err := s.Sign(pasado); err == nil {
		t.Fatalf("se cosignó un cuerpo de %d bytes", MaxNoteBody+1)
	}

	// Firma válida, hecha a mano, del cuerpo que se pasa del tope.
	const ts = uint64(1_800_000_000)
	msg := append([]byte("cosignature/v1\ntime 1800000000\n"), pasado...)
	aMano := make([]byte, TimestampedSignatureSize)
	binary.BigEndian.PutUint64(aMano[:8], ts)
	copy(aMano[8:], ed25519.Sign(priv, msg))
	if v.Verify(pasado, aMano) {
		t.Fatalf("se verificó la cosignature de un cuerpo de %d bytes", MaxNoteBody+1)
	}
}
