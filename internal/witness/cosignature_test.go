package witness

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"testing"

	"github.com/nucleoledger/nucleo/internal/checkpoint"
	"golang.org/x/mod/sumdb/note"
)

// TestCosignatureKeyIDUsesAlgorithm04 fija el key ID del testigo contra valores
// calculados FUERA de este código (con sha256sum sobre los bytes
// name ‖ 0x0a ‖ alg ‖ pubkey). Es la única forma de que el test signifique algo:
// recalcularlo con la misma función que se prueba no verificaría nada.
//
// c2sp.org/tlog-cosignature asigna el byte 0x04 a las claves de cosignature v1;
// el 0x01 es solo para la firma del log sobre el texto de la nota.
func TestCosignatureKeyIDUsesAlgorithm04(t *testing.T) {
	const name = "witness.nucleoledger.com/w1"
	const wantPubHex = "2543b92ff1095511476adc8369db6ddc933665a11978dda1404ee1066ca9559d"

	// Valores golden calculados con sha256sum, independientes del código:
	//   alg 0x01 -> 2a8bc606   (el que se usaría para una firma de log)
	//   alg 0x04 -> f0650a0c   (el correcto para una cosignature)
	const wantCosignatureID = uint32(0xf0650a0c)
	const wantLogID = uint32(0x2a8bc606)

	priv := ed25519.NewKeyFromSeed(seed(64))
	pub := priv.Public().(ed25519.PublicKey)
	if got := hex.EncodeToString(pub); got != wantPubHex {
		t.Fatalf("la clave de prueba cambió: %s != %s", got, wantPubHex)
	}

	if wantCosignatureID == wantLogID {
		t.Fatal("los dos golden son iguales: el test no distinguiría nada")
	}

	s, err := NewSigner(name, priv, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := s.KeyHash(); got != wantCosignatureID {
		t.Errorf("Signer.KeyHash = %08x, want %08x (alg 0x04)", got, wantCosignatureID)
	}

	v, err := NewVerifier(name, pub)
	if err != nil {
		t.Fatal(err)
	}
	if got := v.KeyHash(); got != wantCosignatureID {
		t.Errorf("Verifier.KeyHash = %08x, want %08x (alg 0x04)", got, wantCosignatureID)
	}

	// La misma clave usada como log da otro key ID: es lo que impide que una
	// firma de log y una cosignature se confundan.
	if got := checkpoint.KeyHash(name, pub); got != wantLogID {
		t.Errorf("checkpoint.KeyHash = %08x, want %08x (alg 0x01)", got, wantLogID)
	}
	if got := checkpoint.KeyHashAlg(name, pub, checkpoint.AlgEd25519Cosignature); got != wantCosignatureID {
		t.Errorf("KeyHashAlg(0x04) = %08x, want %08x", got, wantCosignatureID)
	}
	if checkpoint.AlgEd25519 != 0x01 || checkpoint.AlgEd25519Cosignature != 0x04 {
		t.Errorf("bytes de algoritmo = 0x%02x / 0x%02x, want 0x01 / 0x04",
			checkpoint.AlgEd25519, checkpoint.AlgEd25519Cosignature)
	}
}

// TestEmittedCosignatureCarriesAlg04KeyID comprueba que el key ID correcto viaje
// de verdad en los bytes de la línea de firma, no solo en el tipo en memoria.
func TestEmittedCosignatureCarriesAlg04KeyID(t *testing.T) {
	h := newHarness(t)
	cosigned, err := h.witness.Cosign(h.signAt(5), nil)
	if err != nil {
		t.Fatal(err)
	}

	n, err := note.Open(cosigned, note.VerifierList(h.witness.Verifier()))
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, sig := range n.Sigs {
		if sig.Name != h.witness.Name() {
			continue
		}
		found = true
		raw, err := base64.StdEncoding.DecodeString(sig.Base64)
		if err != nil {
			t.Fatal(err)
		}
		inLine := binary.BigEndian.Uint32(raw[:4])
		witPub := ed25519.NewKeyFromSeed(seed(100)).Public().(ed25519.PublicKey)
		want := checkpoint.KeyHashAlg(h.witness.Name(), witPub, checkpoint.AlgEd25519Cosignature)
		if inLine != want {
			t.Errorf("key ID en la línea de firma = %08x, want %08x", inLine, want)
		}
		if bad := checkpoint.KeyHash(h.witness.Name(), witPub); inLine == bad {
			t.Errorf("la línea de firma lleva el key ID de log (0x01) %08x", bad)
		}
	}
	if !found {
		t.Fatal("la nota no trae cosignature del testigo")
	}
}
