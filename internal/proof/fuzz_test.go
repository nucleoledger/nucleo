package proof

import (
	"bytes"
	"crypto/ed25519"
	"reflect"
	"testing"

	"github.com/nucleoledger/nucleo/internal/checkpoint"
)

// Fuzz del recibo de c2sp.org/tlog-proof.
//
// Es el formato que viaja más lejos: un recibo acaba en el correo de una
// contraparte, pegado en un PDF o subido a una página web por alguien que no
// tiene nada que ver con quien lo emitió. El parser lo lee antes de poder
// verificar nada.

func FuzzParseProof(f *testing.F) {
	// Semilla real: un recibo bien formado, construido aquí.
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	signer, err := checkpoint.NewSigner("nucleoledger.com/log", ed25519.NewKeyFromSeed(seed))
	if err != nil {
		f.Fatal(err)
	}
	note, err := checkpoint.Sign(checkpoint.Checkpoint{
		Origin:   "nucleoledger.com/log",
		Size:     8,
		RootHash: make([]byte, checkpoint.RootSize),
	}, signer)
	if err != nil {
		f.Fatal(err)
	}
	good, err := Format(Receipt{
		Index:          3,
		InclusionProof: [][]byte{make([]byte, 32), bytes.Repeat([]byte{1}, 32)},
		CheckpointNote: note,
	})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(good)
	f.Add([]byte("c2sp.org/tlog-proof@v1\n0\n\nnota\n"))
	f.Add([]byte("c2sp.org/tlog-proof@v1\n18446744073709551616\n\nnota\n"))
	f.Add([]byte("otra/cosa@v1\n0\n\nnota\n"))
	f.Add([]byte("c2sp.org/tlog-proof@v1\n0\nAAAA\n\nnota\n"))
	f.Add([]byte("\n\n\n"))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		r, err := Parse(data)
		if err != nil {
			if !reflect.DeepEqual(r, Receipt{}) {
				t.Fatalf("Parse rechazó y devolvió %+v: estado a medias", r)
			}
			return
		}
		// Todo nodo aceptado mide exactamente lo que mide un hash: si el parser
		// dejara pasar uno corto, la verificación de inclusión trabajaría con
		// longitudes que no cuadran.
		for i, node := range r.InclusionProof {
			if len(node) != checkpoint.RootSize {
				t.Fatalf("nodo %d de %d bytes, se esperaban %d", i, len(node), checkpoint.RootSize)
			}
		}
		if len(r.CheckpointNote) == 0 {
			t.Fatal("Parse aceptó un recibo sin nota de checkpoint")
		}
		// Round-trip estricto. Dos codificaciones del mismo recibo significarían
		// que dos ficheros distintos son "el mismo recibo", y un recibo es
		// precisamente algo que se archiva para comparar años después.
		again, err := Format(r)
		if err != nil {
			t.Fatalf("Format falló sobre algo que Parse aceptó: %v", err)
		}
		if !bytes.Equal(again, data) {
			t.Fatalf("el recibo no es canónico:\nentró: %q\nsalió: %q", data, again)
		}
	})
}
