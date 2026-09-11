package witness

import (
	"bytes"
	"crypto/ed25519"
	"reflect"
	"testing"
)

// Fuzz del protocolo del testigo. Es la superficie MÁS expuesta del proyecto: el
// cuerpo de un add-checkpoint llega por HTTP desde cualquiera que alcance el
// puerto, antes de que nada esté verificado. La revisión externa lo señaló con
// esas palabras: "el protocolo de testigo es superficie de ataque".

// FuzzUnmarshalAddCheckpoint ataca el cuerpo de la petición HTTP.
func FuzzUnmarshalAddCheckpoint(f *testing.F) {
	f.Add([]byte("old 0\n\norigin\n1\n47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=\n\n— origin AAAAAAAA\n"))
	f.Add([]byte("old 5\nzskn84s97pizKDh6YIJ2cWTOUA4zcWUxL7zmlh7Rt4g=\n\nnota\n"))
	f.Add([]byte("old 18446744073709551615\n\nx\n"))
	f.Add([]byte("old 007\n\nx\n")) // ceros a la izquierda: el spec los prohíbe
	f.Add([]byte("old -1\n\nx\n"))
	f.Add([]byte("old \n\nx\n"))
	f.Add([]byte("\n\nx\n"))
	f.Add([]byte("old 0\n\n"))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, body []byte) {
		r, err := UnmarshalAddCheckpoint(body)
		if err != nil {
			if !reflect.DeepEqual(r, AddCheckpointRequest{}) {
				t.Fatalf("rechazó y devolvió %+v: estado a medias en la entrada de red", r)
			}
			return
		}
		// El límite de líneas de prueba es la defensa contra un cuerpo que pida
		// trabajo ilimitado. Si el parser lo aceptó, tiene que respetarlo.
		if len(r.Proof) > MaxProofLines {
			t.Fatalf("aceptó %d líneas de prueba, el máximo es %d", len(r.Proof), MaxProofLines)
		}
		if len(r.Note) == 0 {
			t.Fatal("aceptó una petición sin checkpoint")
		}
		// Round-trip: lo aceptado se vuelve a serializar a lo mismo. Si dos
		// cuerpos distintos produjeran la misma petición, un testigo podría
		// cosignar algo que el cliente no cree haber enviado.
		again, err := MarshalAddCheckpoint(r)
		if err != nil {
			t.Fatalf("Marshal falló sobre algo que Unmarshal aceptó: %v", err)
		}
		if !bytes.Equal(again, body) {
			t.Fatalf("el cuerpo no es canónico:\nentró: %q\nsalió: %q", body, again)
		}
	})
}

// FuzzCosignature ataca el blob de firma de una tlog-cosignature@v1: 8 bytes de
// timestamp big-endian más 64 de firma Ed25519.
func FuzzCosignature(f *testing.F) {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i * 3)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	v, err := NewVerifier("w/1", priv.Public().(ed25519.PublicKey))
	if err != nil {
		f.Fatal(err)
	}

	f.Add([]byte{}, []byte{})
	f.Add([]byte("origin\n1\nraíz\n"), make([]byte, 8+ed25519.SignatureSize))
	f.Add([]byte("x"), make([]byte, 8))
	f.Add([]byte("x"), make([]byte, 7))
	f.Add([]byte("x"), bytes.Repeat([]byte{0xff}, 8+ed25519.SignatureSize))

	f.Fuzz(func(t *testing.T, body, sig []byte) {
		// Verify no debe reventar con NADA, y tampoco debe aceptar: la
		// probabilidad de que el fuzzer acierte una firma Ed25519 es nula, así
		// que un true aquí significaría que Verify no comprueba lo que cree.
		if v.Verify(body, sig) {
			t.Fatalf("Verify aceptó una firma que el fuzzer produjo:\nbody=%q\nsig=%x", body, sig)
		}
		// Timestamp sobre basura: error o una fecha, nunca un pánico. Y si da
		// error, la fecha devuelta tiene que ser el cero — un instante a medias
		// se imprimiría como 1970 y pasaría por dato.
		ts, err := Timestamp(sig)
		if err != nil && !ts.IsZero() {
			t.Fatalf("Timestamp falló y devolvió %v en vez del cero", ts)
		}
	})
}
