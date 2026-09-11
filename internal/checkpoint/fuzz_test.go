package checkpoint

import (
	"crypto/ed25519"
	"reflect"
	"testing"
)

// Fuzz del formato de cable de los checkpoints y de las notas firmadas.
//
// La revisión externa lo pidió con una razón concreta: "falta fuzz del wire
// format, no solo JCS. El protocolo de testigo es superficie de ataque". Tenía
// razón. Los parsers de este proyecto leen bytes que vienen de otra máquina —de
// un testigo, de un recibo que alguien pega en una web— y hasta ahora solo el
// canonicalizador JCS tenía fuzzing.
//
// Se comprueban dos invariantes, y la segunda es la que de verdad cuesta:
//
//  1. No hay pánico. Un pánico en un parser es una caída provocable a distancia.
//  2. Un rechazo NO deja estado a medias: si Parse devuelve error, el valor que
//     devuelve tiene que ser el cero del tipo. Un parser que rellena la mitad de
//     una estructura y además devuelve error invita a que quien llama use esa
//     mitad, y ese es el camino por el que un origin o un tamaño sin validar
//     acaban tratados como si estuvieran verificados.

// FuzzParseBody ataca el cuerpo del checkpoint: origin, tamaño y raíz.
func FuzzParseBody(f *testing.F) {
	f.Add("nucleoledger.com/log\n5\nzskn84s97pizKDh6YIJ2cWTOUA4zcWUxL7zmlh7Rt4g=\n")
	f.Add("origin\n0\n47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=\n")
	f.Add("")
	f.Add("\n\n\n")
	f.Add("origin\n18446744073709551615\nzskn84s97pizKDh6YIJ2cWTOUA4zcWUxL7zmlh7Rt4g=\n")
	f.Add("origin\n-1\nzskn84s97pizKDh6YIJ2cWTOUA4zcWUxL7zmlh7Rt4g=\n")
	f.Add("origin con espacios\n1\nzskn84s97pizKDh6YIJ2cWTOUA4zcWUxL7zmlh7Rt4g=\n")
	f.Add("origin\n1\nno-es-base64!!\n")

	f.Fuzz(func(t *testing.T, text string) {
		c, err := Parse(text)
		if err != nil {
			if !reflect.DeepEqual(c, Checkpoint{}) {
				t.Fatalf("Parse rechazó y aun así devolvió %+v: estado a medias", c)
			}
			return
		}
		// Si lo aceptó, el checkpoint tiene que ser válido y volver a
		// serializarse a los MISMOS bytes. Un parser que acepta dos textos
		// distintos para el mismo checkpoint rompe la comparación de checkpoints,
		// que es en lo que se apoya toda la detección de reescrituras.
		if err := c.Validate(); err != nil {
			t.Fatalf("Parse aceptó un checkpoint que no valida: %v (%+v)", err, c)
		}
		again, err := Format(c)
		if err != nil {
			t.Fatalf("Format falló sobre algo que Parse aceptó: %v", err)
		}
		if again != text {
			t.Fatalf("el formato no es canónico:\nentró: %q\nsalió: %q", text, again)
		}
	})
}

// FuzzParseNote ataca la nota firmada completa: cuerpo, línea en blanco y líneas
// de firma en base64.
func FuzzParseNote(f *testing.F) {
	// Semilla real: una nota firmada de verdad, generada aquí con una clave fija.
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i)
	}
	signer, err := NewSigner("nucleoledger.com/log", ed25519.NewKeyFromSeed(seed))
	if err != nil {
		f.Fatal(err)
	}
	good, err := Sign(Checkpoint{
		Origin:   "nucleoledger.com/log",
		Size:     5,
		RootHash: make([]byte, RootSize),
	}, signer)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(good)
	f.Add([]byte("origin\n1\n47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=\n\n— origin AAAAAAAA\n"))
	f.Add([]byte("origin\n1\n47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=\n\n"))
	f.Add([]byte("\n\n"))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, msg []byte) {
		c, err := ParseNote(msg)
		if err != nil {
			if !reflect.DeepEqual(c, Checkpoint{}) {
				t.Fatalf("ParseNote rechazó y devolvió %+v: estado a medias", c)
			}
			return
		}
		if err := c.Validate(); err != nil {
			t.Fatalf("ParseNote aceptó un checkpoint que no valida: %v", err)
		}
		// IsCosigned solo mira formas y nunca debe reventar sobre lo que
		// ParseNote haya aceptado.
		_ = IsCosigned(msg)
	})
}

// FuzzVerifyNote ataca la ruta CON verificación de firma, que es la que decide
// si algo cuenta como atestación.
func FuzzVerifyNote(f *testing.F) {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(200 + i)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	verifier, err := NewVerifier("w/1", priv.Public().(ed25519.PublicKey))
	if err != nil {
		f.Fatal(err)
	}
	signer, err := NewSigner("w/1", priv)
	if err != nil {
		f.Fatal(err)
	}
	good, err := Sign(Checkpoint{Origin: "w/1", Size: 1, RootHash: make([]byte, RootSize)}, signer)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(good)
	f.Add([]byte("w/1\n1\n47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=\n\n— w/1 AAAAAAAAAA==\n"))

	f.Fuzz(func(t *testing.T, msg []byte) {
		c, n, err := Verify(msg, verifier)
		if err != nil {
			// Aquí el estado a medias sería peor que en Parse: quien llama podría
			// usar el checkpoint creyendo que está firmado.
			if !reflect.DeepEqual(c, Checkpoint{}) || n != nil {
				t.Fatalf("Verify rechazó y devolvió c=%+v n=%v: estado a medias", c, n)
			}
			return
		}
		if n == nil {
			t.Fatal("Verify aceptó y devolvió una nota nil")
		}
		if len(n.Sigs) == 0 {
			t.Fatal("Verify aceptó una nota sin ninguna firma verificada")
		}
	})
}
