package receipt

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/nucleoledger/nucleo/internal/proof"
)

// Fuzz del recibo ENTERO, con su envoltorio legible.
//
// El formato de proof ya se fuzzea en su paquete; lo que se ataca aquí es la
// capa que añade este: la comprobación de que el texto visible sea exactamente el
// que se deriva de la prueba. Esa comprobación es la que convierte el recibo en
// un documento fiable para una persona, y un parser que la dejara pasar a medias
// produciría papeles que dicen una cosa y demuestran otra.
//
// Se fuzzea con la política REAL de un vector golden y con ese recibo en el corpus.
//
// Antes la política eran claves de ceros y sin signerKey, así que desde ADR-017 Parse
// rechazaba en la primera línea —falta la clave del firmante— y ni la rama de aceptación
// ni la propiedad de canonicidad de más abajo se ejecutaban NUNCA. El fuzzer subía el
// contador de casos sin poder encontrar nada, que es la peor clase de test: el que
// tranquiliza. Lo señaló la cuarta auditoría.
//
// El canario de abajo impide que vuelva a pasar en silencio: si el recibo del vector deja
// de aceptarse con esta política, el fuzzer falla en el arranque en vez de seguir
// mutando basura.
func FuzzParseReceipt(f *testing.F) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "vectors", "receipt", "valido-1-cosignature.json"))
	if err != nil {
		f.Fatal(err)
	}
	var v vectorFile
	if err := json.Unmarshal(raw, &v); err != nil {
		f.Fatal(err)
	}
	pol := policyFromVectorF(f, v.Policy)
	if _, err := Parse([]byte(v.Receipt), pol); err != nil {
		f.Fatalf("CANARIO: el recibo del vector golden no se acepta con su política, así que este fuzz no probaría la rama que importa: %v", err)
	}
	f.Add([]byte(v.Receipt))

	f.Add([]byte(Magic + "\ndestinatario      : X" + RecipientNote + "\n"))
	f.Add([]byte(Magic + "\n" + separator + "\n{}\n"))
	f.Add([]byte(separator + "\n"))
	f.Add([]byte("\n\n" + separator + "\n\n"))
	f.Add([]byte(Magic + "\ndestinatario      : X\n\n" + separator + "\n" +
		`{"index":0,"payload_cid":"","payload_hash":"","prev_hash":"","signer_pubkey":"","tenant":"","timestamp":"","type":""}` + "\n"))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		r, err := Parse(data, pol)
		if err != nil {
			if r != nil {
				t.Fatalf("Parse rechazó y devolvió %+v: estado a medias", r)
			}
			return
		}
		if r == nil {
			t.Fatal("Parse aceptó y devolvió nil")
		}
		// El destinatario que se devuelve nunca lleva la etiqueta pegada: quien
		// consuma el recibo recibe el nombre, no el nombre más un sufijo que
		// tendría que limpiar en cada integración.
		if len(r.Recipient) >= len(RecipientNote) &&
			r.Recipient[len(r.Recipient)-len(RecipientNote):] == RecipientNote {
			t.Fatalf("el destinatario devuelto lleva la etiqueta pegada: %q", r.Recipient)
		}
		// Y si se vuelve a formatear, tienen que salir los MISMOS bytes: es la
		// propiedad en la que se apoya todo lo demás de este paquete.
		again, err := Format(r, pol)
		if err != nil {
			t.Fatalf("Format falló sobre algo que Parse aceptó: %v", err)
		}
		if !reflect.DeepEqual(again, data) {
			t.Fatalf("el recibo no es canónico:\nentró: %q\nsalió: %q", data, again)
		}
	})
}

// FuzzTextoLegible ataca solo el extractor del encabezado, que es lo que imprime
// la CLI y lo que una página web enseña antes de verificar nada.
func FuzzTextoLegible(f *testing.F) {
	f.Add([]byte(Magic + "\nx\n\n" + separator + "\nmáquina\n"))
	f.Add([]byte(separator))
	f.Add([]byte("sin separador"))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		// Text no valida nada: solo corta. Lo único que no puede hacer es
		// reventar, porque se llama sobre bytes que todavía no se han verificado.
		_ = Text(data)
	})
}

// policyFromVectorF es policyFromVector para un *testing.F.
func policyFromVectorF(f *testing.F, v vectorPolicy) proof.Policy {
	f.Helper()
	logKey, err := hex.DecodeString(v.LogKey)
	if err != nil {
		f.Fatal(err)
	}
	signerKey, err := hex.DecodeString(v.SignerKey)
	if err != nil {
		f.Fatal(err)
	}
	pol := proof.Policy{Origin: v.Origin, LogKey: logKey, SignerKey: signerKey,
		Quorum: v.Quorum, Witnesses: map[string]ed25519.PublicKey{}}
	for name, h := range v.Witnesses {
		k, err := hex.DecodeString(h)
		if err != nil {
			f.Fatal(err)
		}
		pol.Witnesses[name] = k
	}
	return pol
}
