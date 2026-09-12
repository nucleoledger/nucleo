package receipt

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nucleoledger/nucleo/internal/proof"
)

// DIFERENCIAL Go ↔ TypeScript (C.4 del Sprint 7c).
//
// Genera un catálogo de mutaciones del recibo golden y anota el veredicto de GO
// en cada una. Un script del SDK —sdk/ts/scripts/diferencial.mjs— pasa el mismo
// catálogo por el verificador de TypeScript y falla si algún veredicto difiere.
// Lo ejecuta el job `diferencial` del CI.
//
// Por qué existe: los vectores compartidos solo prueban que las implementaciones
// coinciden en ACEPTAR. La auditoría adversarial encontró cuatro entradas en las
// que Go aceptaba y TypeScript rechazaba, y ninguna suite las miraba. Una
// divergencia de veredicto es un bug aunque el recibo sea basura: dos
// verificadores que no opinan lo mismo son dos verificadores en los que no se
// puede confiar por igual.
//
// Cómo añadir mutaciones: una entrada más en catalogoDeMutaciones. El nombre es
// lo que se ve en el CI cuando falla; que diga qué se tocó. El test normal
// (sin NUCLEO_DIFERENCIAL_OUT) solo comprueba que el catálogo se genera y que el
// recibo intacto es el único que Go acepta salvo los casos marcados.

// mutacion es un caso del catálogo, con el veredicto de Go ya anotado.
type mutacion struct {
	Nombre  string `json:"nombre"`
	Receipt string `json:"receipt"`
	GoValid bool   `json:"go_valid"`
	GoErr   string `json:"go_err,omitempty"`
}

// catalogoDeMutaciones aplica al recibo base todas las transformaciones que un
// atacante perezoso, un editor de texto o un correo electrónico podrían aplicar.
func catalogoDeMutaciones(base string) []mutacion {
	lineas := strings.Split(base, "\n")
	var out []mutacion
	add := func(nombre, r string) { out = append(out, mutacion{Nombre: nombre, Receipt: r}) }

	add("intacto", base)
	for i := range lineas {
		et := fmt.Sprintf("%d %.24q", i, lineas[i])
		cp := func() []string { return append([]string{}, lineas...) }

		sin := cp()
		add("borra linea "+et, strings.Join(append(sin[:i:i], sin[i+1:]...), "\n"))

		dup := cp()
		add("duplica linea "+et, strings.Join(append(dup[:i+1:i+1], append([]string{lineas[i]}, dup[i+1:]...)...), "\n"))

		ins := cp()
		add("linea en blanco antes de "+et, strings.Join(append(ins[:i:i], append([]string{""}, ins[i:]...)...), "\n"))

		sp := cp()
		sp[i] += " "
		add("espacio al final de "+et, strings.Join(sp, "\n"))

		cr := cp()
		cr[i] += "\r"
		add("CR al final de "+et, strings.Join(cr, "\n"))
	}
	acc := ""
	for i, l := range lineas[:len(lineas)-1] {
		acc += l + "\n"
		add(fmt.Sprintf("truncado tras linea %d", i), acc)
	}
	add("sin salto final", strings.TrimSuffix(base, "\n"))
	add("doble salto final", base+"\n")
	for p := 0; p < len(base); p += 97 {
		b := []byte(base)
		b[p] ^= 0x20
		add(fmt.Sprintf("byte %d xor 0x20", p), string(b))
	}
	return out
}

type politicaVector struct {
	Origin    string            `json:"origin"`
	LogKey    string            `json:"log_key"`
	SignerKey string            `json:"signer_key"`
	Witnesses map[string]string `json:"witnesses"`
	Quorum    int               `json:"quorum"`
}

// mutacionConPolitica es una entrada del catálogo: cada caso lleva su política,
// porque el catálogo recorre TODOS los vectores válidos —once: tamaños 1, 2, 4,
// 5, 8 y 9 con índices 0 y último, y el destinatario que imita una firma— y cada
// uno tiene la suya.
type mutacionConPolitica struct {
	mutacion
	Vector string         `json:"vector"`
	Policy map[string]any `json:"policy"`
}

func TestDiferencialGeneraCatalogo(t *testing.T) {
	files, err := filepath.Glob(filepath.Join("..", "..", "testdata", "vectors", "receipt", "valido-*.json"))
	if err != nil || len(files) == 0 {
		t.Fatalf("sin vectores válidos: %v", err)
	}
	var catalogo []mutacionConPolitica
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var v struct {
			Name    string         `json:"name"`
			Receipt string         `json:"receipt"`
			Policy  politicaVector `json:"policy"`
		}
		if err := json.Unmarshal(raw, &v); err != nil {
			t.Fatal(err)
		}
		pol := proof.Policy{Origin: v.Policy.Origin, Quorum: v.Policy.Quorum,
			Witnesses: map[string]ed25519.PublicKey{}}
		if pol.LogKey, err = hex.DecodeString(v.Policy.LogKey); err != nil {
			t.Fatal(err)
		}
		if pol.SignerKey, err = hex.DecodeString(v.Policy.SignerKey); err != nil {
			t.Fatal(err)
		}
		for n, h := range v.Policy.Witnesses {
			if pol.Witnesses[n], err = hex.DecodeString(h); err != nil {
				t.Fatal(err)
			}
		}
		polJSON := map[string]any{
			"origin": v.Policy.Origin, "logKey": v.Policy.LogKey, "signerKey": v.Policy.SignerKey,
			"witnesses": v.Policy.Witnesses, "quorum": v.Policy.Quorum,
		}

		casos := catalogoDeMutaciones(v.Receipt)
		aceptados := 0
		for i := range casos {
			r, err := Parse([]byte(casos[i].Receipt), pol)
			if err == nil {
				_, err = r.Verify(pol)
			}
			if err != nil {
				casos[i].GoErr = err.Error()
			} else {
				casos[i].GoValid = true
				aceptados++
			}
			catalogo = append(catalogo, mutacionConPolitica{mutacion: casos[i], Vector: v.Name, Policy: polJSON})
		}
		// Go solo acepta el recibo intacto y su copia truncada tras la última línea,
		// que es el mismo recibo. Cualquier otra aceptación es una representación
		// alternativa del mismo recibo, que es lo que C.3 prohíbe.
		if aceptados != 2 {
			for _, c := range casos {
				if c.GoValid {
					t.Errorf("%s: Go acepta: %s", v.Name, c.Nombre)
				}
			}
			t.Fatalf("%s: Go acepta %d mutaciones; solo debe aceptar el intacto y su copia", v.Name, aceptados)
		}
	}

	out := os.Getenv("NUCLEO_DIFERENCIAL_OUT")
	if out == "" {
		t.Logf("%d mutaciones sobre %d vectores; NUCLEO_DIFERENCIAL_OUT no está definido, no se escribe el catálogo",
			len(catalogo), len(files))
		return
	}
	enc, err := json.MarshalIndent(map[string]any{"casos": catalogo}, "", " ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(out, enc, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("%d mutaciones sobre %d vectores escritas en %s", len(catalogo), len(files), out)
}
