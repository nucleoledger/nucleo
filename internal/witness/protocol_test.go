package witness

import (
	"bytes"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/nucleoledger/nucleo/internal/checkpoint"
)

// specExample es el cuerpo de petición de EJEMPLO que trae el propio documento
// c2sp.org/tlog-witness, copiado literalmente (commit c559ede, ver ADR-011).
//
// Vale como vector externo: no lo produjo este código, así que si el parser lo
// lee bien es porque entiende el formato del spec y no porque coincida consigo
// mismo. Es la regla anti-circularidad aplicada a un formato de cable.
const specExample = `old 20852014
PlRNCrwHpqhGrupue0L7gxbjbMiKA9temvuZZDDpkaw=
jrJZDmY8Y7SyJE0MWLpLozkIVMSMZcD5kvuKxPC3swk=
5+pKlUdi2LeF/BcMHBn+Ku6yhPGNCswZZD1X/6QgPd8=
/6WVhPs2CwSsb5rYBH5cjHV/wSmA79abXAwhXw3Kj/0=

example.com/behind-the-sofa
20852163
CsUYapGGPo4dkMgIAUqom/Xajj7h2fB2MPA3j2jxq2I=

— example.com/behind-the-sofa Az3grlgtzPICa5OS8npVmf1Myq/5IZniMp+ZJurmRDeOoRDe4URYN7u5/Zhcyv2q1gGzGku9nTo+zyWE+xeMcTOAYQ8=
— example.com/behind-the-sofa opLqBQsREYCgu6xQkYQwJr9fo45a62DN9EdmHXnZdXNqlcVGlCum2Wks+49/V6267UEjw6QUXTS5Rovnzv++qbSzm9Q=
`

// TestParseSpecExample lee el ejemplo del spec y comprueba cada campo.
func TestParseSpecExample(t *testing.T) {
	req, err := UnmarshalAddCheckpoint([]byte(specExample))
	if err != nil {
		t.Fatalf("el ejemplo del spec no parsea: %v", err)
	}
	if req.OldSize != 20852014 {
		t.Errorf("OldSize = %d, want 20852014", req.OldSize)
	}
	if len(req.Proof) != 4 {
		t.Fatalf("%d nodos de prueba, want 4", len(req.Proof))
	}
	for i, node := range req.Proof {
		if len(node) != 32 {
			t.Errorf("nodo %d mide %d bytes, want 32", i, len(node))
		}
	}
	if got := base64.StdEncoding.EncodeToString(req.Proof[0]); got != "PlRNCrwHpqhGrupue0L7gxbjbMiKA9temvuZZDDpkaw=" {
		t.Errorf("primer nodo = %q", got)
	}

	c, err := checkpoint.ParseNote(req.Note)
	if err != nil {
		t.Fatalf("el checkpoint del ejemplo no parsea: %v", err)
	}
	if c.Origin != "example.com/behind-the-sofa" || c.Size != 20852163 {
		t.Errorf("checkpoint = %+v", c)
	}
	// La nota tiene que quedar VERBATIM, con sus dos líneas de firma: es lo que
	// se verifica criptográficamente, así que recortarla la invalidaría.
	if n := bytes.Count(req.Note, []byte("— example.com/behind-the-sofa ")); n != 2 {
		t.Errorf("la nota conserva %d líneas de firma, want 2", n)
	}

	// Round-trip byte a byte.
	back, err := MarshalAddCheckpoint(req)
	if err != nil {
		t.Fatal(err)
	}
	if string(back) != specExample {
		t.Errorf("el round-trip no reproduce el ejemplo:\n%q", back)
	}
}

// TestMarshalUsesSpecEncoding fija las reglas de codificación del tamaño.
func TestMarshalUsesSpecEncoding(t *testing.T) {
	note := []byte("origin\n0\nroot\n\n— x y\n")
	body, err := MarshalAddCheckpoint(AddCheckpointRequest{OldSize: 0, Note: note})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(body), "old 0\n\n") {
		t.Errorf("un tamaño cero debe codificarse como \"old 0\": %q", body)
	}
}

// TestUnmarshalRejectsMalformed cubre lo que el formato NO admite.
func TestUnmarshalRejectsMalformed(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"sin línea vacía", "old 5\nabc\n"},
		{"sin línea old", "5\n\norigin\n1\nroot\n\n— x y\n"},
		{"tamaño con ceros a la izquierda", "old 007\n\norigin\n1\nroot\n\n— x y\n"},
		{"tamaño no numérico", "old cinco\n\norigin\n1\nroot\n\n— x y\n"},
		{"tamaño vacío", "old \n\norigin\n1\nroot\n\n— x y\n"},
		{"nodo de prueba no base64", "old 5\n@@@@\n\norigin\n1\nroot\n\n— x y\n"},
		{"checkpoint vacío", "old 5\n\n"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := UnmarshalAddCheckpoint([]byte(c.body)); !errors.Is(err, ErrMalformedRequest) {
				t.Errorf("err = %v, want %v", err, ErrMalformedRequest)
			}
		})
	}

	// El spec fija 63 como máximo de líneas de prueba, en las dos direcciones.
	node := base64.StdEncoding.EncodeToString(make([]byte, 32))
	body := "old 5\n" + strings.Repeat(node+"\n", MaxProofLines+1) + "\norigin\n1\nroot\n\n— x y\n"
	if _, err := UnmarshalAddCheckpoint([]byte(body)); !errors.Is(err, ErrMalformedRequest) {
		t.Errorf("64 líneas de prueba: err = %v, want %v", err, ErrMalformedRequest)
	}
	proof := make([][]byte, MaxProofLines+1)
	for i := range proof {
		proof[i] = make([]byte, 32)
	}
	if _, err := MarshalAddCheckpoint(AddCheckpointRequest{Proof: proof, Note: []byte("x")}); !errors.Is(err, ErrMalformedRequest) {
		t.Errorf("marshal con 64 nodos: err = %v, want %v", err, ErrMalformedRequest)
	}
}

// TestOriginHashMatchesSpec comprueba la ruta de monitorización contra un hash
// calculado fuera de este código, con sha256sum.
func TestOriginHashMatchesSpec(t *testing.T) {
	// $ printf 'example.com/behind-the-sofa' | sha256sum
	const want = "5fd2dc0beb4ce54da5050cf6d5c75248b023abad441c3cecde3976fbe9da4fe4"
	if got := OriginHash("example.com/behind-the-sofa"); got != want {
		t.Errorf("OriginHash = %q, want %q", got, want)
	}
	if got := MonitorPath("example.com/behind-the-sofa"); got != "/"+want+"/checkpoint" {
		t.Errorf("MonitorPath = %q", got)
	}
}
