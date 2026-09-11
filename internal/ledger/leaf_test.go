package ledger

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// Vectores de la regla de hoja leaf/v2, de testdata/vectors/leaf/v2.json.
//
// Los calculó testdata/vectors/leaf/generar.py con hashlib y nada más, y el caso
// de ceros está contrastado además con sha256sum. Regla anti-circularidad: un
// golden calculado con la función que se quiere probar no prueba nada, y en una
// regla de hoja equivocarse significa que dos implementaciones construyen árboles
// distintos sin que ningún test lo note.

type leafVectors struct {
	LeafRule string `json:"leaf_rule"`
	Cases    []struct {
		Name        string `json:"name"`
		Note        string `json:"note"`
		HashHex     string `json:"hash_hex"`
		SigHex      string `json:"signature_hex"`
		LeafDataHex string `json:"leaf_data_hex"`
		LeafDataLen int    `json:"leaf_data_len"`
		LeafHashHex string `json:"leaf_hash_hex"`
	} `json:"cases"`
	Tree struct {
		LeavesHex []string          `json:"leaves_hex"`
		RootsHex  map[string]string `json:"roots_hex"`
	} `json:"tree"`
}

func loadLeafVectors(t *testing.T) leafVectors {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "vectors", "leaf", "v2.json"))
	if err != nil {
		t.Fatal(err)
	}
	var v leafVectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	if len(v.Cases) == 0 || len(v.Tree.LeavesHex) == 0 {
		t.Fatal("los vectores están vacíos")
	}
	return v
}

func TestLeafV2Vectors(t *testing.T) {
	v := loadLeafVectors(t)
	if v.LeafRule != LeafRule {
		t.Fatalf("los vectores son de %q y el código implementa %q", v.LeafRule, LeafRule)
	}

	for _, c := range v.Cases {
		t.Run(c.Name, func(t *testing.T) {
			hash, err := hex.DecodeString(c.HashHex)
			if err != nil {
				t.Fatal(err)
			}
			sig, err := hex.DecodeString(c.SigHex)
			if err != nil {
				t.Fatal(err)
			}
			data, err := LeafData(hash, sig)
			if err != nil {
				t.Fatal(err)
			}
			if len(data) != c.LeafDataLen || len(data) != LeafDataSize {
				t.Errorf("leaf_data mide %d; el vector dice %d", len(data), c.LeafDataLen)
			}
			if got := hex.EncodeToString(data); got != c.LeafDataHex {
				t.Errorf("leaf_data:\n got %s\nwant %s\n(%s)", got, c.LeafDataHex, c.Note)
			}
			if got := hex.EncodeToString(LeafHash(data)); got != c.LeafHashHex {
				t.Errorf("leaf_hash:\n got %s\nwant %s", got, c.LeafHashHex)
			}
		})
	}

	t.Run("raíces de un árbol de 8 hojas", func(t *testing.T) {
		var hojas [][]byte
		for _, h := range v.Tree.LeavesHex {
			raw, err := hex.DecodeString(h)
			if err != nil {
				t.Fatal(err)
			}
			if len(raw) != LeafDataSize {
				t.Fatalf("una hoja del vector mide %d bytes", len(raw))
			}
			hojas = append(hojas, raw)
		}
		for n := 1; n <= len(hojas); n++ {
			want := v.Tree.RootsHex[itoa(n)]
			if want == "" {
				t.Fatalf("el vector no trae raíz para n=%d", n)
			}
			if got := hex.EncodeToString(Root(hojas[:n])); got != want {
				t.Errorf("raíz n=%d:\n got %s\nwant %s", n, got, want)
			}
		}
	})
}

// TestLeafDataRechazaLongitudesMalas: la longitud fija es lo que hace que la
// concatenación no sea ambigua, así que dejar pasar una longitud distinta
// destruiría la única razón por la que no hace falta separador.
func TestLeafDataRechazaLongitudesMalas(t *testing.T) {
	ok32, ok64 := make([]byte, 32), make([]byte, 64)
	for _, c := range []struct {
		nombre    string
		hash, sig []byte
	}{
		{"hash corto", make([]byte, 31), ok64},
		{"hash largo", make([]byte, 33), ok64},
		{"hash vacío", nil, ok64},
		{"firma corta", ok32, make([]byte, 63)},
		{"firma larga", ok32, make([]byte, 65)},
		{"firma vacía", ok32, nil},
		{"los dos al revés", ok64, ok32},
	} {
		t.Run(c.nombre, func(t *testing.T) {
			if _, err := LeafData(c.hash, c.sig); err == nil {
				t.Errorf("se aceptó hash de %d y firma de %d bytes", len(c.hash), len(c.sig))
			}
		})
	}
}

// TestLeafDataOrdenImporta deja escrito que el orden no es convencional: es parte
// de la especificación. Los dos casos espejo del vector lo fijan, y esto lo dice
// sin depender del fichero.
func TestLeafDataOrdenImporta(t *testing.T) {
	h := make([]byte, 32)
	for i := range h {
		h[i] = 0xaa
	}
	sig := make([]byte, 64)
	for i := range sig {
		sig[i] = 0xbb
	}
	data, err := LeafData(h, sig)
	if err != nil {
		t.Fatal(err)
	}
	if data[0] != 0xaa || data[31] != 0xaa {
		t.Error("los primeros 32 bytes deben ser el hash")
	}
	if data[32] != 0xbb || data[95] != 0xbb {
		t.Error("los últimos 64 bytes deben ser la firma")
	}
}

// itoa evita importar strconv solo para esto.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
