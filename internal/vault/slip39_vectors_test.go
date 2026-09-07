package vault

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	slip39 "github.com/shurlinet/go-slip39"
)

// vectorsPassphrase es la que usan los vectores oficiales de SatoshiLabs.
const vectorsPassphrase = "TREZOR"

// slip39Vector es una fila del fichero oficial: descripción, mnemónicos,
// secreto esperado en hex —vacío si el vector DEBE rechazarse— y xprv, que aquí
// no se usa.
type slip39Vector struct {
	Description string
	Mnemonics   []string
	SecretHex   string
}

func loadSlip39Vectors(t *testing.T) []slip39Vector {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "vectors", "slip39", "vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var rows [][]json.RawMessage
	if err := json.Unmarshal(raw, &rows); err != nil {
		t.Fatal(err)
	}
	out := make([]slip39Vector, 0, len(rows))
	for i, r := range rows {
		if len(r) < 3 {
			t.Fatalf("vector %d con %d campos", i, len(r))
		}
		var v slip39Vector
		if err := json.Unmarshal(r[0], &v.Description); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(r[1], &v.Mnemonics); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(r[2], &v.SecretHex); err != nil {
			t.Fatal(err)
		}
		out = append(out, v)
	}
	return out
}

// TestSlip39OfficialVectors corre los 45 vectores oficiales de SatoshiLabs
// contra la biblioteca.
//
// Los vectores vienen del repositorio canónico de Trezor, no del testdata que la
// biblioteca trae consigo: dejar que una implementación se examine con sus
// propios vectores no prueba nada. Treinta de los cuarenta y cinco son vectores
// NEGATIVOS —checksum roto, padding inválido, shares incompatibles— y valen
// tanto como los positivos: una biblioteca que recupere un secreto de un
// mnemónico corrupto es exactamente el fallo silencioso que este proyecto no
// puede permitirse.
func TestSlip39OfficialVectors(t *testing.T) {
	vectors := loadSlip39Vectors(t)
	if len(vectors) != 45 {
		t.Fatalf("el fichero trae %d vectores, los oficiales son 45", len(vectors))
	}

	var valid, invalid int
	for _, v := range vectors {
		t.Run(v.Description, func(t *testing.T) {
			got, err := slip39.Combine(v.Mnemonics, []byte(vectorsPassphrase))

			if v.SecretHex == "" {
				if err == nil {
					t.Fatalf("se recuperó un secreto (%x) de un vector que debe rechazarse", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("no se recuperó el secreto: %v", err)
			}
			want, err := hex.DecodeString(v.SecretHex)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("secreto = %x, want %x", got, want)
			}
		})
		if v.SecretHex == "" {
			invalid++
		} else {
			valid++
		}
	}
	if valid != 15 || invalid != 30 {
		t.Errorf("reparto de vectores = %d válidos y %d inválidos, want 15 y 30", valid, invalid)
	}
}
