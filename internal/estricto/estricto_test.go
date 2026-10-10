package estricto

import (
	"errors"
	"strings"
	"testing"
)

var errPrueba = errors.New("formato de prueba inválido")

func opciones() Opciones {
	return Opciones{
		Error: errPrueba, Max: 256, Profundidad: 2,
		MsgAnidado: "demasiado hondo para la prueba",
		MsgValor:   "valor que la prueba no admite",
	}
}

// TestLeerDevuelveLosMiembrosEnOrden: lo que se lee, en el orden del documento.
func TestLeerDevuelveLosMiembrosEnOrden(t *testing.T) {
	obj, err := Leer([]byte(`{"b": "x", "a": {"k": "v"}, "n": 3}`), opciones())
	if err != nil {
		t.Fatal(err)
	}
	if len(obj) != 3 || obj[0].Nombre != "b" || obj[1].Valor.Tipo != 'o' || obj[1].Valor.Objeto[0].Valor.Cadena != "v" || obj[2].Valor.Numero != "3" {
		t.Fatalf("leído: %+v", obj)
	}
}

// TestLeerRechazaConLasOpcionesDeCadaFormato: el centinela y los dos mensajes propios
// de cada formato, y la profundidad y el tamaño que pone él.
func TestLeerRechazaConLasOpcionesDeCadaFormato(t *testing.T) {
	for _, c := range []struct {
		nombre, doc, dice string
	}{
		{"repetido", `{"a": "1", "a": "2"}`, `"a" está repetido`},
		{"anidado de más", `{"a": {"b": {"c": "d"}}}`, "demasiado hondo para la prueba"},
		{"booleano", `{"a": true}`, "valor que la prueba no admite"},
		{"array", `{"a": []}`, "valor que la prueba no admite"},
		{"coma final", `{"a": "1",}`, "se esperaba el nombre de un miembro"},
		{"BOM", "\xef\xbb\xbf{}", "empieza con BOM"},
		{"demasiado grande", `{"a": "` + strings.Repeat("x", 300) + `"}`, "el máximo es 256"},
		{"dos objetos", `{} {}`, "hay contenido después del objeto"},
	} {
		t.Run(c.nombre, func(t *testing.T) {
			_, err := Leer([]byte(c.doc), opciones())
			if !errors.Is(err, errPrueba) {
				t.Fatalf("error %v; tiene que envolver el centinela del formato", err)
			}
			if !strings.Contains(err.Error(), c.dice) {
				t.Errorf("el error no dice %q: %v", c.dice, err)
			}
		})
	}
	// Con más profundidad permitida, lo de antes se acepta.
	o := opciones()
	o.Profundidad = 3
	if _, err := Leer([]byte(`{"a": {"b": {"c": "d"}}}`), o); err != nil {
		t.Errorf("con Profundidad 3: %v", err)
	}
}

// TestHexClaveYAsciiIgual: las dos ayudas que comparten los formatos.
func TestHexClaveYAsciiIgual(t *testing.T) {
	if !HexClave(strings.Repeat("ab", 32)) || HexClave(strings.Repeat("AB", 32)) || HexClave(strings.Repeat("ab", 31)) {
		t.Error("HexClave")
	}
	if !AsciiIgual("signerKey", "SIGNERKEY") || AsciiIgual("logs", "log") {
		t.Error("AsciiIgual")
	}
}
