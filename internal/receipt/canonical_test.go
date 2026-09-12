package receipt

import (
	"errors"
	"strings"
	"testing"
)

// La auditoría adversarial del 12-sep-2026 metió un \r al final de cinco líneas
// de la parte de máquina del recibo golden y Go aceptó las cinco. El verificador
// de TypeScript rechazaba cuatro. Un mismo recibo, dos veredictos, y un documento
// con infinitas representaciones byte-distintas que "verifican" — justo lo que
// impide archivar un recibo y compararlo años después.
//
// La causa: la firma del emisor se verificaba sobre un RE-RENDER limpio, no sobre
// lo recibido, y el decodificador base64 de Go ignora \r y \n. Ahora Parse exige
// que la parte de máquina recibida sea byte a byte la que Format volvería a
// producir (C.3 del Sprint 7c), la misma regla que el fuzzer impuso al testigo.

// lineaCon devuelve el recibo con un sufijo pegado al final de la línea i.
func lineaCon(t *testing.T, data []byte, i int, sufijo string) []byte {
	t.Helper()
	lineas := strings.Split(string(data), "\n")
	if i >= len(lineas) {
		t.Fatalf("el recibo tiene %d líneas, no hay línea %d", len(lineas), i)
	}
	lineas[i] += sufijo
	return []byte(strings.Join(lineas, "\n"))
}

// indiceDe devuelve el índice de la primera línea que cumple la condición.
func indiceDe(t *testing.T, data []byte, cond func(string) bool) int {
	t.Helper()
	for i, l := range strings.Split(string(data), "\n") {
		if cond(l) {
			return i
		}
	}
	t.Fatal("no se encontró la línea buscada")
	return -1
}

func TestParseRechazaLaParteDeMaquinaNoCanonica(t *testing.T) {
	sc := newScene(t, 1)
	r, err := sc.issue(t, "María Pérez", 1)
	if err != nil {
		t.Fatal(err)
	}
	data, err := Format(r, sc.policy())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Parse(data, sc.policy()); err != nil {
		t.Fatalf("control: el recibo íntegro no parsea: %v", err)
	}

	esB64Largo := func(l string) bool { return len(l) == 88 && strings.HasSuffix(l, "==") }
	esFirmaEmisor := func(l string) bool { return strings.HasPrefix(l, ReceiptSigPrefix+testTenant+" ") }
	esNodo := func(l string) bool { return len(l) == 44 && strings.HasSuffix(l, "=") && !strings.Contains(l, " ") }

	firmaBloque := indiceDe(t, data, esB64Largo)
	firmaEmisor := indiceDe(t, data, esFirmaEmisor)
	primerNodo := indiceDe(t, data, esNodo)

	// Los cinco casos exactos de la auditoría, más los que el mismo mecanismo
	// dejaba pasar y nadie había probado.
	for _, c := range []struct {
		nombre string
		linea  int
		sufijo string
		// porCanonicidad marca los casos que ANTES se aceptaban y que solo la
		// comparación de bytes rechaza. Los demás los para una comprobación
		// estructural anterior (el magic de la prueba, un base64 que no decodifica),
		// y para ellos basta con que se rechacen.
		porCanonicidad bool
	}{
		{"CR al final de la firma del bloque", firmaBloque, "\r", true},
		{"CR al final de la firma del emisor", firmaEmisor, "\r", true},
		{"CR al final del primer nodo de la prueba", primerNodo, "\r", true},
		{"CR al final del segundo nodo", primerNodo + 1, "\r", true},
		{"CR al final del tercer nodo", primerNodo + 2, "\r", true},
		{"LF extra tras la firma del bloque", firmaBloque, "\n", false},
		{"espacio al final de la firma del emisor", firmaEmisor, " ", false},
	} {
		t.Run(c.nombre, func(t *testing.T) {
			mutado := lineaCon(t, data, c.linea, c.sufijo)
			if string(mutado) == string(data) {
				t.Fatal("la mutación no cambió nada: el test no prueba nada")
			}
			_, err := Parse(mutado, sc.policy())
			if err == nil {
				t.Fatalf("Parse ACEPTÓ un recibo no canónico (línea %d + %q)", c.linea, c.sufijo)
			}
			if !c.porCanonicidad {
				return
			}
			// El rechazo tiene que ser de FORMATO, no de firma: la firma del emisor
			// verificaría sobre el re-render, que es justo el hueco. Se exige que se
			// cierre en la comparación de bytes y que el mensaje lo diga.
			if !errors.Is(err, ErrFormat) {
				t.Errorf("err = %v, want ErrFormat (forma no canónica)", err)
			}
			if !strings.Contains(err.Error(), "forma canónica") {
				t.Errorf("el mensaje no dice que la forma no es canónica: %v", err)
			}
		})
	}
}

// TestFormatParseEsIdempotenteEnLosBytes deja escrita la propiedad que hace útil
// todo lo anterior: Format(Parse(x)) == x para todo recibo que Parse acepta.
func TestFormatParseEsIdempotenteEnLosBytes(t *testing.T) {
	sc := newScene(t, 2)
	for _, idx := range []uint64{0, 1, 3} {
		r, err := sc.issue(t, "Contraparte S.A.", idx)
		if err != nil {
			t.Fatal(err)
		}
		data, err := Format(r, sc.policy())
		if err != nil {
			t.Fatal(err)
		}
		back, err := Parse(data, sc.policy())
		if err != nil {
			t.Fatal(err)
		}
		again, err := Format(back, sc.policy())
		if err != nil {
			t.Fatal(err)
		}
		if string(again) != string(data) {
			t.Errorf("bloque %d: Format(Parse(x)) != x", idx)
		}
	}
}
