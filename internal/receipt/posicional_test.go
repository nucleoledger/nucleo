package receipt

import (
	"errors"
	"strings"
	"testing"
)

// TestCosignatureNoSeReclasificaComoFirmaDelEmisor fija una defensa que hasta
// ahora dependía de una constante sin vigilancia (C.7 del Sprint 7c).
//
// La auditoría adversarial preguntó por el camino inverso al que el formato
// protege: no que una línea nuestra caiga dentro de la nota del checkpoint, sino
// que una cosignature de testigo —que vive en la nota— se pegue en la posición de
// la firma del emisor. Lo que lo bloquea es la longitud: una tlog-cosignature@v1
// mide 4 + 8 + 64 = 76 bytes y una firma Ed25519 mide 64. Es una defensa real y
// buena, pero nada la probaba, y una constante que nadie vigila se cambia un día
// "para que cuadre" y nadie lo nota. Este test es la vigilancia.
func TestCosignatureNoSeReclasificaComoFirmaDelEmisor(t *testing.T) {
	sc := newScene(t, 1)
	r, err := sc.issue(t, "María Pérez", 1)
	if err != nil {
		t.Fatal(err)
	}
	data, err := Format(r, sc.policy())
	if err != nil {
		t.Fatal(err)
	}
	lineas := strings.Split(string(data), "\n")

	// La línea de la firma del emisor y la cosignature del testigo dentro de la
	// nota, localizadas por lo que son, no por su número de línea.
	emisor := -1
	testigo := -1
	for i, l := range lineas {
		switch {
		case strings.HasPrefix(l, ReceiptSigPrefix+testTenant+" "):
			emisor = i
		case strings.HasPrefix(l, ReceiptSigPrefix) && emisor >= 0 && i > emisor:
			// La primera línea de firma después de la del emisor está dentro de la
			// nota. Puede ser la del log o la del testigo; se busca la del testigo
			// por su nombre.
			for name := range sc.wits {
				if strings.HasPrefix(l, ReceiptSigPrefix+name+" ") {
					testigo = i
				}
			}
		}
	}
	if emisor < 0 || testigo < 0 {
		t.Fatalf("no se localizaron las dos líneas (emisor=%d, testigo=%d):\n%s", emisor, testigo, data)
	}

	// Ataque: la cosignature del testigo, re-etiquetada con el nombre del tenant
	// para pasar la comprobación de nombre, en la posición de la firma del emisor.
	blobTestigo := lineas[testigo][strings.LastIndex(lineas[testigo], " ")+1:]
	lineas[emisor] = ReceiptSigPrefix + testTenant + " " + blobTestigo
	mutado := strings.Join(lineas, "\n")
	if mutado == string(data) {
		t.Fatal("la sustitución no cambió nada: el test no prueba nada")
	}

	_, err = Parse([]byte(mutado), sc.policy())
	if err == nil {
		t.Fatal("una cosignature de testigo se aceptó como firma del emisor")
	}
	// Y tiene que caer POR LA LONGITUD, antes de intentar verificar nada: es la
	// defensa que este test vigila. Si algún día se relajara, este mensaje cambia y
	// el test lo dice.
	if !errors.Is(err, ErrFormat) || !strings.Contains(err.Error(), "firma del emisor de 76 bytes") {
		t.Errorf("err = %v; want ErrFormat por firma del emisor de 76 bytes, se esperaban 64", err)
	}
}
