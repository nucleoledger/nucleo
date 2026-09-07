// Package ecuador es el primer perfil sobre el core: los tipos de registro que
// una empresa ecuatoriana necesita sellar.
//
// Un perfil no cambia el protocolo. Aporta tres cosas sobre el núcleo genérico:
// qué campos tiene un tipo de documento, cómo se validan, y CUÁLES de ellos son
// adivinables y por tanto no pueden viajar como hash desnudo (PROTOCOL.md §5).
package ecuador

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// ClaveAccesoLen es la longitud de la clave de acceso del SRI.
const ClaveAccesoLen = 49

var (
	// ErrClaveAcceso indica una clave de acceso mal formada.
	ErrClaveAcceso = errors.New("ecuador: clave de acceso inválida")
	// ErrDigitoVerificador indica que el dígito 49 no cuadra con los 48 primeros.
	ErrDigitoVerificador = errors.New("ecuador: dígito verificador incorrecto")
)

// ClaveAcceso es la clave de 49 dígitos descompuesta en sus campos.
//
// El desglose por posiciones lo fija la Ficha Técnica de Comprobantes
// Electrónicos del SRI (esquema off-line):
//
//	 1–8   fecha de emisión, ddmmaaaa
//	 9–10  tipo de comprobante
//	11–23  RUC del emisor
//	   24  ambiente (1 pruebas, 2 producción)
//	25–27  establecimiento
//	28–30  punto de emisión
//	31–39  secuencial
//	40–47  código numérico
//	   48  tipo de emisión
//	   49  dígito verificador, módulo 11
type ClaveAcceso struct {
	Raw             string
	FechaEmision    time.Time
	TipoComprobante string
	RUCEmisor       string
	Ambiente        string
	Establecimiento string
	PuntoEmision    string
	Secuencial      string
	CodigoNumerico  string
	TipoEmision     string
	DigitoVerif     int
}

// TipoComprobanteNombre traduce el código a algo que una persona entienda.
func TipoComprobanteNombre(codigo string) string {
	switch codigo {
	case "01":
		return "factura"
	case "03":
		return "liquidación de compra"
	case "04":
		return "nota de crédito"
	case "05":
		return "nota de débito"
	case "06":
		return "guía de remisión"
	case "07":
		return "comprobante de retención"
	default:
		return "tipo " + codigo
	}
}

// ParseClaveAcceso valida la clave y la descompone.
//
// El dígito verificador se comprueba SIEMPRE. Es lo primero que separa un
// número tecleado mal de uno bueno, y dejarlo pasar significaría sellar un
// comprobante cuya clave no existe en el SRI: el registro quedaría en el ledger
// para siempre, apuntando a nada.
func ParseClaveAcceso(clave string) (ClaveAcceso, error) {
	if len(clave) != ClaveAccesoLen {
		return ClaveAcceso{}, fmt.Errorf("%w: mide %d dígitos, la clave de acceso tiene %d",
			ErrClaveAcceso, len(clave), ClaveAccesoLen)
	}
	for i := 0; i < len(clave); i++ {
		if clave[i] < '0' || clave[i] > '9' {
			return ClaveAcceso{}, fmt.Errorf("%w: el carácter %d (%q) no es un dígito",
				ErrClaveAcceso, i+1, string(clave[i]))
		}
	}

	base, dv := clave[:48], int(clave[48]-'0')
	if want := DigitoVerificador(base); dv != want {
		return ClaveAcceso{}, fmt.Errorf("%w: la clave termina en %d y el módulo 11 de los 48 dígitos anteriores da %d",
			ErrDigitoVerificador, dv, want)
	}

	fecha, err := time.Parse("02012006", clave[0:8])
	if err != nil {
		return ClaveAcceso{}, fmt.Errorf("%w: fecha de emisión %q no es ddmmaaaa", ErrClaveAcceso, clave[0:8])
	}

	return ClaveAcceso{
		Raw:             clave,
		FechaEmision:    fecha.UTC(),
		TipoComprobante: clave[8:10],
		RUCEmisor:       clave[10:23],
		Ambiente:        clave[23:24],
		Establecimiento: clave[24:27],
		PuntoEmision:    clave[27:30],
		Secuencial:      clave[30:39],
		CodigoNumerico:  clave[39:47],
		TipoEmision:     clave[47:48],
		DigitoVerif:     dv,
	}, nil
}

// DigitoVerificador calcula el dígito 49 sobre los 48 primeros, con el módulo 11
// del SRI.
//
// El algoritmo: se recorren los dígitos DE DERECHA A IZQUIERDA multiplicando
// cada uno por un peso que cicla 2,3,4,5,6,7; se suman los productos; el dígito
// es 11 menos el residuo de la suma entre 11, con dos casos especiales: si sale
// 11 el dígito es 0, y si sale 10 el dígito es 1.
//
// Los dos casos especiales existen porque un dígito decimal no puede valer 10
// ni 11. Omitirlos es el error clásico de las implementaciones caseras, y no se
// nota hasta que aparece una clave que cae justo ahí.
func DigitoVerificador(base string) int {
	suma, peso := 0, 2
	for i := len(base) - 1; i >= 0; i-- {
		suma += int(base[i]-'0') * peso
		if peso == 7 {
			peso = 2
		} else {
			peso++
		}
	}
	switch d := 11 - suma%11; d {
	case 11:
		return 0
	case 10:
		return 1
	default:
		return d
	}
}

// ValidarRUC comprueba la forma de un RUC: 13 dígitos que terminan en 001.
//
// NO se valida el dígito verificador del RUC: el SRI usa tres algoritmos
// distintos según el tercer dígito —persona natural, sociedad privada, sector
// público— y aplicar el que no toca rechazaría RUCs buenos. Rechazar un
// comprobante legítimo es peor que aceptar uno con un RUC mal tecleado, que de
// todos modos el SRI rechazará después.
func ValidarRUC(ruc string) error {
	if len(ruc) != 13 {
		return fmt.Errorf("%w: el RUC mide %d dígitos, se esperan 13", ErrClaveAcceso, len(ruc))
	}
	for i := 0; i < len(ruc); i++ {
		if ruc[i] < '0' || ruc[i] > '9' {
			return fmt.Errorf("%w: el RUC tiene caracteres que no son dígitos", ErrClaveAcceso)
		}
	}
	if !strings.HasSuffix(ruc, "001") {
		return fmt.Errorf("%w: el RUC %q no termina en 001", ErrClaveAcceso, ruc)
	}
	return nil
}
