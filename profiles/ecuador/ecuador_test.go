package ecuador

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// Los dígitos verificadores de este fichero se calcularon FUERA de este código,
// con un script de python que transcribe la semántica de una implementación PHP
// independiente (github.com/bitaldu/Clave-de-acceso-SRI), cuyo algoritmo
// coincide con la descripción de la Ficha Técnica del SRI: recorrido de derecha
// a izquierda, pesos cíclicos 2..7, dv = 11 − (suma mód 11), con 10 → 1 y
// 11 → 0.
//
// Conviene dejar constancia de algo que apareció al buscar la fuente: varios
// artículos divulgativos publican ejemplos numéricos que NO cuadran con el
// algoritmo que ellos mismos describen —uno de ellos con una clave de 50
// dígitos—. Por eso el oráculo es una implementación, no un blog.

func TestDigitoVerificadorGolden(t *testing.T) {
	cases := []struct {
		nombre string
		base   string
		want   int
	}{
		{"ejemplo de la implementación PHP", "050320200717231252640012001002000001193050320001", 4},
		{"desglose de campos del artículo", "040520260117912345670012001001000000123123456781", 4},
		{"factura de la demo de Núcleo", "070920260117900123450010010010000000011234567811", 1},
		{"todo ceros", strings.Repeat("0", 48), 0},
		{"todo unos", strings.Repeat("1", 48), 4},
	}
	for _, c := range cases {
		t.Run(c.nombre, func(t *testing.T) {
			if len(c.base) != 48 {
				t.Fatalf("la base mide %d, deben ser 48", len(c.base))
			}
			if got := DigitoVerificador(c.base); got != c.want {
				t.Errorf("dv = %d, want %d (calculado con python fuera de este código)", got, c.want)
			}
		})
	}
}

// TestDigitoVerificadorCasosEspeciales: los dos casos que un dígito decimal no
// puede representar. Omitirlos es el error clásico, y no se nota hasta que
// aparece una clave que cae justo ahí.
func TestDigitoVerificadorCasosEspeciales(t *testing.T) {
	// Se recorren claves base hasta encontrar una de cada caso, y se comprueba
	// que el resultado esté siempre en 0..9. Buscarlas en vez de inventarlas
	// evita fijar un vector que no ejercite lo que dice ejercitar.
	var vio0, vio1 bool
	for i := 0; i < 200; i++ {
		base := fmt.Sprintf("%048d", i)
		d := DigitoVerificador(base)
		if d < 0 || d > 9 {
			t.Fatalf("base %s dio un dígito fuera de rango: %d", base, d)
		}
		suma := 0
		peso := 2
		for j := len(base) - 1; j >= 0; j-- {
			suma += int(base[j]-'0') * peso
			if peso == 7 {
				peso = 2
			} else {
				peso++
			}
		}
		switch 11 - suma%11 {
		case 11:
			vio0 = true
			if d != 0 {
				t.Errorf("11 debía dar 0, dio %d", d)
			}
		case 10:
			vio1 = true
			if d != 1 {
				t.Errorf("10 debía dar 1, dio %d", d)
			}
		}
	}
	if !vio0 || !vio1 {
		t.Errorf("no se ejercitaron los dos casos especiales (11→0: %v, 10→1: %v)", vio0, vio1)
	}
}

// TestParseClaveAccesoRechaza cubre lo que no es una clave de acceso.
func TestParseClaveAccesoRechaza(t *testing.T) {
	buena := "0709202601179001234500100100100000000112345678" + "11" + "1"
	if len(buena) != 49 {
		t.Fatalf("la clave de prueba mide %d", len(buena))
	}
	if _, err := ParseClaveAcceso(buena); err != nil {
		t.Fatalf("la clave buena se rechazó: %v", err)
	}

	// El caso central: un dígito verificador incorrecto.
	malo := buena[:48] + "9"
	_, err := ParseClaveAcceso(malo)
	if !errors.Is(err, ErrDigitoVerificador) {
		t.Fatalf("dv incorrecto: err = %v, want %v", err, ErrDigitoVerificador)
	}
	// Y el mensaje dice qué se esperaba, porque quien lo lee está tecleando.
	if !strings.Contains(err.Error(), "módulo 11") {
		t.Errorf("el mensaje no explica el fallo: %v", err)
	}

	for _, c := range []struct{ nombre, clave string }{
		{"corta", buena[:48]},
		{"larga", buena + "0"},
		{"con letras", "A" + buena[1:]},
		{"vacía", ""},
	} {
		if _, err := ParseClaveAcceso(c.clave); !errors.Is(err, ErrClaveAcceso) {
			t.Errorf("%s: err = %v, want %v", c.nombre, err, ErrClaveAcceso)
		}
	}
}

// TestParseClaveAccesoDesglosa comprueba el troceado por posiciones.
func TestParseClaveAccesoDesglosa(t *testing.T) {
	base := "070920260117900123450010010010000000011234567811"
	clave := base + fmt.Sprint(DigitoVerificador(base))

	c, err := ParseClaveAcceso(clave)
	if err != nil {
		t.Fatal(err)
	}
	if got := c.FechaEmision.Format("2006-01-02"); got != "2026-09-07" {
		t.Errorf("fecha = %s, want 2026-09-07", got)
	}
	if c.TipoComprobante != "01" || TipoComprobanteNombre(c.TipoComprobante) != "factura" {
		t.Errorf("tipo = %q (%s)", c.TipoComprobante, TipoComprobanteNombre(c.TipoComprobante))
	}
	if c.RUCEmisor != "1790012345001" {
		t.Errorf("RUC = %q", c.RUCEmisor)
	}
	if err := ValidarRUC(c.RUCEmisor); err != nil {
		t.Errorf("el RUC extraído no valida: %v", err)
	}
}

// TestValidarRUC cubre la forma del RUC.
func TestValidarRUC(t *testing.T) {
	if err := ValidarRUC("1790012345001"); err != nil {
		t.Errorf("RUC válido rechazado: %v", err)
	}
	for _, malo := range []string{"179001234500", "17900123450012", "179001234500A", "1790012345002"} {
		if err := ValidarRUC(malo); err == nil {
			t.Errorf("se aceptó el RUC %q", malo)
		}
	}
}

// facturaEjemplo es un XML de factura del SRI con la estructura real. La firma
// XAdES no se incluye porque este perfil no la valida: el XML se sella BYTE A
// BYTE y la firma la comprueba el SRI, no Núcleo.
func facturaEjemplo(t *testing.T, clave string) []byte {
	t.Helper()
	return []byte(`<?xml version="1.0" encoding="UTF-8"?>
<factura id="comprobante" version="1.0.0">
  <infoTributaria>
    <ambiente>1</ambiente>
    <tipoEmision>1</tipoEmision>
    <razonSocial>DISTRIBUIDORA DEL LITORAL S.A.S.</razonSocial>
    <ruc>1790012345001</ruc>
    <claveAcceso>` + clave + `</claveAcceso>
    <codDoc>01</codDoc>
    <estab>001</estab>
    <ptoEmi>001</ptoEmi>
    <secuencial>000000001</secuencial>
  </infoTributaria>
  <infoFactura>
    <fechaEmision>07/09/2026</fechaEmision>
    <identificacionComprador>1712345678</identificacionComprador>
    <razonSocialComprador>MARIA PEREZ</razonSocialComprador>
    <totalSinImpuestos>10000.00</totalSinImpuestos>
    <importeTotal>11500.00</importeTotal>
  </infoFactura>
</factura>`)
}

func claveDemo() string {
	base := "070920260117900123450010010010000000011234567811"
	return base + fmt.Sprint(DigitoVerificador(base))
}

// TestParseFacturaSeparaLoSensible es lo que define un perfil: decidir qué se
// puede publicar y qué no.
func TestParseFacturaSeparaLoSensible(t *testing.T) {
	rec, clave, err := ParseFactura(facturaEjemplo(t, claveDemo()))
	if err != nil {
		t.Fatal(err)
	}
	if rec.Type != TipoFactura {
		t.Errorf("tipo = %q", rec.Type)
	}
	if clave.RUCEmisor != "1790012345001" {
		t.Errorf("RUC = %q", clave.RUCEmisor)
	}

	plain := map[string]string{}
	for _, f := range rec.Plain() {
		plain[f.Name] = f.Value
	}
	sensible := map[string]string{}
	for _, f := range rec.Sensitive() {
		sensible[f.Name] = f.Value
	}

	// La cédula del comprador, su nombre y el importe NO pueden ir en claro.
	for _, k := range []string{"identificacion_comprador", "razon_social_comprador", "importe_total"} {
		if _, ok := plain[k]; ok {
			t.Errorf("%s viaja en claro y es un dato adivinable o personal", k)
		}
		if _, ok := sensible[k]; !ok {
			t.Errorf("%s no está marcado como comprometible", k)
		}
	}
	// La clave de acceso sí: es el identificador público ante el SRI.
	if plain["clave_acceso"] != clave.Raw {
		t.Errorf("clave_acceso = %q", plain["clave_acceso"])
	}

	// Y cada decisión lleva su motivo escrito.
	for _, f := range rec.Fields {
		if strings.TrimSpace(f.Why) == "" {
			t.Errorf("el campo %q no explica por qué se trata así", f.Name)
		}
	}
}

// TestParseFacturaRechaza cubre los documentos que no se pueden sellar.
func TestParseFacturaRechaza(t *testing.T) {
	buena := claveDemo()

	t.Run("dígito verificador incorrecto", func(t *testing.T) {
		mala := buena[:48] + "9"
		_, _, err := ParseFactura(facturaEjemplo(t, mala))
		if !errors.Is(err, ErrDigitoVerificador) {
			t.Fatalf("err = %v, want %v", err, ErrDigitoVerificador)
		}
	})

	t.Run("el RUC del XML no es el de la clave", func(t *testing.T) {
		xmlRaw := strings.Replace(string(facturaEjemplo(t, buena)),
			"<ruc>1790012345001</ruc>", "<ruc>0999999999001</ruc>", 1)
		_, _, err := ParseFactura([]byte(xmlRaw))
		if !errors.Is(err, ErrDocumento) {
			t.Fatalf("err = %v, want %v", err, ErrDocumento)
		}
	})

	t.Run("no es XML", func(t *testing.T) {
		if _, _, err := ParseFactura([]byte("esto no es un XML")); !errors.Is(err, ErrDocumento) {
			t.Errorf("err = %v, want %v", err, ErrDocumento)
		}
	})
}

// TestParseActa cubre el segundo tipo del perfil.
func TestParseActa(t *testing.T) {
	acta := Acta{
		RazonSocial: "DISTRIBUIDORA DEL LITORAL S.A.S.",
		FechaJunta:  "2026-09-07",
		TipoActa:    "junta-general-ordinaria",
		Socios:      []string{"María Pérez", "Juan Gómez", "Ana Salazar"},
	}
	rec, err := ParseActa(acta)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Type != TipoActa {
		t.Errorf("tipo = %q", rec.Type)
	}
	// Cada socio va como compromiso INDEPENDIENTE, no como una lista unida:
	// una lista comprometida entera solo demostraría "esta lista exacta", y
	// basta que alguien llegue tarde para que deje de servir.
	if n := len(rec.Sensitive()); n != 3 {
		t.Errorf("%d campos comprometidos, want 3 (uno por socio)", n)
	}
	for _, f := range rec.Sensitive() {
		if !strings.HasPrefix(f.Name, "socio_") {
			t.Errorf("campo comprometido inesperado: %q", f.Name)
		}
	}
	if n := len(rec.Plain()); n != 3 {
		t.Errorf("%d campos en claro, want 3", n)
	}

	for _, c := range []struct {
		nombre string
		acta   Acta
	}{
		{"sin razón social", Acta{FechaJunta: "2026-09-07", TipoActa: "x", Socios: []string{"a"}}},
		{"sin tipo", Acta{RazonSocial: "X", FechaJunta: "2026-09-07", Socios: []string{"a"}}},
		{"sin socios", Acta{RazonSocial: "X", FechaJunta: "2026-09-07", TipoActa: "x"}},
		{"fecha mal", Acta{RazonSocial: "X", FechaJunta: "07/09/2026", TipoActa: "x", Socios: []string{"a"}}},
		{"socio vacío", Acta{RazonSocial: "X", FechaJunta: "2026-09-07", TipoActa: "x", Socios: []string{"a", "  "}}},
	} {
		if _, err := ParseActa(c.acta); !errors.Is(err, ErrDocumento) {
			t.Errorf("%s: err = %v, want %v", c.nombre, err, ErrDocumento)
		}
	}
}
