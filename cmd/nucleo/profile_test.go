//go:build testhooks

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nucleoledger/nucleo/profiles/ecuador"
)

// claveDemo arma una clave de acceso válida para los tests. El dígito
// verificador se calcula, no se escribe: escribirlo a mano en un test que
// verifica el cálculo sería circular.
// claveDemo devuelve una clave de acceso COHERENTE con el XML de facturaXML:
// los ocho campos que codifica son los mismos que el XML declara aparte, que es
// lo que el perfil coteja desde el hallazgo MEDIO de la auditoría pre-pública.
func claveDemo() string {
	base := "07092026" + // fecha de emisión
		"01" + // factura
		"1790012345001" + // RUC del emisor
		"1" + // ambiente: pruebas
		"001" + // establecimiento
		"001" + // punto de emisión
		"000000001" + // secuencial
		"12345678" + // código numérico
		"1" // tipo de emisión
	return base + fmt.Sprint(ecuador.DigitoVerificador(base))
}

// facturaXML escribe un XML de factura con la clave dada.
func (c *cli) facturaXML(t *testing.T, clave string) string {
	t.Helper()
	path := filepath.Join(c.dir, "factura-"+clave[44:]+".xml")
	body := `<?xml version="1.0" encoding="UTF-8"?>
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
</factura>`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestSealProfileGolden fija la salida de sellar con perfil.
//
// Lo que importa del golden no es el formato por sí mismo, sino que la línea
// del importe y la de la cédula NO aparezcan nunca en claro. Un cambio que las
// imprimiera "para depurar" rompería este test, que es exactamente para lo que
// está.
func TestSealProfileGolden(t *testing.T) {
	c := newCLI(t)
	c.initLedger()
	xmlPath := c.facturaXML(t, claveDemo())

	out := c.mustRun("seal", "--profile", "ecuador.sri.factura", "--xml", xmlPath)

	for _, want := range []string{
		"perfil       : ecuador.sri.factura",
		"clave_acceso:            " + claveDemo(),
		"ruc_emisor:              1790012345001",
		"tipo_comprobante:        01",
		"fecha_emision:           2026-09-07",
		"campos sensibles, registrados como COMPROMISO (nunca como hash desnudo)",
		"identificacion_comprador: hmac-sha256/v1:",
		"importe_total:           hmac-sha256/v1:",
		"razon_social_comprador:  hmac-sha256/v1:",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("la salida no contiene %q:\n%s", want, out)
		}
	}

	// LO QUE NO PUEDE APARECER. Es la mitad importante del test.
	for _, prohibido := range []string{"1712345678", "MARIA PEREZ", "11500.00"} {
		if strings.Contains(out, prohibido) {
			t.Errorf("%q aparece EN CLARO en la salida:\n%s", prohibido, out)
		}
	}
}

// TestSealProfileRechazaDigitoVerificador es el rechazo que evita sellar un
// comprobante que el SRI no reconocerá. Una vez en el ledger no se puede
// quitar, así que la validación va antes de escribir nada.
func TestSealProfileRechazaDigitoVerificador(t *testing.T) {
	c := newCLI(t)
	c.initLedger()

	malo := claveDemo()[:48] + "9"
	if malo == claveDemo() {
		t.Fatal("el dígito alterado coincide con el bueno: el test no probaría nada")
	}
	xmlPath := c.facturaXML(t, malo)

	out, stderr, code := c.run("seal", "--profile", "ecuador.sri.factura", "--xml", xmlPath)
	if code != exitUsage {
		t.Fatalf("código = %d, want %d\n%s", code, exitUsage, out)
	}
	if !strings.Contains(stderr, "dígito verificador") || !strings.Contains(stderr, "módulo 11") {
		t.Errorf("el mensaje no explica el problema:\n%s", stderr)
	}

	// Y nada quedó sellado.
	st := c.mustRun("--json", "status")
	var v map[string]any
	if err := json.Unmarshal([]byte(st), &v); err != nil {
		t.Fatal(err)
	}
	if v["tree_size"] != float64(0) {
		t.Errorf("se selló algo pese al rechazo: tree_size = %v", v["tree_size"])
	}
}

// TestSealProfileRechazaTenantQueNoCuadra: si quien invoca dice un RUC y el
// documento dice otro, alguien se equivocó de fichero. Sellar el que sea es
// peor que parar.
func TestSealProfileRechazaTenantQueNoCuadra(t *testing.T) {
	c := newCLI(t)
	c.initLedger()
	xmlPath := c.facturaXML(t, claveDemo())

	_, stderr, code := c.run("seal", "--profile", "ecuador.sri.factura",
		"--xml", xmlPath, "--tenant", "0999999999001")
	if code != exitUsage {
		t.Errorf("código = %d, want %d", code, exitUsage)
	}
	if !strings.Contains(stderr, "el documento dice") {
		t.Errorf("stderr = %q", stderr)
	}
}

// TestSealProfileJSONLlevaCompromisos comprueba la salida para máquinas.
func TestSealProfileJSONLlevaCompromisos(t *testing.T) {
	c := newCLI(t)
	c.initLedger()
	xmlPath := c.facturaXML(t, claveDemo())

	out := c.mustRun("--json", "seal", "--profile", "ecuador.sri.factura", "--xml", xmlPath)
	var v struct {
		Profile     string            `json:"profile"`
		Metadata    map[string]string `json:"metadata"`
		Commitments map[string]string `json:"commitments"`
	}
	if err := json.Unmarshal([]byte(out), &v); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if v.Profile != "ecuador.sri.factura" {
		t.Errorf("profile = %q", v.Profile)
	}
	if v.Metadata["ruc_emisor"] != "1790012345001" {
		t.Errorf("metadata = %+v", v.Metadata)
	}
	if len(v.Commitments) != 3 {
		t.Errorf("%d compromisos, want 3", len(v.Commitments))
	}
	for name, com := range v.Commitments {
		if !strings.HasPrefix(com, "hmac-sha256/v1:") {
			t.Errorf("%s no lleva el algoritmo: %q", name, com)
		}
	}
	// Ni en JSON aparecen los valores en claro.
	if strings.Contains(out, "1712345678") || strings.Contains(out, "11500.00") {
		t.Errorf("valores sensibles en la salida JSON:\n%s", out)
	}
}
