package ecuador

import (
	"encoding/xml"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Tipos de registro que aporta este perfil.
const (
	TipoFactura = "ecuador.sri.factura.v1"
	TipoActa    = "ecuador.sas.acta.v1"
)

// Sensitivity dice cómo debe viajar un campo al ledger.
type Sensitivity int

const (
	// Plain: el campo es público o no adivinable, y va como metadato en claro.
	Plain Sensitivity = iota
	// Committed: el campo es adivinable o personal y va como COMPROMISO.
	//
	// Nunca como hash desnudo: PROTOCOL.md §5 lo prohíbe, y el motivo es que
	// una cédula, un RUC o un importe viven en un espacio de valores tan
	// pequeño que un hash público se invierte probando.
	Committed
)

// Field describe un campo del perfil.
type Field struct {
	Name        string
	Value       string
	Sensitivity Sensitivity
	// Why explica, para quien lea el registro dentro de años, por qué este
	// campo se trató así. Las decisiones de privacidad sin motivo escrito se
	// acaban revirtiendo por comodidad.
	Why string
}

// Record es lo que un perfil extrae de un documento: metadatos en claro y
// campos que deben comprometerse.
type Record struct {
	Type   string
	Fields []Field
}

// Plain devuelve los campos que van en claro.
func (r Record) Plain() []Field { return r.filter(Plain) }

// Sensitive devuelve los campos que deben comprometerse.
func (r Record) Sensitive() []Field { return r.filter(Committed) }

func (r Record) filter(s Sensitivity) []Field {
	var out []Field
	for _, f := range r.Fields {
		if f.Sensitivity == s {
			out = append(out, f)
		}
	}
	return out
}

// ErrDocumento indica un documento que el perfil no puede interpretar.
var ErrDocumento = errors.New("ecuador: documento inválido")

// facturaXML es lo mínimo que se lee del XML del SRI.
//
// Se leen los campos por su nombre y NO se reserializa nada: el XML se sella
// byte a byte, como manda PROTOCOL.md §5, porque lleva una firma XAdES-BES que
// cualquier recanonicalización rompería. Este parseo sirve para los metadatos
// del perfil, no para el sellado.
type facturaXML struct {
	XMLName  xml.Name `xml:"factura"`
	InfoTrib struct {
		Ambiente    string `xml:"ambiente"`
		RazonSocial string `xml:"razonSocial"`
		RUC         string `xml:"ruc"`
		ClaveAcceso string `xml:"claveAcceso"`
		CodDoc      string `xml:"codDoc"`
		Estab       string `xml:"estab"`
		PtoEmi      string `xml:"ptoEmi"`
		Secuencial  string `xml:"secuencial"`
	} `xml:"infoTributaria"`
	InfoFactura struct {
		FechaEmision            string `xml:"fechaEmision"`
		IdentificacionComprador string `xml:"identificacionComprador"`
		RazonSocialComprador    string `xml:"razonSocialComprador"`
		ImporteTotal            string `xml:"importeTotal"`
		TotalSinImpuestos       string `xml:"totalSinImpuestos"`
	} `xml:"infoFactura"`
}

// ParseFactura extrae los metadatos de un XML de factura del SRI.
//
// El XML entra tal cual y sale tal cual: esta función no lo modifica ni lo
// vuelve a serializar. Lo que devuelve son METADATOS para el perfil; lo que se
// sella son los bytes originales.
func ParseFactura(raw []byte) (Record, ClaveAcceso, error) {
	var doc facturaXML
	if err := xml.Unmarshal(raw, &doc); err != nil {
		return Record{}, ClaveAcceso{}, fmt.Errorf("%w: no es un XML de factura: %w", ErrDocumento, err)
	}
	clave, err := ParseClaveAcceso(strings.TrimSpace(doc.InfoTrib.ClaveAcceso))
	if err != nil {
		return Record{}, ClaveAcceso{}, err
	}
	if err := ValidarRUC(doc.InfoTrib.RUC); err != nil {
		return Record{}, ClaveAcceso{}, err
	}
	if doc.InfoTrib.RUC != clave.RUCEmisor {
		return Record{}, ClaveAcceso{}, fmt.Errorf(
			"%w: el RUC del XML (%s) no es el de la clave de acceso (%s)",
			ErrDocumento, doc.InfoTrib.RUC, clave.RUCEmisor)
	}

	rec := Record{Type: TipoFactura, Fields: []Field{
		{Name: "clave_acceso", Value: clave.Raw, Sensitivity: Plain,
			Why: "es el identificador público del comprobante ante el SRI; sin él el registro no se puede cruzar con nada"},
		{Name: "ruc_emisor", Value: clave.RUCEmisor, Sensitivity: Plain,
			Why: "es quien emite y quien sella: ocultárselo a sí mismo no protege a nadie"},
		{Name: "tipo_comprobante", Value: clave.TipoComprobante, Sensitivity: Plain,
			Why: "hay siete valores posibles; comprometerlo no ocultaría nada y estorbaría al filtrar"},
		{Name: "fecha_emision", Value: clave.FechaEmision.Format("2006-01-02"), Sensitivity: Plain,
			Why: "va dentro de la clave de acceso, que ya es pública"},
		{Name: "establecimiento", Value: clave.Establecimiento, Sensitivity: Plain,
			Why: "va dentro de la clave de acceso"},
		{Name: "secuencial", Value: clave.Secuencial, Sensitivity: Plain,
			Why: "va dentro de la clave de acceso"},

		{Name: "identificacion_comprador", Value: doc.InfoFactura.IdentificacionComprador, Sensitivity: Committed,
			Why: "es una cédula o RUC de un TERCERO: diez o trece dígitos con estructura conocida, invertibles por fuerza bruta si viajaran como hash"},
		{Name: "razon_social_comprador", Value: doc.InfoFactura.RazonSocialComprador, Sensitivity: Committed,
			Why: "identifica a una persona o empresa concreta y suele estar en registros públicos, así que un hash se invierte con una lista"},
		{Name: "importe_total", Value: doc.InfoFactura.ImporteTotal, Sensitivity: Committed,
			Why: "los importes tienen poquísima entropía —dos decimales y un rango estrecho— y revelan el negocio"},
	}}
	return rec, clave, nil
}

// Acta son los datos de un acta de junta de una SAS.
type Acta struct {
	RazonSocial string   `json:"razon_social"`
	FechaJunta  string   `json:"fecha_junta"`
	TipoActa    string   `json:"tipo_acta"`
	Socios      []string `json:"socios_asistentes"`
}

// ParseActa valida un acta y decide qué va comprometido.
func ParseActa(a Acta) (Record, error) {
	switch {
	case strings.TrimSpace(a.RazonSocial) == "":
		return Record{}, fmt.Errorf("%w: falta la razón social", ErrDocumento)
	case a.TipoActa == "":
		return Record{}, fmt.Errorf("%w: falta el tipo de acta", ErrDocumento)
	case len(a.Socios) == 0:
		return Record{}, fmt.Errorf("%w: un acta de junta sin socios asistentes no es un acta", ErrDocumento)
	}
	if _, err := time.Parse("2006-01-02", a.FechaJunta); err != nil {
		return Record{}, fmt.Errorf("%w: fecha de junta %q no es aaaa-mm-dd", ErrDocumento, a.FechaJunta)
	}

	fields := []Field{
		{Name: "razon_social", Value: a.RazonSocial, Sensitivity: Plain,
			Why: "la sociedad que sella es la que consta en el registro mercantil, que es público"},
		{Name: "fecha_junta", Value: a.FechaJunta, Sensitivity: Plain,
			Why: "que hubo junta ese día es lo que el acta demuestra; ocultarlo vaciaría el registro"},
		{Name: "tipo_acta", Value: a.TipoActa, Sensitivity: Plain,
			Why: "conjunto cerrado y pequeño de valores; comprometerlo no ocultaría nada"},
	}
	// Cada socio va como compromiso independiente, no como una lista unida.
	// Una lista comprometida entera solo permitiría demostrar "esta lista
	// exacta", y basta que alguien llegue tarde para que no sirva; además, el
	// número de socios de una SAS es tan pequeño que probar permutaciones sería
	// trivial.
	for i, s := range a.Socios {
		if strings.TrimSpace(s) == "" {
			return Record{}, fmt.Errorf("%w: el socio %d está vacío", ErrDocumento, i+1)
		}
		fields = append(fields, Field{
			Name: fmt.Sprintf("socio_%d", i+1), Value: s, Sensitivity: Committed,
			Why: "quién asistió a una junta es un dato personal, y una lista de socios es corta y adivinable",
		})
	}
	return Record{Type: TipoActa, Fields: fields}, nil
}
