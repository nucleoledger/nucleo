package receipt

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/nucleoledger/nucleo/internal/ledger"
	"github.com/nucleoledger/nucleo/internal/proof"
)

// timeLayout es el formato de los dos relojes: RFC 3339 en UTC, el mismo que
// usa el header del bloque.
const timeLayout = "2006-01-02T15:04:05Z07:00"

// Format serializa el recibo: encabezado legible, separador, y la parte de
// máquina —header canónico y prueba de c2sp.org/tlog-proof—.
//
// El encabezado se DERIVA de la parte de máquina, siempre. No hay ningún campo
// que un emisor pueda rellenar a mano con una cosa distinta de la que dice la
// prueba, y Parse lo vuelve a comprobar. Un recibo es un documento que alguien
// va a leer y creer: que su texto visible pueda contradecir sus bytes
// verificables sería el peor defecto posible de este paquete.
func Format(r *Receipt) ([]byte, error) {
	text, err := renderText(r)
	if err != nil {
		return nil, err
	}
	canonical, err := r.Header.Canonical()
	if err != nil {
		return nil, err
	}
	tlogProof, err := proof.Format(r.Proof)
	if err != nil {
		return nil, err
	}

	var b bytes.Buffer
	b.Write(text)
	b.WriteString(separator + "\n")
	b.Write(canonical)
	b.WriteString("\n")
	b.Write(tlogProof)
	return b.Bytes(), nil
}

// renderText compone el encabezado legible.
func renderText(r *Receipt) ([]byte, error) {
	declared, err := r.DeclaredTime()
	if err != nil {
		return nil, err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s\n", Magic)
	fmt.Fprintf(&b, "destinatario      : %s\n", r.Recipient)
	fmt.Fprintf(&b, "emisor (tenant)   : %s\n", r.Header.Tenant)
	fmt.Fprintf(&b, "tipo de registro  : %s\n", r.Header.Type)
	fmt.Fprintf(&b, "hash del contenido: %s\n", r.Header.PayloadHash)
	fmt.Fprintf(&b, "bloque            : %d\n", r.Header.Index)
	b.WriteString("\n")
	fmt.Fprintf(&b, "TIEMPO DECLARADO  : %s  (declarado por el sistema emisor)\n",
		declared.UTC().Format(timeLayout))
	if provable, ok := r.ProvableTime(); ok {
		fmt.Fprintf(&b, "TIEMPO DEMOSTRABLE: %s  (atestiguado por testigos)\n",
			provable.UTC().Format(timeLayout))
	} else {
		fmt.Fprintf(&b, "TIEMPO DEMOSTRABLE: %s\n", NoProvableTime)
	}
	b.WriteString("\n")
	return []byte(b.String()), nil
}

// Parse lee un recibo y comprueba que su texto legible sea EXACTAMENTE el que
// se deriva de la prueba.
//
// Esa comprobación es el motivo de que Parse exista. Sin ella, cualquiera
// podría entregar un recibo cuya prueba es impecable y cuyo texto visible dice
// otra fecha, otro importe o otro destinatario, contando con que nadie lea los
// bytes. El recibo es un documento para personas: el texto tiene que valer
// tanto como la firma.
func Parse(data []byte) (*Receipt, error) {
	i := bytes.Index(data, []byte(separator+"\n"))
	if i < 0 {
		return nil, fmt.Errorf("%w: falta el separador %q", ErrFormat, separator)
	}
	text, machine := data[:i], data[i+len(separator)+1:]

	recipient, err := textField(text, "destinatario      : ")
	if err != nil {
		return nil, err
	}

	// El header canónico ocupa una línea: es JCS, que no lleva saltos.
	nl := bytes.IndexByte(machine, '\n')
	if nl < 0 {
		return nil, fmt.Errorf("%w: falta el header canónico", ErrFormat)
	}
	var h ledger.Header
	if err := json.Unmarshal(machine[:nl], &h); err != nil {
		return nil, fmt.Errorf("%w: header ilegible: %v", ErrFormat, err)
	}
	// Los bytes del header tienen que ser la forma canónica JCS, que es lo que
	// se firmó. Recanonicalizar por lo bajo escondería una diferencia real.
	canonical, err := h.Canonical()
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(canonical, machine[:nl]) {
		return nil, fmt.Errorf("%w: el header no está en forma canónica JCS", ErrFormat)
	}

	p, err := proof.Parse(machine[nl+1:])
	if err != nil {
		return nil, err
	}
	r := &Receipt{Recipient: recipient, Header: h, Proof: p}

	want, err := renderText(r)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(want, text) {
		return nil, fmt.Errorf("%w:\nse leyó:\n%s\nla prueba dice:\n%s", ErrTextMismatch, text, want)
	}
	return r, nil
}

// textField extrae el valor de una línea del encabezado.
func textField(text []byte, prefix string) (string, error) {
	for _, line := range strings.Split(string(text), "\n") {
		if v, ok := strings.CutPrefix(line, prefix); ok {
			return v, nil
		}
	}
	return "", fmt.Errorf("%w: falta la línea %q", ErrFormat, strings.TrimSpace(prefix))
}

// Verify comprueba la prueba con la política dada y, además, que el tiempo
// demostrable impreso esté respaldado por testigos que la política acepta.
//
// Lo segundo importa tanto como lo primero. Un recibo puede traer una
// cosignature de un testigo cualquiera y presentarla como tiempo demostrable; si
// quien verifica no confía en ese testigo, el recibo NO puede seguir mostrando
// esa fecha como atestiguada. Que la prueba de inclusión sea correcta no
// convierte en cierto lo que dice el encabezado.
func (r *Receipt) Verify(p proof.Policy) (proof.Result, error) {
	entryHash, err := r.EntryHash()
	if err != nil {
		return proof.Result{}, err
	}
	res, err := r.Proof.Verify(entryHash, p)
	if err != nil {
		return proof.Result{}, err
	}
	printed, hasPrinted := r.ProvableTime()
	switch {
	case !hasPrinted && len(res.Cosigners) == 0:
		return res, nil
	case !hasPrinted:
		return proof.Result{}, fmt.Errorf("%w: el recibo no declara tiempo demostrable y la prueba trae %d cosignatures",
			ErrTextMismatch, len(res.Cosigners))
	case len(res.Cosigners) == 0:
		return proof.Result{}, fmt.Errorf("%w: el recibo declara tiempo demostrable %s y ningún testigo de la política lo respalda",
			ErrTextMismatch, printed.UTC().Format(timeLayout))
	case !res.ProvableTime.Equal(printed):
		return proof.Result{}, fmt.Errorf("%w: el recibo declara %s y los testigos de la política atestiguan %s",
			ErrTextMismatch, printed.UTC().Format(timeLayout), res.ProvableTime.UTC().Format(timeLayout))
	}
	return res, nil
}

// Text devuelve solo el encabezado legible, para imprimirlo.
func Text(data []byte) string {
	if i := bytes.Index(data, []byte(separator)); i >= 0 {
		return strings.TrimRight(string(data[:i]), "\n")
	}
	return ""
}
