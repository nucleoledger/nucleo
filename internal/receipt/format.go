package receipt

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
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
func Format(r *Receipt, p proof.Policy) ([]byte, error) {
	text, err := renderText(r, p)
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

	if len(r.BlockSig) != ed25519.SignatureSize {
		return nil, fmt.Errorf("%w: firma de bloque de %d bytes, se esperaban %d",
			ErrFormat, len(r.BlockSig), ed25519.SignatureSize)
	}

	var b bytes.Buffer
	b.Write(text)
	b.WriteString(separator + "\n")
	b.Write(canonical)
	b.WriteString("\n")
	// La firma del bloque va en su propia línea, entre el header y la prueba
	// (PROTOCOL.md §3.1). Aquí y no al final a propósito: la cola del recibo es la
	// nota del checkpoint, y proof.Parse consume todo lo que viene después de la
	// prueba. Cualquier línea pegada al final acabaría dentro de la nota, donde se
	// leería como una línea de firma más — una firma nuestra disfrazada de firma de
	// testigo es exactamente lo que no queremos que pueda pasar.
	b.WriteString(base64.StdEncoding.EncodeToString(r.BlockSig))
	b.WriteString("\n")
	// La firma del emisor, si ya está. Cuando no está, Format produce exactamente
	// los bytes que hay que firmar: es la misma función, y por eso no puede haber
	// discrepancia entre "lo que se firmó" y "lo que se publica menos la firma".
	// Definir el mensaje firmado como "el documento sin su línea de firma" y
	// construirlo con otra función sería el camino más corto a firmar una cosa y
	// publicar otra.
	if len(r.ReceiptSig) > 0 {
		b.WriteString(ReceiptSigPrefix)
		b.WriteString(r.Header.Tenant)
		b.WriteString(" ")
		b.WriteString(base64.StdEncoding.EncodeToString(r.ReceiptSig))
		b.WriteString("\n")
	}
	b.Write(tlogProof)
	return b.Bytes(), nil
}

// SignedBytes devuelve los bytes que la firma del emisor cubre: el recibo ENTERO
// tal como se publicará, menos su propia línea de firma.
//
// Cubre todo y no solo el destinatario a propósito. Firmar la línea del
// destinatario por separado permitiría recombinar una línea firmada con otra prueba,
// que es la forma clásica de convertir una firma en nada.
func SignedBytes(r *Receipt, p proof.Policy) ([]byte, error) {
	sin := *r
	sin.ReceiptSig = nil
	return Format(&sin, p)
}

// Sign firma el recibo con la clave del emisor —la misma que firmó el bloque— y
// deja la firma dentro.
//
// Se firma el digest SHA-256 de los bytes, no los bytes: es la convención de todo
// el protocolo (PROTOCOL.md §1) y permite que un verificador que ya calculó el
// digest no tenga que conservar el documento entero.
//
// Exige que la clave sea la de signer_pubkey. Firmar con otra produciría un recibo
// que no verifica, y descubrirlo al emitir es mucho mejor que descubrirlo cuando lo
// rechaza la contraparte.
func Sign(r *Receipt, p proof.Policy, priv ed25519.PrivateKey) error {
	if len(priv) != ed25519.PrivateKeySize {
		return fmt.Errorf("%w: clave privada de %d bytes", ErrFormat, len(priv))
	}
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok || hex.EncodeToString(pub) != r.Header.SignerPubKey {
		return fmt.Errorf("%w: la clave no es la de signer_pubkey del header", ErrFormat)
	}
	msg, err := SignedBytes(r, p)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(msg)
	r.ReceiptSig = ed25519.Sign(priv, digest[:])
	return nil
}

// VerifyReceiptSignature comprueba la firma del emisor sobre el recibo completo.
//
// La clave sale del header del propio recibo, y eso es lo que hace que esto no
// necesite PKI nueva: signer_pubkey está dentro del header, el header entra en la
// hoja desde leaf/v2, y la hoja está bajo una raíz que los testigos cosignan. La
// contraparte no tiene que pedirle la clave a nadie ni confiar en un directorio.
func VerifyReceiptSignature(r *Receipt, p proof.Policy) error {
	if len(r.ReceiptSig) == 0 {
		return ErrNoReceiptSignature
	}
	pub, err := hex.DecodeString(r.Header.SignerPubKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: signer_pubkey no es una clave Ed25519", ErrFormat)
	}
	msg, err := SignedBytes(r, p)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(msg)
	if !ed25519.Verify(pub, digest[:], r.ReceiptSig) {
		return ErrReceiptSignature
	}
	return nil
}

// renderText compone el encabezado legible bajo la política dada.
//
// La política entra aquí porque el tiempo demostrable no existe en abstracto:
// existe respecto a un conjunto de testigos en los que se confía. El emisor
// renderiza con la suya; quien recibe el recibo lo vuelve a renderizar con la
// suya al parsearlo, y si no coinciden, el recibo no se acepta. Es incómodo a
// propósito: enseñar una fecha que quien mira no puede verificar sería peor.
func renderText(r *Receipt, p proof.Policy) ([]byte, error) {
	declared, err := r.DeclaredTime()
	if err != nil {
		return nil, err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s\n", Magic)
	fmt.Fprintf(&b, "destinatario      : %s%s\n", r.Recipient, RecipientNote)
	fmt.Fprintf(&b, "emisor (tenant)   : %s\n", r.Header.Tenant)
	fmt.Fprintf(&b, "tipo de registro  : %s\n", r.Header.Type)
	fmt.Fprintf(&b, "hash del contenido: %s\n", r.Header.PayloadHash)
	fmt.Fprintf(&b, "bloque            : %d\n", r.Header.Index)
	b.WriteString("\n")
	fmt.Fprintf(&b, "TIEMPO DECLARADO  : %s  (declarado por el sistema emisor)\n",
		declared.UTC().Format(timeLayout))
	provable, ok, err := r.ProvableTime(p)
	if err != nil {
		return nil, err
	}
	if ok {
		fmt.Fprintf(&b, "TIEMPO DEMOSTRABLE: %s  (atestiguado por testigos)\n",
			provable.UTC().Format(timeLayout))
	} else {
		fmt.Fprintf(&b, "TIEMPO DEMOSTRABLE: %s\n", NoProvableTime)
	}
	b.WriteString("\n")
	b.WriteString(LegalNotice)
	b.WriteString("\n\n")
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
func Parse(data []byte, p proof.Policy) (*Receipt, error) {
	i := bytes.Index(data, []byte(separator+"\n"))
	if i < 0 {
		return nil, fmt.Errorf("%w: falta el separador %q", ErrFormat, separator)
	}
	text, machine := data[:i], data[i+len(separator)+1:]

	recipient, err := textField(text, "destinatario      : ")
	if err != nil {
		return nil, err
	}
	// La etiqueta se quita para recuperar el nombre. Si el recibo no la trae
	// —porque viene de una versión anterior, o porque alguien la borró— el nombre
	// queda como estaba, renderText volverá a añadirla y la comparación byte a
	// byte de más abajo rechazará el recibo. Es el resultado correcto: un recibo
	// que enseña un destinatario sin decir qué es no debe pasar por bueno.
	recipient = strings.TrimSuffix(recipient, RecipientNote)

	// Un recibo v1 se reconoce y se rechaza con un mensaje que lo explique. Sin
	// esto, el error hablaría de una firma que falta o de un header ilegible, y
	// quien lo leyera buscaría el problema donde no está.
	if bytes.HasPrefix(data, []byte(MagicV1+"\n")) {
		return nil, fmt.Errorf("%w: este recibo es %s, con la regla de hoja leaf/v1; "+
			"este verificador implementa %s (leaf/v2). Ver PROTOCOL.md §2.1 y ADR-014",
			ErrFormat, MagicV1, Magic)
	}

	// El header canónico ocupa una línea: es JCS, que no lleva saltos.
	nl := bytes.IndexByte(machine, '\n')
	if nl < 0 {
		return nil, fmt.Errorf("%w: falta el header canónico", ErrFormat)
	}
	var h ledger.Header
	if err := json.Unmarshal(machine[:nl], &h); err != nil {
		return nil, fmt.Errorf("%w: header ilegible: %w", ErrFormat, err)
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

	// Tras el header, la línea de la firma del bloque.
	rest := machine[nl+1:]
	nl2 := bytes.IndexByte(rest, '\n')
	if nl2 < 0 {
		return nil, fmt.Errorf("%w: falta la firma del bloque", ErrFormat)
	}
	// Strict() y la longitud exacta, por lo mismo que en el resto del proyecto: que
	// un recibo tenga UNA sola representación en bytes es lo que permite archivarlo
	// y compararlo años después. Lo aprendimos con el fuzzer del testigo.
	blockSig, err := base64.StdEncoding.Strict().DecodeString(string(rest[:nl2]))
	if err != nil {
		return nil, fmt.Errorf("%w: la firma del bloque no es base64 válido: %w", ErrFormat, err)
	}
	if len(blockSig) != ed25519.SignatureSize {
		return nil, fmt.Errorf("%w: firma de bloque de %d bytes, se esperaban %d",
			ErrFormat, len(blockSig), ed25519.SignatureSize)
	}

	// Y tras ella, la firma del emisor. El formato la EXIGE; se lee como opcional
	// para poder dar un error propio —"no lleva firma del emisor"— en vez de que
	// proof.Parse se queje de un magic que no entiende.
	afterSig := rest[nl2+1:]
	var receiptSig []byte
	if bytes.HasPrefix(afterSig, []byte(ReceiptSigPrefix)) {
		nl3 := bytes.IndexByte(afterSig, '\n')
		if nl3 < 0 {
			return nil, fmt.Errorf("%w: la línea de la firma del emisor no termina", ErrFormat)
		}
		line := string(afterSig[:nl3])
		sp := strings.LastIndex(line, " ")
		if sp < 0 {
			return nil, fmt.Errorf("%w: la línea de la firma del emisor no trae nombre y firma", ErrFormat)
		}
		name := strings.TrimPrefix(line[:sp], ReceiptSigPrefix)
		if name != h.Tenant {
			return nil, fmt.Errorf("%w: la firma del emisor dice ser de %q y el header declara %q",
				ErrFormat, name, h.Tenant)
		}
		receiptSig, err = base64.StdEncoding.Strict().DecodeString(line[sp+1:])
		if err != nil {
			return nil, fmt.Errorf("%w: la firma del emisor no es base64 válido: %w", ErrFormat, err)
		}
		if len(receiptSig) != ed25519.SignatureSize {
			return nil, fmt.Errorf("%w: firma del emisor de %d bytes, se esperaban %d",
				ErrFormat, len(receiptSig), ed25519.SignatureSize)
		}
		afterSig = afterSig[nl3+1:]
	}

	tlogProof, err := proof.Parse(afterSig)
	if err != nil {
		return nil, err
	}
	r := &Receipt{
		Recipient: recipient, Header: h, BlockSig: blockSig,
		ReceiptSig: receiptSig, Proof: tlogProof,
	}

	want, err := renderText(r, p)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(want, text) {
		return nil, fmt.Errorf("%w:\nse leyó:\n%s\nla prueba dice:\n%s", ErrTextMismatch, text, want)
	}
	// La firma del emisor se exige aquí, en Parse, y no solo en Verify. Es lo que la
	// hace útil: si fuera opcional al leer, un recibo sin ella seguiría imprimiéndose
	// igual de bien y la protección del destinatario dependería de que alguien se
	// acordara de llamar a la otra función.
	if err := VerifyReceiptSignature(r, p); err != nil {
		return nil, err
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

// Verify comprueba la prueba con la política dada y devuelve lo que el
// destinatario puede afirmar.
//
// Ya no hace falta contrastar el encabezado con la prueba, como antes: el
// encabezado se DERIVA de esta misma verificación, en renderText, y Parse lo
// vuelve a derivar y exige igualdad byte a byte. Lo que antes eran dos fuentes
// que había que reconciliar es ahora una sola.
func (r *Receipt) Verify(p proof.Policy) (proof.Result, error) {
	// La firma del emisor sobre el recibo entero, que es la que cubre al
	// destinatario (ADR-015). Va primero porque es la más barata de comprobar y la
	// que delata el manoseo más probable: alguien que reescribe el nombre.
	//
	// Se comprueba AQUÍ y en Parse, pero NO en verify, y la diferencia no es un
	// detalle de organización: el texto legible se deriva del tiempo demostrable, el
	// tiempo demostrable sale de verify, y la firma cubre el texto. Si verify
	// exigiera la firma, firmar sería imposible — habría que verificar la firma para
	// poder calcular los bytes que hay que firmar. Lo descubrí intentándolo.
	if err := VerifyReceiptSignature(r, p); err != nil {
		return proof.Result{}, err
	}
	return r.verify(p)
}

// Text devuelve solo el encabezado legible, para imprimirlo.
func Text(data []byte) string {
	if i := bytes.Index(data, []byte(separator)); i >= 0 {
		return strings.TrimRight(string(data[:i]), "\n")
	}
	return ""
}
