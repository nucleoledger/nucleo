// Package receipt arma el recibo entregable de Núcleo: la prueba verificable de
// c2sp.org/tlog-proof envuelta en un encabezado que una persona pueda leer.
//
// Su razón de ser está en PROTOCOL.md §4 y en ADR-002: un recibo tiene que
// mostrar DOS relojes y no confundirlos nunca.
//
//   - El tiempo DECLARADO es el timestamp que el sistema emisor puso en el
//     bloque. Sale de un reloj que el propio emisor controla, así que puede
//     mentir. Se muestra porque es información útil, no porque pruebe nada.
//   - El tiempo DEMOSTRABLE es el menor de los timestamps de las cosignatures
//     de testigos. Un tercero independiente afirmó haber visto ese árbol en ese
//     momento, y eso sí acota cuándo existía el registro.
//
// Un recibo sin cosignatures no tiene tiempo demostrable, y lo dice con esas
// palabras en vez de callarse: presentar el declarado a secas sería exactamente
// la confusión que PROTOCOL.md prohíbe.
package receipt

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/nucleoledger/nucleo/internal/checkpoint"
	"github.com/nucleoledger/nucleo/internal/ledger"
	"github.com/nucleoledger/nucleo/internal/proof"
)

// Magic identifica el formato y su versión.
// El magic fija a la vez el formato del recibo y la REGLA DE HOJA con la que se
// verifica (PROTOCOL.md §3.1). Así un verificador nunca tiene que adivinar con qué
// regla recomponer la hoja: lo lee en la primera línea.
//
// v1 queda como histórica: su hoja era solo el hash del bloque y su recibo no
// llevaba la firma, así que quien lo tenía no podía comprobarla. Los recibos v1 no
// verifican con este código, y eso es deliberado — ADR-014 y PROTOCOL 0.2-draft.
const Magic = "nucleo.org/receipt@v2"

// MagicV1 es el magic histórico. Se conserva para poder RECONOCER un recibo viejo
// y dar un error que lo explique, en vez de uno que hable de un separador perdido.
const MagicV1 = "nucleo.org/receipt@v1"

// separator abre la parte de máquina.
const separator = "--- prueba verificable ---"

// NoProvableTime es lo que se imprime cuando no hay ninguna cosignature. Se
// escribe en mayúsculas y sin rodeos: es la diferencia entre "esto lo vio un
// tercero" y "esto lo dice quien lo emitió".
const NoProvableTime = "SIN TIEMPO DEMOSTRABLE"

// RecipientNote es la etiqueta que acompaña AL NOMBRE del destinatario, en su
// misma línea.
//
// El destinatario no está cubierto por ninguna firma: lo elige quien emite el
// recibo, en el momento de emitirlo, y podría poner cualquier nombre. La prueba
// demuestra que el registro existía; no demuestra a quién se le entregó.
//
// Eso hay que decirlo donde está el nombre, no en otro párrafo. El uso que la
// revisión externa anticipó —pegar el recibo en el pie de un PDF con el nombre
// del cliente— convierte ese nombre en aparente prueba de emisión a esa persona,
// y en una disputa se leerá así. Va en la MISMA línea a propósito: una etiqueta
// en la línea de abajo se separa del nombre con un copia-pega descuidado, y
// entonces vuelve el problema que pretendía resolver.
//
// La opción completa —que el emisor firme el recibo entero, destinatario
// incluido— se evalúa en ADR-015 y está sin decidir. Esta es la mínima honesta:
// no añade garantías, deja de insinuarlas.
const RecipientNote = "  (firmado por el emisor)"

// RecipientNoteUnsigned es la etiqueta ANTERIOR, la del recibo que no llevaba firma
// del emisor. Se conserva solo para reconocer un recibo viejo y explicarlo.
const RecipientNoteUnsigned = "  (anotado por el emisor, no firmado)"

// ReceiptSigPrefix abre la línea de la firma del emisor, con la misma convención que
// las líneas de firma de una nota firmada: "— <nombre> <base64>".
const ReceiptSigPrefix = "— "

// LegalNotice es la advertencia legal que viaja DENTRO del recibo.
//
// No es decoración ni cobertura de nadie: es la diferencia entre lo que este
// documento demuestra y lo que un lector va a suponer que demuestra. Núcleo
// puede afirmar que un registro existía con unos bytes concretos en un momento
// acotado por terceros. No puede afirmar que lo registrado sea cierto, ni que
// tenga el efecto de un acto público, y un recibo impreso con sello de aspecto
// técnico invita precisamente a esa lectura.
//
// Va en el texto legible, y por tanto queda cubierta por la igualdad byte a
// byte que exige Parse: un recibo al que le quiten la advertencia deja de
// verificar. Eso es deliberado. Si fuera un pie de página que se puede borrar
// con un editor, el primer uso comercial lo borraría.
//
// Redacción fijada con el dev. Cambiarla cambia los bytes del recibo y por tanto
// los vectores golden y el verificador de TypeScript: no se retoca a la ligera.
const LegalNotice = "ADVERTENCIA LEGAL\n" +
	"Este recibo es evidencia técnica de integridad y tiempo. No constituye por sí\n" +
	"mismo un acto público, una certificación notarial ni un pronunciamiento de\n" +
	"autoridad. Su valor probatorio lo determina un perito o un juez."

var (
	// ErrFormat indica un recibo malformado.
	ErrFormat = errors.New("receipt: recibo malformado")
	// ErrNotAttested indica que la entrada no está cubierta por ningún
	// checkpoint guardado todavía.
	ErrNotAttested = errors.New("receipt: la entrada aún no está cubierta por un checkpoint")
	// ErrTextMismatch indica que el texto legible no coincide con lo que dice la
	// prueba. Es el rechazo más importante de este paquete: un recibo cuyo texto
	// visible contradiga sus bytes verificables sería un documento engañoso.
	ErrTextMismatch = errors.New("receipt: el texto del recibo no coincide con la prueba")
	// ErrBlockSignature indica que la firma del bloque no verifica contra la clave
	// que el propio header declara.
	ErrBlockSignature = errors.New("receipt: la firma del bloque no verifica con signer_pubkey")
	// ErrReceiptSignature indica que la firma del emisor sobre el recibo completo no
	// verifica. Es el rechazo que protege al destinatario: sin él, la línea del
	// destinatario la puede reescribir cualquiera que tenga el fichero.
	ErrReceiptSignature = errors.New("receipt: la firma del emisor sobre el recibo no verifica")
	// ErrUnexpectedSigner indica que el bloque lo firmó una clave distinta de la
	// que la política espera. Las firmas pueden ser perfectas y aun así el
	// documento no ser del emisor que la contraparte cree (ADR-017).
	ErrUnexpectedSigner = errors.New("receipt: el bloque no está firmado por la clave del emisor que fija la política")
	// ErrNoReceiptSignature indica un recibo sin firma del emisor. El formato la
	// exige: un recibo sin ella es de una versión anterior.
	ErrNoReceiptSignature = errors.New("receipt: el recibo no lleva firma del emisor")
)

// Ledger es lo que hace falta del ledger para emitir un recibo. Lo cumple
// *store.Store sin adaptador.
type Ledger interface {
	Blocks(from, to uint64) ([]*ledger.Block, error)
	LeafData() ([][]byte, error)
	LastCheckpoint() ([]byte, error)
}

// Receipt es el paquete entregable.
type Receipt struct {
	// Recipient es a quién se entrega.
	//
	// NO está cubierto por ninguna firma, y no puede estarlo: se elige al emitir
	// el recibo, mucho después de sellar el bloque. Quien reciba un recibo puede
	// cambiar este nombre y la prueba seguirá verificando. Lo que el recibo
	// demuestra —que este contenido estaba en el log en ese momento— no depende
	// del destinatario; el nombre es dirección, no prueba, y presentarlo como
	// prueba sería falso.
	Recipient string
	// Header es el header del bloque en su forma canónica JCS, tal cual se
	// firmó. Va entero porque es lo que permite al destinatario recomputar el
	// hash de la hoja y comprobar que el payload_hash que él calcula sobre su
	// documento es el que está sellado.
	Header ledger.Header
	// BlockSig es la firma Ed25519 del bloque, 64 bytes crudos.
	//
	// Viaja en el recibo porque leaf/v2 la necesita: sin ella el destinatario no
	// puede recomponer leaf_data y por tanto no puede verificar la inclusión. Y al
	// viajar, gana algo que con leaf/v1 no tenía: puede comprobar la firma contra
	// signer_pubkey. Antes veía la clave en el header y no tenía nada con lo que
	// contrastarla.
	BlockSig []byte
	// Proof es la prueba de c2sp.org/tlog-proof.
	Proof proof.Receipt
	// ReceiptSig es la firma del emisor sobre el recibo ENTERO, destinatario
	// incluido: 64 bytes crudos (ADR-015, PROTOCOL.md §3.1).
	//
	// La clave es la MISMA que firma los bloques, y ahí está el truco que hace que
	// esto no necesite ninguna PKI nueva: su pública viaja en el header como
	// signer_pubkey, y desde leaf/v2 el header entra en la hoja, así que una raíz
	// cosignada por testigos la clava. La contraparte verifica esta firma con lo que
	// ya tiene en el recibo y en su política, sin preguntarle a nadie.
	//
	// Lo que añade: el destinatario deja de ser una línea que cualquiera con el
	// fichero puede reescribir. Lo que NO añade: nada impide al emisor emitir dos
	// recibos del mismo registro a dos destinatarios distintos, ni demuestra entrega.
	ReceiptSig []byte
}

// Issue arma el recibo del bloque indicado contra el último checkpoint guardado, y
// lo FIRMA con la clave del emisor.
//
// Firma aquí y no en un paso aparte porque el formato exige la firma (ADR-015): un
// Issue que devolviera recibos sin firmar dejaría que alguien se olvidara del
// segundo paso y emitiera documentos que ningún verificador acepta. Es imposible
// construir un recibo incompleto por descuido.
//
// Necesita la política porque el texto legible depende de ella —el tiempo demostrable
// solo existe respecto a unos testigos— y la firma cubre el texto. Una consecuencia
// que conviene tener clara: el emisor firma el recibo tal como se renderiza bajo SU
// política. Si la contraparte usa otra, el recibo ya se rechazaba antes por el texto;
// ahora además no verificaría la firma. Es la misma restricción, no una nueva.
func Issue(l Ledger, recipient string, index uint64, p proof.Policy, priv ed25519.PrivateKey) (*Receipt, error) {
	if recipient == "" {
		return nil, fmt.Errorf("%w: falta el destinatario", ErrFormat)
	}
	// Un nombre que contenga la etiqueta produciría una línea con la etiqueta dos
	// veces. No rompe nada verificable —el round-trip cuadra y el nombre se
	// recupera intacto— pero deja un papel ambiguo, y la ambigüedad en la línea
	// del destinatario es justo lo que la etiqueta viene a quitar. Se rechaza al
	// emitir: más vale no poder crear el problema que detectarlo después.
	for _, prohibida := range []string{RecipientNote, RecipientNoteUnsigned} {
		if strings.Contains(recipient, strings.TrimSpace(prohibida)) {
			return nil, fmt.Errorf("%w: el destinatario no puede contener %q",
				ErrFormat, strings.TrimSpace(prohibida))
		}
	}
	noteBytes, err := l.LastCheckpoint()
	if err != nil {
		return nil, err
	}
	c, err := checkpoint.ParseNote(noteBytes)
	if err != nil {
		return nil, err
	}
	if index >= c.Size {
		return nil, fmt.Errorf("%w: bloque %d, el checkpoint cubre %d", ErrNotAttested, index, c.Size)
	}

	blocks, err := l.Blocks(index, index+1)
	if err != nil {
		return nil, err
	}
	if len(blocks) != 1 {
		return nil, fmt.Errorf("%w: no hay bloque %d", ErrFormat, index)
	}

	leaves, err := l.LeafData()
	if err != nil {
		return nil, err
	}
	path, err := ledger.InclusionProof(leaves[:c.Size], int(index))
	if err != nil {
		return nil, err
	}
	sig, err := hex.DecodeString(blocks[0].Signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return nil, fmt.Errorf("%w: la firma del bloque %d no es una firma Ed25519", ErrFormat, index)
	}
	r := &Receipt{
		Recipient: recipient,
		Header:    blocks[0].Header,
		BlockSig:  sig,
		Proof: proof.Receipt{
			Index:          index,
			InclusionProof: path,
			CheckpointNote: noteBytes,
		},
	}
	if err := Sign(r, p, priv); err != nil {
		return nil, err
	}
	return r, nil
}

// LeafData recompone leaf_data desde el header y la firma que el recibo trae
// (PROTOCOL.md §2.1, leaf/v2). Es lo que el destinatario mete en la prueba de
// inclusión, y por eso el header viaja entero y la firma con él.
//
// Se llamaba EntryHash y devolvía el digest del header. El nombre era engañoso ya
// entonces —lo que hace falta para verificar la inclusión son los datos de la hoja,
// no su hash— y con leaf/v2 habría sido falso.
func (r *Receipt) LeafData() ([]byte, error) {
	digest, err := r.Header.Digest()
	if err != nil {
		return nil, err
	}
	return ledger.LeafData(digest, r.BlockSig)
}

// VerifyBlockSignature comprueba la firma del bloque contra la clave pública que
// declara el header.
//
// Es la ruta que un recibo v1 no daba: llevaba signer_pubkey y no llevaba la firma,
// así que la contraparte veía de quién decía ser y no podía comprobarlo.
//
// No sustituye a la prueba de inclusión ni al contrario. La inclusión demuestra que
// el log se comprometió con estos bytes; la firma demuestra que la clave del emisor
// los firmó. Una raíz cosignada dice qué publicó el log; una firma dice quién lo
// escribió.
func (r *Receipt) VerifyBlockSignature() error {
	pub, err := hex.DecodeString(r.Header.SignerPubKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: signer_pubkey no es una clave Ed25519", ErrFormat)
	}
	if len(r.BlockSig) != ed25519.SignatureSize {
		return fmt.Errorf("%w: firma de bloque de %d bytes", ErrFormat, len(r.BlockSig))
	}
	digest, err := r.Header.Digest()
	if err != nil {
		return err
	}
	if !ed25519.Verify(pub, digest, r.BlockSig) {
		return ErrBlockSignature
	}
	return nil
}

// DeclaredTime devuelve el timestamp que el emisor puso en el bloque.
func (r *Receipt) DeclaredTime() (time.Time, error) { return r.Header.Time() }

// ProvableTime devuelve el tiempo demostrable del recibo BAJO UNA POLÍTICA: el
// menor de los timestamps de las cosignatures que verifican con las claves de
// testigo que esa política acepta.
//
// Exige la política porque sin ella la pregunta no tiene respuesta. Antes se
// calculaba por la FORMA del blob de firma —72 bytes con pinta de
// tlog-cosignature@v1— y eso convertía en tiempo demostrable cualquier cosa que
// alguien hubiera pegado al final de la nota. Un recibo es un documento que se
// enseña: la fecha que muestra tiene que estar respaldada por una firma que
// verifique, o no mostrarse.
//
// No se conserva ninguna variante "por forma", ni siquiera para depurar. Una
// función que devuelve una fecha con aspecto de demostrada sin haberla
// verificado es un arma cargada esperando a que alguien la imprima.
func (r *Receipt) ProvableTime(p proof.Policy) (time.Time, bool, error) {
	res, err := r.verify(p)
	if err != nil {
		return time.Time{}, false, err
	}
	if len(res.Cosigners) == 0 {
		return time.Time{}, false, nil
	}
	return res.ProvableTime, true, nil
}

// verify es la verificación compartida por el renderizado y por Verify. Que el
// encabezado se derive de lo MISMO que verifica el destinatario es lo que impide
// que el texto y la prueba lleguen a contradecirse.
//
// NO comprueba la firma del emisor, y eso es deliberado: el texto se deriva del
// tiempo demostrable, el tiempo demostrable sale de aquí, y la firma del emisor
// cubre el texto. Exigirla aquí haría imposible firmar. La comprueban Verify y
// Parse, que son las dos puertas por las que entra un recibo ajeno.
func (r *Receipt) verify(p proof.Policy) (proof.Result, error) {
	// IDENTIDAD del firmante, contra la política y no contra el recibo (ADR-017).
	// Va antes que todo lo demás porque es la pregunta que la contraparte hace en
	// realidad: ¿es de quien creo que es? Una firma válida de otra clave no la
	// responde.
	if err := p.RequireSignerKey(); err != nil {
		return proof.Result{}, err
	}
	if hex.EncodeToString(p.SignerKey) != r.Header.SignerPubKey {
		return proof.Result{}, fmt.Errorf("%w: el header declara %s y la política espera %s",
			ErrUnexpectedSigner, r.Header.SignerPubKey[:16], hex.EncodeToString(p.SignerKey)[:16])
	}
	// La firma del bloque se comprueba ANTES de la prueba de inclusión. El orden
	// no cambia el veredicto, pero sí el mensaje de error que alguien va a leer:
	// "la firma del emisor no verifica" dice qué pasa; "la entrada no está
	// incluida" mandaría a mirar el árbol cuando el problema es la firma.
	if err := r.VerifyBlockSignature(); err != nil {
		return proof.Result{}, err
	}
	leafData, err := r.LeafData()
	if err != nil {
		return proof.Result{}, err
	}
	return r.Proof.Verify(leafData, p)
}
