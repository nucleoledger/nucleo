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
	"errors"
	"fmt"
	"time"

	"github.com/nucleoledger/nucleo/internal/checkpoint"
	"github.com/nucleoledger/nucleo/internal/ledger"
	"github.com/nucleoledger/nucleo/internal/proof"
)

// Magic identifica el formato y su versión.
const Magic = "nucleo.org/receipt@v1"

// separator abre la parte de máquina.
const separator = "--- prueba verificable ---"

// NoProvableTime es lo que se imprime cuando no hay ninguna cosignature. Se
// escribe en mayúsculas y sin rodeos: es la diferencia entre "esto lo vio un
// tercero" y "esto lo dice quien lo emitió".
const NoProvableTime = "SIN TIEMPO DEMOSTRABLE"

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
)

// Ledger es lo que hace falta del ledger para emitir un recibo. Lo cumple
// *store.Store sin adaptador.
type Ledger interface {
	Blocks(from, to uint64) ([]*ledger.Block, error)
	LeafHashes() ([][]byte, error)
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
	// Proof es la prueba de c2sp.org/tlog-proof.
	Proof proof.Receipt
}

// Issue arma el recibo del bloque indicado contra el último checkpoint guardado.
func Issue(l Ledger, recipient string, index uint64) (*Receipt, error) {
	if recipient == "" {
		return nil, fmt.Errorf("%w: falta el destinatario", ErrFormat)
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

	leaves, err := l.LeafHashes()
	if err != nil {
		return nil, err
	}
	path, err := ledger.InclusionProof(leaves[:c.Size], int(index))
	if err != nil {
		return nil, err
	}
	return &Receipt{
		Recipient: recipient,
		Header:    blocks[0].Header,
		Proof: proof.Receipt{
			Index:          index,
			InclusionProof: path,
			CheckpointNote: noteBytes,
		},
	}, nil
}

// EntryHash recompone el hash de la hoja desde el header. Es lo que el
// destinatario verifica, y por eso el header viaja entero en el recibo.
func (r *Receipt) EntryHash() ([]byte, error) { return r.Header.Digest() }

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

// verify es la verificación completa, compartida por el renderizado y por
// Verify. Que el encabezado se derive de lo MISMO que verifica el destinatario
// es lo que impide que el texto y la prueba lleguen a contradecirse.
func (r *Receipt) verify(p proof.Policy) (proof.Result, error) {
	entryHash, err := r.EntryHash()
	if err != nil {
		return proof.Result{}, err
	}
	return r.Proof.Verify(entryHash, p)
}
