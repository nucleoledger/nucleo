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
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/nucleoledger/nucleo/internal/checkpoint"
	"github.com/nucleoledger/nucleo/internal/ledger"
	"github.com/nucleoledger/nucleo/internal/proof"
	"github.com/nucleoledger/nucleo/internal/witness"
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

// ProvableTime devuelve el menor de los timestamps de las cosignatures
// PRESENTES en la nota, y si hay alguna.
//
// No verifica firmas: dice qué afirma el documento. Que esas cosignatures sean
// de testigos en los que confías lo decide Verify con tu política, y si no
// coinciden, Verify falla.
func (r *Receipt) ProvableTime() (time.Time, bool) {
	var earliest time.Time
	var found bool
	for _, sig := range cosignatureBlobs(r.Proof.CheckpointNote) {
		ts, err := witness.Timestamp(sig)
		if err != nil {
			continue
		}
		if !found || ts.Before(earliest) {
			earliest, found = ts, true
		}
	}
	return earliest, found
}

// cosignatureBlobs devuelve los blobs de firma de la nota que tienen la FORMA de
// una tlog-cosignature@v1: 4 bytes de key ID más 72 de firma con timestamp.
func cosignatureBlobs(msg []byte) [][]byte {
	i := bytes.LastIndex(msg, []byte("\n\n"))
	if i < 0 {
		return nil
	}
	var out [][]byte
	for _, line := range strings.Split(string(msg[i+2:]), "\n") {
		if !strings.HasPrefix(line, "— ") {
			continue
		}
		j := strings.LastIndex(line, " ")
		blob, err := base64.StdEncoding.DecodeString(line[j+1:])
		if err != nil || len(blob) != 4+72 {
			continue
		}
		out = append(out, blob[4:])
	}
	return out
}
