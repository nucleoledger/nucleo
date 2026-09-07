package witness

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/nucleoledger/nucleo/internal/checkpoint"
	"github.com/nucleoledger/nucleo/internal/ledger"
	"golang.org/x/mod/sumdb/note"
)

var (
	// ErrConflict indica que el tamaño anterior declarado por el cliente no es
	// el del último checkpoint que este testigo cosignó para ese origin.
	//
	// Corresponde al 409 de c2sp.org/tlog-witness, y a NADA MÁS: el spec reserva
	// ese código a esta única causa, y su cuerpo es el tamaño verdadero para que
	// un log honesto que perdió el hilo pueda reintentar. Una prueba que no
	// verifica o una raíz que no cuadra son 422, no 409: ahí el tamaño declarado
	// era correcto y devolverlo no ayudaría a nadie.
	ErrConflict = errors.New("witness: el tamaño anterior no es el último cosignado")
	// ErrUnknownLog indica un origin del que el testigo no conoce la clave.
	ErrUnknownLog = errors.New("witness: log desconocido")
	// ErrClockRewind indica que el reloj del testigo retrocedió.
	ErrClockRewind = errors.New("witness: el reloj retrocedió respecto a la última cosignature")
	// ErrBadSignature indica una nota sin ninguna firma válida de la clave que
	// el testigo conoce para ese origin. Corresponde al 403 del spec.
	ErrBadSignature = errors.New("witness: el checkpoint no está firmado por la clave del log")
	// ErrOldSize indica un tamaño anterior mayor que el del checkpoint.
	// Corresponde al 400 del spec.
	ErrOldSize = errors.New("witness: el tamaño anterior supera al del checkpoint")
	// ErrUnprocessable indica un checkpoint que no se puede procesar: prueba de
	// consistencia que no verifica, prueba no vacía con tamaño anterior cero,
	// raíces distintas con el mismo tamaño, o árbol vacío con raíz que no es la
	// de la cadena vacía. Corresponde al 422 del spec.
	ErrUnprocessable = errors.New("witness: checkpoint no procesable")
)

// emptyTreeRoot es la raíz del árbol vacío: SHA-256 de la cadena vacía
// (RFC 6962 §2.1). Valor comprobado fuera del código, con sha256sum.
var emptyTreeRoot = mustHex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

// ConflictError acompaña al rechazo con el tamaño del último checkpoint
// cosignado, que es lo que c2sp.org/tlog-witness devuelve en un 409 para que un
// log honesto pueda construir la prueba de consistencia correcta y reintentar.
type ConflictError struct {
	Origin   string
	LastSize uint64
	Reason   error
}

func (e *ConflictError) Error() string {
	return fmt.Sprintf("%v: origin %q, último tamaño cosignado %d: %v",
		ErrConflict, e.Origin, e.LastSize, e.Reason)
}

// Is permite compararlo con ErrConflict mediante errors.Is.
func (e *ConflictError) Is(target error) bool { return target == ErrConflict }

// Unwrap expone la causa concreta, normalmente el fallo de la prueba.
func (e *ConflictError) Unwrap() error { return e.Reason }

// Witness es un testigo: recuerda el último checkpoint cosignado por origin y
// solo cosigna uno nuevo si se demuestra que extiende al anterior.
//
// El recuerdo vive en un State, que es lo que hace que su palabra valga algo. Un
// testigo que olvida lo que avaló no sirve de nada, y olvidarlo es justo lo que
// un log malicioso necesita que le pase.
type Witness struct {
	mu     sync.Mutex
	signer *Signer
	logs   map[string]note.Verifier
	state  State
}

// New crea un testigo con memoria en RAM. Si now es nil se usa el reloj del
// sistema; los tests inyectan un reloj determinista.
func New(name string, priv ed25519.PrivateKey, now func() time.Time) (*Witness, error) {
	return NewWithState(name, priv, now, NewMemState())
}

// NewWithState crea un testigo con la memoria que se le dé. Un testigo real usa
// PersistentState: su recuerdo tiene que sobrevivir a un reinicio.
func NewWithState(name string, priv ed25519.PrivateKey, now func() time.Time, st State) (*Witness, error) {
	s, err := NewSigner(name, priv, now)
	if err != nil {
		return nil, err
	}
	if st == nil {
		return nil, errors.New("witness: se requiere un State")
	}
	return &Witness{signer: s, logs: make(map[string]note.Verifier), state: st}, nil
}

// Name devuelve el nombre del testigo.
func (w *Witness) Name() string { return w.signer.Name() }

// Verifier devuelve el verificador público del testigo, para que un tercero
// compruebe sus cosignatures sin conocer la clave privada.
func (w *Witness) Verifier() *Verifier {
	v, err := NewVerifier(w.signer.Name(), w.signer.PublicKey())
	if err != nil {
		panic(err) // imposible: la clave se validó al construir el firmante
	}
	return v
}

// AddLog registra la clave pública con la que el testigo verificará los
// checkpoints de un origin.
func (w *Witness) AddLog(origin string, pub ed25519.PublicKey) error {
	v, err := checkpoint.NewVerifier(origin, pub)
	if err != nil {
		return err
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.logs[origin] = v
	return nil
}

// Last devuelve el último checkpoint cosignado para un origin.
func (w *Witness) Last(origin string) (checkpoint.Checkpoint, bool) {
	raw, err := w.state.Latest(origin)
	if err != nil {
		return checkpoint.Checkpoint{}, false
	}
	c, err := checkpoint.ParseNote(raw)
	if err != nil {
		return checkpoint.Checkpoint{}, false
	}
	return c, true
}

// LastNote devuelve la nota VERBATIM del último checkpoint cosignado para un
// origin, que es lo que el endpoint de monitorización tiene que servir.
func (w *Witness) LastNote(origin string) ([]byte, error) { return w.state.Latest(origin) }

// State devuelve la memoria del testigo, para cerrarla.
func (w *Witness) State() State { return w.state }

// Cosign verifica y cosigna un checkpoint sin que el cliente declare el tamaño
// anterior: el testigo usa el que él recuerda. Es la vía de conveniencia para
// demos y pruebas; el protocolo HTTP usa CosignAt.
func (w *Witness) Cosign(msg []byte, consistencyProof [][]byte) ([]byte, error) {
	return w.cosign(nil, msg, consistencyProof)
}

// CosignAt es la vía del protocolo c2sp.org/tlog-witness: el cliente declara el
// tamaño del último checkpoint que cree cosignado, y el testigo exige que
// coincida con el que recuerda. Si no coincide devuelve *ConflictError, que el
// servidor traduce en el 409 con el tamaño verdadero.
//
// Esa comparación es más que higiene: es lo que impide que un log que perdió el
// hilo —o que lo perdió a propósito— consiga una cosignature sobre una historia
// que el testigo no puede encadenar con lo que ya avaló.
func (w *Witness) CosignAt(oldSize uint64, msg []byte, consistencyProof [][]byte) ([]byte, error) {
	return w.cosign(&oldSize, msg, consistencyProof)
}

// cosign es el flujo común. declaredOld nil significa "usa el tuyo".
func (w *Witness) cosign(declaredOld *uint64, msg []byte, consistencyProof [][]byte) ([]byte, error) {
	// 1. Resolver el origin ANTES de verificar firma alguna.
	//
	// Es lo que exige el protocolo: hay que saber de qué log se habla para
	// elegir la clave con la que verificar, y para poder responder 404 a un
	// origin desconocido en vez de un 403 indistinguible. No debilita nada. El
	// origin sin verificar solo SELECCIONA la clave; acto seguido se exige que
	// la nota esté firmada por ella. Un origin falso selecciona una clave que
	// no firmó nada y la verificación se cae.
	declared, err := checkpoint.ParseNote(msg)
	if err != nil {
		return nil, err
	}
	w.mu.Lock()
	logVerifier, known := w.logs[declared.Origin]
	w.mu.Unlock()
	if !known {
		return nil, fmt.Errorf("%w: %q", ErrUnknownLog, declared.Origin)
	}

	// 2. Verificar la firma del log con ESA clave, y solo con ella.
	c, n, err := checkpoint.Verify(msg, logVerifier)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrBadSignature, err)
	}
	if !signedBy(n, logVerifier) || c.Origin != declared.Origin {
		return nil, fmt.Errorf("%w: la nota de %q no está firmada por su clave", ErrBadSignature, declared.Origin)
	}

	// 3. El tamaño anterior declarado no puede superar al del checkpoint.
	//
	// Va ANTES de comparar con lo que el testigo recuerda porque el spec lo
	// presenta antes: es una comprobación sobre la petición en sí, que no
	// necesita mirar el estado, y su código es 400 —petición mal formada— no
	// 409. Invertir el orden convertiría una petición absurda en un conflicto,
	// y el cliente recibiría un tamaño que no le sirve de nada.
	if declaredOld != nil && *declaredOld > c.Size {
		return nil, fmt.Errorf("%w: anterior %d, checkpoint %d", ErrOldSize, *declaredOld, c.Size)
	}

	// 4. Comprobar y persistir ATÓMICAMENTE, y firmar dentro de la misma
	// transacción. Es el requisito de c2sp.org/tlog-witness: si la comprobación
	// del tamaño anterior y la escritura del nuevo ocurrieran por separado, dos
	// peticiones simultáneas podrían dejar al testigo avalando una historia más
	// corta que otra que ya avaló. Y si la firma falla, la transacción se
	// deshace: el testigo no queda comprometido con lo que no llegó a firmar.
	var cosigned []byte
	err = w.state.Advance(declared.Origin, func(current []byte) ([]byte, error) {
		var last checkpoint.Checkpoint
		var seen bool
		if current != nil {
			parsed, err := checkpoint.ParseNote(current)
			if err != nil {
				return nil, fmt.Errorf("witness: memoria corrupta para %q: %w", declared.Origin, err)
			}
			last, seen = parsed, true
		}

		old := last.Size // 0 si nunca cosignó, que es lo que dice el spec
		if declaredOld != nil {
			if *declaredOld != old {
				return nil, &ConflictError{
					Origin: declared.Origin, LastSize: old,
					Reason: fmt.Errorf("el cliente declaró %d", *declaredOld),
				}
			}
		}

		if err := checkExtension(old, seen, last, c, consistencyProof); err != nil {
			return nil, err
		}

		signed, err := note.Sign(&note.Note{
			Text:           n.Text,
			Sigs:           n.Sigs,
			UnverifiedSigs: n.UnverifiedSigs,
		}, w.signer)
		if err != nil {
			return nil, fmt.Errorf("witness: cosignature de %q: %w", declared.Origin, err)
		}
		cosigned = signed
		return signed, nil
	})
	if err != nil {
		return nil, err
	}
	return cosigned, nil
}

// checkExtension aplica, en el orden del spec, todo lo que separa un checkpoint
// aceptable de un 422.
func checkExtension(old uint64, seen bool, last, c checkpoint.Checkpoint, proof [][]byte) error {
	if old > c.Size {
		return fmt.Errorf("%w: anterior %d, checkpoint %d", ErrOldSize, old, c.Size)
	}
	// Un checkpoint de tamaño cero SOLO puede llevar la raíz del árbol vacío.
	if c.Size == 0 && !bytes.Equal(c.RootHash, emptyTreeRoot) {
		return fmt.Errorf("%w: tamaño 0 con una raíz que no es la del árbol vacío", ErrUnprocessable)
	}
	// Sin historia previa no hay nada que demostrar: el árbol vacío es
	// consistente con cualquier árbol, así que la prueba DEBE venir vacía.
	if old == 0 {
		if len(proof) != 0 {
			return fmt.Errorf("%w: prueba de %d nodos con tamaño anterior 0", ErrUnprocessable, len(proof))
		}
		return nil
	}
	// Mismo tamaño: no se demuestra extensión, se exige identidad de raíces.
	if old == c.Size {
		if !bytes.Equal(last.RootHash, c.RootHash) {
			return fmt.Errorf("%w: mismo tamaño %d con raíz distinta", ErrUnprocessable, old)
		}
		return nil
	}
	if !seen {
		return fmt.Errorf("%w: tamaño anterior %d sin checkpoint recordado", ErrUnprocessable, old)
	}
	// Una prueba de consistencia que no verifica es 422, no 409.
	//
	// El spec no deja margen: «If the proof is not empty when the old size is
	// zero, or if a Merkle Consistency Proof doesn't verify, the witness MUST
	// respond with a "422 Unprocessable Entity" HTTP status code.» El 409 está
	// reservado a UNA sola causa —que el tamaño anterior declarado no sea el
	// último que el testigo cosignó— y su cuerpo es ese tamaño, que es
	// justamente lo que aquí no hay que devolver: el cliente declaró el tamaño
	// correcto, lo que falla es su prueba.
	if err := ledger.VerifyConsistency(int(old), int(c.Size), last.RootHash, c.RootHash, proof); err != nil {
		return fmt.Errorf("%w: la prueba de consistencia de %d a %d no verifica: %w",
			ErrUnprocessable, old, c.Size, err)
	}
	return nil
}

// signedBy indica si la nota trae una firma verificada de ese verificador.
func signedBy(n *note.Note, v note.Verifier) bool {
	for _, sig := range n.Sigs {
		if sig.Name == v.Name() && sig.Hash == v.KeyHash() {
			return true
		}
	}
	return false
}

// originByHash busca el origin cuyo SHA-256 en hex coincide con el dado. Lo usa
// la ruta de monitorización, que el spec direcciona por hash del origin.
func (w *Witness) originByHash(hash string) (string, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	for origin := range w.logs {
		if OriginHash(origin) == hash {
			return origin, true
		}
	}
	return "", false
}
