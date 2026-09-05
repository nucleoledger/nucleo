package witness

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/nucleoledger/nucleo/internal/checkpoint"
	"github.com/nucleoledger/nucleo/internal/ledger"
	"golang.org/x/mod/sumdb/note"
)

var (
	// ErrConflict indica que el checkpoint presentado no extiende al último que
	// este testigo cosignó para ese origin: la señal de que el log intentó
	// reescribir su historia. Corresponde al 409 de c2sp.org/tlog-witness.
	ErrConflict = errors.New("witness: checkpoint inconsistente con el último cosignado")
	// ErrUnknownLog indica un origin del que el testigo no conoce la clave.
	ErrUnknownLog = errors.New("witness: log desconocido")
	// ErrClockRewind indica que el reloj del testigo retrocedió.
	ErrClockRewind = errors.New("witness: el reloj retrocedió respecto a la última cosignature")
)

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

// Witness es un testigo en memoria: guarda el último checkpoint cosignado por
// origin y solo cosigna uno nuevo si se demuestra que extiende al anterior.
type Witness struct {
	mu     sync.Mutex
	signer *Signer
	logs   map[string]note.Verifier
	last   map[string]checkpoint.Checkpoint
}

// New crea un testigo con su propia identidad Ed25519. Si now es nil se usa el
// reloj del sistema; los tests inyectan un reloj determinista.
func New(name string, priv ed25519.PrivateKey, now func() time.Time) (*Witness, error) {
	s, err := NewSigner(name, priv, now)
	if err != nil {
		return nil, err
	}
	return &Witness{
		signer: s,
		logs:   make(map[string]note.Verifier),
		last:   make(map[string]checkpoint.Checkpoint),
	}, nil
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
	w.mu.Lock()
	defer w.mu.Unlock()
	c, ok := w.last[origin]
	return c, ok
}

// Cosign verifica y cosigna un checkpoint, devolviendo la nota con la
// cosignature del testigo añadida a las firmas que ya traía.
//
// consistencyProof es PROOF(lastSize, D[newSize]) y solo hace falta a partir del
// segundo checkpoint de un origin.
func (w *Witness) Cosign(msg []byte, consistencyProof [][]byte) ([]byte, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	// 1. Verificar la firma antes de creerse nada del contenido. Se prueban
	// todas las claves de log conocidas y después se exige que la firma buena
	// sea justamente la del origin que el cuerpo declara: si no, cualquier log
	// registrado podría firmar checkpoints en nombre de otro.
	c, n, err := checkpoint.Verify(msg, w.knownVerifiers()...)
	if err != nil {
		return nil, err
	}
	logVerifier, ok := w.logs[c.Origin]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrUnknownLog, c.Origin)
	}
	if !signedBy(n, logVerifier) {
		return nil, fmt.Errorf("%w: la nota de %q no está firmada por su clave", ErrUnknownLog, c.Origin)
	}

	// 2. Comprobar que extiende al último cosignado. El primero de un origin se
	// acepta por definición: el testigo no puede saber nada anterior a él.
	last, seen := w.last[c.Origin]
	if seen {
		if err := ledger.VerifyConsistency(int(last.Size), int(c.Size),
			last.RootHash, c.RootHash, consistencyProof); err != nil {
			return nil, &ConflictError{Origin: c.Origin, LastSize: last.Size, Reason: err}
		}
	}

	// 3. Persistir ANTES de responder.
	//
	// Es la regla de c2sp.org/tlog-witness. Si el testigo respondiera primero y
	// guardara después, un log malicioso podría lanzar dos peticiones a la vez,
	// quedarse con la cosignature que le conviene y lograr que el testigo olvide
	// la otra tras un reinicio, quedando como avalista de dos historias
	// incompatibles. Guardar primero solo puede dejar al testigo MÁS estricto de
	// la cuenta —con un checkpoint registrado que no llegó a cosignar—, que es
	// el lado seguro del error. Aquí el candado cubre todo el flujo; en el
	// daemon real esta escritura debe ser atómica con la comprobación anterior.
	stored := c
	stored.RootHash = bytes.Clone(c.RootHash)
	w.last[c.Origin] = stored

	// 4. Cosignar. Si la firma falla —por ejemplo, porque el reloj retrocedió—
	// se revierte el registro: el testigo no llegó a comprometerse con nada.
	cosigned, err := note.Sign(&note.Note{
		Text:           n.Text,
		Sigs:           n.Sigs,
		UnverifiedSigs: n.UnverifiedSigs,
	}, w.signer)
	if err != nil {
		if seen {
			w.last[c.Origin] = last
		} else {
			delete(w.last, c.Origin)
		}
		return nil, fmt.Errorf("witness: cosignature de %q: %w", c.Origin, err)
	}
	return cosigned, nil
}

// knownVerifiers devuelve las claves de log registradas. Se llama con el candado
// tomado.
func (w *Witness) knownVerifiers() []note.Verifier {
	out := make([]note.Verifier, 0, len(w.logs))
	for _, v := range w.logs {
		out = append(out, v)
	}
	return out
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
