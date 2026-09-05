// Package witness implementa un testigo local que cosigna checkpoints según
// c2sp.org/tlog-cosignature@v1 y se niega a cosignar un log que se contradice.
//
// Un testigo es la frontera de seguridad real del registro: el log puede
// reescribir su base de datos, pero no puede hacer que un tercero que ya
// cosignó una raíz firme otra incompatible. PROTOCOL.md §8 lo dice sin rodeos:
// los disparadores de SQLite son una barandilla, los testigos son la garantía.
package witness

import (
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/nucleoledger/nucleo/internal/checkpoint"
)

// TimestampedSignatureSize es el tamaño de la timestamped_signature de
// c2sp.org/tlog-cosignature@v1: 8 bytes de timestamp más 64 de firma Ed25519.
const TimestampedSignatureSize = 8 + ed25519.SignatureSize

// ErrCosignature indica una cosignature malformada o que no verifica.
var ErrCosignature = errors.New("witness: cosignature inválida")

// cosignedMessage arma el mensaje que realmente se firma en cosignature v1: dos
// líneas de cabecera y, a continuación, el cuerpo íntegro de la nota del
// checkpoint. No se firma el cuerpo a secas, de modo que una firma de testigo
// nunca puede confundirse con la firma del propio log.
func cosignedMessage(timestamp uint64, noteBody []byte) []byte {
	prefix := "cosignature/v1\ntime " + strconv.FormatUint(timestamp, 10) + "\n"
	msg := make([]byte, 0, len(prefix)+len(noteBody))
	msg = append(msg, prefix...)
	msg = append(msg, noteBody...)
	return msg
}

// Signer firma checkpoints como cosignature v1. Implementa note.Signer, así que
// x/mod/sumdb/note lo acepta sin modificaciones: la biblioteca aporta el
// formato de nota y este tipo aporta el contenido de la firma.
//
// SPEC-CHECK: el key ID se calcula aquí con el identificador de algoritmo 0x01
// (checkpoint.KeyHash), que es el único que fija PROTOCOL.md §3. El registro de
// algoritmos de notas firmadas de C2SP podría asignar un identificador distinto
// a las claves de cosignature/v1; de ser así cambiaría el key ID del testigo
// —no los bytes de la firma— y habría que fijarlo antes de interoperar con
// testigos de terceros.
type Signer struct {
	name string
	hash uint32
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
	now  func() time.Time

	mu       sync.Mutex
	lastTime uint64
}

// NewSigner crea el firmante de cosignatures del testigo. Si now es nil se usa
// el reloj del sistema; los tests inyectan un reloj determinista.
func NewSigner(name string, priv ed25519.PrivateKey, now func() time.Time) (*Signer, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, errors.New("witness: clave privada Ed25519 inválida")
	}
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("witness: clave privada Ed25519 inválida")
	}
	if now == nil {
		now = time.Now
	}
	return &Signer{name: name, hash: checkpoint.KeyHash(name, pub), priv: priv, pub: pub, now: now}, nil
}

// Name devuelve el nombre del testigo.
func (s *Signer) Name() string { return s.name }

// KeyHash devuelve el key ID del testigo.
func (s *Signer) KeyHash() uint32 { return s.hash }

// Sign produce la timestamped_signature de 72 bytes: el timestamp Unix en
// big-endian seguido de la firma Ed25519 del mensaje cosignado.
//
// El timestamp emitido nunca retrocede. Si lo hiciera, un verificador no podría
// tomar el mínimo de los timestamps de cosignature como tiempo demostrable de
// una entrada (ADR-002): un reloj que va hacia atrás permitiría antedatar. Ante
// un salto hacia atrás el testigo falla en vez de firmar, que es el lado seguro.
func (s *Signer) Sign(noteBody []byte) ([]byte, error) {
	t := s.now().Unix()
	if t < 0 {
		return nil, errors.New("witness: timestamp anterior a la época Unix")
	}
	timestamp := uint64(t)

	s.mu.Lock()
	defer s.mu.Unlock()
	if timestamp < s.lastTime {
		return nil, fmt.Errorf("%w: %d < %d", ErrClockRewind, timestamp, s.lastTime)
	}

	sig := ed25519.Sign(s.priv, cosignedMessage(timestamp, noteBody))
	out := make([]byte, TimestampedSignatureSize)
	binary.BigEndian.PutUint64(out[:8], timestamp)
	copy(out[8:], sig)
	s.lastTime = timestamp
	return out, nil
}

// PublicKey devuelve la clave pública del testigo.
func (s *Signer) PublicKey() ed25519.PublicKey { return s.pub }

// Verifier valida cosignatures v1. Implementa note.Verifier.
type Verifier struct {
	name string
	hash uint32
	pub  ed25519.PublicKey
}

// NewVerifier crea el verificador de cosignatures de un testigo conocido.
func NewVerifier(name string, pub ed25519.PublicKey) (*Verifier, error) {
	if len(pub) != ed25519.PublicKeySize {
		return nil, errors.New("witness: clave pública Ed25519 inválida")
	}
	return &Verifier{name: name, hash: checkpoint.KeyHash(name, pub), pub: pub}, nil
}

// Name devuelve el nombre del testigo.
func (v *Verifier) Name() string { return v.name }

// KeyHash devuelve el key ID del testigo.
func (v *Verifier) KeyHash() uint32 { return v.hash }

// Verify comprueba la timestamped_signature reconstruyendo el mensaje cosignado
// con el timestamp que viaja dentro de la propia firma.
func (v *Verifier) Verify(noteBody, sig []byte) bool {
	if len(sig) != TimestampedSignatureSize {
		return false
	}
	timestamp := binary.BigEndian.Uint64(sig[:8])
	return ed25519.Verify(v.pub, cosignedMessage(timestamp, noteBody), sig[8:])
}

// Timestamp extrae el instante declarado por una cosignature ya verificada.
//
// Es «tiempo demostrable» en el sentido de ADR-002: a diferencia del timestamp
// del bloque, que lo pone el propio tenant, este lo pone un tercero.
func Timestamp(sig []byte) (time.Time, error) {
	if len(sig) != TimestampedSignatureSize {
		return time.Time{}, ErrCosignature
	}
	return time.Unix(int64(binary.BigEndian.Uint64(sig[:8])), 0).UTC(), nil
}
