// Package checkpoint implementa el checkpoint firmado de C2SP
// (c2sp.org/tlog-checkpoint): una nota firmada cuyo cuerpo son tres líneas
// —origin, tamaño del árbol y raíz de Merkle en base64— sobre las que el log
// pone su firma Ed25519.
//
// El formato de nota firmada no se reimplementa aquí: lo aporta
// golang.org/x/mod/sumdb/note según ADR-008. Este paquete define el cuerpo
// concreto del checkpoint, su validación y la regla de PROTOCOL.md §3 de que un
// log NUNCA firma un checkpoint inconsistente con otro que ya firmó.
package checkpoint

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/mod/sumdb/note"
)

var (
	// ErrFormat indica un cuerpo de checkpoint que no respeta el formato.
	ErrFormat = errors.New("checkpoint: formato inválido")
	// ErrRootSize indica una raíz que no mide 32 bytes.
	ErrRootSize = errors.New("checkpoint: la raíz debe medir 32 bytes")
	// ErrOrigin indica un origin vacío o con caracteres no permitidos.
	ErrOrigin = errors.New("checkpoint: origin inválido")
	// ErrRollback indica un checkpoint que retrocede respecto al último firmado.
	// Es la regla de PROTOCOL.md §3: un log no puede desdecirse.
	ErrRollback = errors.New("checkpoint: retroceso respecto al último checkpoint firmado")
)

// RootSize es el tamaño en bytes de una raíz de Merkle SHA-256.
const RootSize = sha256.Size

// Checkpoint es el cuerpo de la nota: qué log, cuántas entradas y qué raíz.
type Checkpoint struct {
	Origin   string
	Size     uint64
	RootHash []byte
}

// Validate comprueba que el checkpoint sea representable en el formato.
func (c Checkpoint) Validate() error {
	if err := validOrigin(c.Origin); err != nil {
		return err
	}
	if len(c.RootHash) != RootSize {
		return fmt.Errorf("%w: %d", ErrRootSize, len(c.RootHash))
	}
	return nil
}

// validOrigin rechaza un origin vacío o que rompería el formato de líneas. La
// nota firmada separa cuerpo y firmas por una línea en blanco, así que un origin
// con saltos de línea o espacios al borde haría ambiguo el parseo.
func validOrigin(origin string) error {
	if origin == "" || strings.ContainsAny(origin, "\n\r") || strings.TrimSpace(origin) != origin {
		return fmt.Errorf("%w: %q", ErrOrigin, origin)
	}
	return nil
}

// Format devuelve el cuerpo de la nota: origin, tamaño decimal y raíz en base64
// estándar, una por línea y con salto final. Es exactamente lo que se firma.
func Format(c Checkpoint) (string, error) {
	if err := c.Validate(); err != nil {
		return "", err
	}
	return c.Origin + "\n" +
		strconv.FormatUint(c.Size, 10) + "\n" +
		base64.StdEncoding.EncodeToString(c.RootHash) + "\n", nil
}

// Parse lee el cuerpo de un checkpoint. Es estricto a propósito: el tamaño no
// admite ceros a la izquierda ni signo, y la raíz debe venir en base64 canónico,
// porque dos codificaciones distintas del mismo checkpoint producirían firmas
// distintas y romperían la comparación entre testigos.
func Parse(text string) (Checkpoint, error) {
	if !strings.HasSuffix(text, "\n") {
		return Checkpoint{}, fmt.Errorf("%w: el cuerpo debe terminar en salto de línea", ErrFormat)
	}
	lines := strings.Split(strings.TrimSuffix(text, "\n"), "\n")

	// c2sp.org/tlog-checkpoint permite líneas adicionales tras la tercera —van
	// dentro de lo firmado— pero las marca como NOT RECOMMENDED. Decisión de
	// Núcleo: rechazarlas, fallo cerrado. Núcleo emite exactamente tres líneas
	// de cuerpo y todavía no atestigua logs ajenos, así que aceptar extensiones
	// solo añadiría superficie. Ignorarlas en silencio sería peor que fallar,
	// porque descartaría contenido firmado. Admitirlas exige un parseo que
	// preserve el cuerpo verbatim para poder reserializarlo byte a byte, y eso
	// se difiere hasta que haga falta atestiguar logs de terceros.
	if len(lines) != 3 {
		return Checkpoint{}, fmt.Errorf("%w: se esperaban 3 líneas, hay %d", ErrFormat, len(lines))
	}

	origin := lines[0]
	if err := validOrigin(origin); err != nil {
		return Checkpoint{}, err
	}

	sizeText := lines[1]
	if sizeText == "" || (len(sizeText) > 1 && sizeText[0] == '0') {
		return Checkpoint{}, fmt.Errorf("%w: tamaño no canónico %q", ErrFormat, sizeText)
	}
	size, err := strconv.ParseUint(sizeText, 10, 64)
	if err != nil {
		return Checkpoint{}, fmt.Errorf("%w: tamaño %q: %v", ErrFormat, sizeText, err)
	}

	root, err := base64.StdEncoding.Strict().DecodeString(lines[2])
	if err != nil {
		return Checkpoint{}, fmt.Errorf("%w: raíz %q: %v", ErrFormat, lines[2], err)
	}
	if len(root) != RootSize {
		return Checkpoint{}, fmt.Errorf("%w: %d", ErrRootSize, len(root))
	}
	if base64.StdEncoding.EncodeToString(root) != lines[2] {
		return Checkpoint{}, fmt.Errorf("%w: raíz en base64 no canónico", ErrFormat)
	}

	return Checkpoint{Origin: origin, Size: size, RootHash: root}, nil
}

// ParseNote extrae el checkpoint del cuerpo de una nota firmada SIN comprobar
// ninguna firma. Existe para quien necesita el tamaño o la raíz antes de tener
// las claves a mano —el almacén, al indexar un checkpoint por su tree_size—, y
// nunca debe usarse para decidir si un checkpoint es de fiar: para eso está
// Verify, que sí exige firmas válidas.
func ParseNote(msg []byte) (Checkpoint, error) {
	i := bytes.LastIndex(msg, []byte("\n\n"))
	if i < 0 {
		return Checkpoint{}, fmt.Errorf("%w: la nota no separa cuerpo y firmas", ErrFormat)
	}
	return Parse(string(msg[:i+1]))
}

// Sign firma el checkpoint como nota. Ed25519 es determinista, así que los bytes
// resultantes son reproducibles para una misma clave y checkpoint.
func Sign(c Checkpoint, signers ...note.Signer) ([]byte, error) {
	text, err := Format(c)
	if err != nil {
		return nil, err
	}
	if len(signers) == 0 {
		return nil, errors.New("checkpoint: se requiere al menos un firmante")
	}
	msg, err := note.Sign(&note.Note{Text: text}, signers...)
	if err != nil {
		return nil, fmt.Errorf("checkpoint: firma de la nota: %w", err)
	}
	return msg, nil
}

// Verify abre la nota con los verificadores dados y devuelve el checkpoint junto
// con la nota abierta, para que quien llame pueda inspeccionar las firmas.
//
// Las firmas de claves desconocidas no rompen la apertura: quedan en
// UnverifiedSigs. Pero si NINGUNA firma verifica, note.Open falla; por eso la
// política de un recibo debe incluir siempre la clave del log.
func Verify(msg []byte, verifiers ...note.Verifier) (Checkpoint, *note.Note, error) {
	n, err := note.Open(msg, note.VerifierList(verifiers...))
	if err != nil {
		return Checkpoint{}, nil, fmt.Errorf("checkpoint: apertura de la nota: %w", err)
	}
	c, err := Parse(n.Text)
	if err != nil {
		return Checkpoint{}, nil, err
	}
	return c, n, nil
}

// NewSigner construye un firmante de notas desde una clave privada Ed25519.
//
// note.NewSigner solo acepta la clave en su codificación de texto, así que se
// arma aquí a partir de la semilla: eso permite firmantes deterministas en los
// tests sin depender de note.GenerateKey ni de un lector aleatorio simulado.
func NewSigner(name string, priv ed25519.PrivateKey) (note.Signer, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, errors.New("checkpoint: clave privada Ed25519 inválida")
	}
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("checkpoint: clave privada Ed25519 inválida")
	}
	skey := fmt.Sprintf("PRIVATE+KEY+%s+%08x+%s", name, KeyHash(name, pub),
		base64.StdEncoding.EncodeToString(append([]byte{algEd25519}, priv.Seed()...)))
	s, err := note.NewSigner(skey)
	if err != nil {
		return nil, fmt.Errorf("checkpoint: firmante %q: %w", name, err)
	}
	return s, nil
}

// NewVerifier construye un verificador de notas desde una clave pública Ed25519.
func NewVerifier(name string, pub ed25519.PublicKey) (note.Verifier, error) {
	vkey, err := note.NewEd25519VerifierKey(name, pub)
	if err != nil {
		return nil, fmt.Errorf("checkpoint: verificador %q: %w", name, err)
	}
	v, err := note.NewVerifier(vkey)
	if err != nil {
		return nil, fmt.Errorf("checkpoint: verificador %q: %w", name, err)
	}
	return v, nil
}

// Identificadores de algoritmo del registro de notas firmadas de C2SP. El byte
// entra en el cálculo del key ID, así que una misma clave Ed25519 tiene un key
// ID distinto según para qué se use: eso es lo que impide que la firma de un log
// y la cosignature de un testigo se confundan aunque compartieran clave.
const (
	// AlgEd25519 identifica la firma Ed25519 del log sobre el texto de la nota.
	AlgEd25519 = 0x01
	// AlgEd25519Cosignature identifica una clave de c2sp.org/tlog-cosignature@v1.
	AlgEd25519Cosignature = 0x04
)

// algEd25519 se conserva para la codificación de clave privada de
// x/mod/sumdb/note, que solo entiende el 0x01.
const algEd25519 = AlgEd25519

// KeyHash calcula el key ID de la firma del log: los primeros 4 bytes, en
// big-endian, de SHA-256(name ‖ "\n" ‖ 0x01 ‖ pubkey).
func KeyHash(name string, pub ed25519.PublicKey) uint32 {
	return KeyHashAlg(name, pub, AlgEd25519)
}

// KeyHashAlg calcula el key ID para un identificador de algoritmo concreto:
// SHA-256(name ‖ "\n" ‖ alg ‖ pubkey), truncado a 4 bytes big-endian.
func KeyHashAlg(name string, pub ed25519.PublicKey, alg byte) uint32 {
	h := sha256.New()
	h.Write([]byte(name))
	h.Write([]byte("\n"))
	h.Write([]byte{alg})
	h.Write(pub)
	return binary.BigEndian.Uint32(h.Sum(nil))
}
