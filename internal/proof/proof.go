// Package proof implementa el recibo de Núcleo: un artefacto autocontenido, al
// estilo de c2sp.org/tlog-proof, que demuestra que una entrada concreta está en
// un log atestiguado.
//
// La propiedad que lo define es que se verifica SIN acceso al ledger. Quien
// recibe el recibo solo necesita el hash de su entrada y una política —qué log,
// con qué clave, qué testigos y cuántos exige—. No hace falta la cadena, ni el
// árbol, ni conexión con el emisor. Eso es lo que convierte al recibo en prueba
// entregable a un tercero.
package proof

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/nucleoledger/nucleo/internal/checkpoint"
	"github.com/nucleoledger/nucleo/internal/ledger"
	"github.com/nucleoledger/nucleo/internal/witness"
	"golang.org/x/mod/sumdb/note"
)

// Magic es la primera línea del recibo, que identifica formato y versión.
const Magic = "c2sp.org/tlog-proof@v1"

var (
	// ErrFormat indica un recibo malformado.
	ErrFormat = errors.New("proof: recibo malformado")
	// ErrPolicy indica una política incompleta o incoherente.
	ErrPolicy = errors.New("proof: política inválida")
	// ErrOrigin indica que el recibo es de otro log.
	ErrOrigin = errors.New("proof: el recibo no pertenece al log de la política")
	// ErrQuorum indica que no se alcanzó el número de testigos exigido.
	ErrQuorum = errors.New("proof: quórum de testigos no alcanzado")
	// ErrInclusion indica que la entrada no está en el árbol del checkpoint.
	ErrInclusion = errors.New("proof: la entrada no está incluida en el checkpoint")
	// ErrIndex indica un índice incoherente con el tamaño del checkpoint.
	ErrIndex = errors.New("proof: índice fuera del árbol del checkpoint")
)

// Receipt es el recibo serializable: el índice de la entrada, su camino de
// inclusión y la nota del checkpoint tal cual, con todas sus cosignatures.
type Receipt struct {
	Index          uint64
	InclusionProof [][]byte
	CheckpointNote []byte
}

// Policy es lo que el verificador debe conocer de antemano. Sin ella un recibo
// solo demuestra consistencia interna; con ella demuestra pertenencia a un log
// concreto avalado por terceros concretos.
type Policy struct {
	// Origin es el identificador del log que se espera.
	Origin string
	// LogKey es la clave pública del log. Debe estar siempre: si no se conoce
	// ninguna clave que verifique, la nota ni siquiera se puede abrir.
	LogKey ed25519.PublicKey
	// Witnesses son los testigos aceptados, por nombre.
	Witnesses map[string]ed25519.PublicKey
	// Quorum es el número mínimo de cosignatures de testigos distintos.
	Quorum int
}

// Result es lo que el verificador puede afirmar tras validar el recibo.
type Result struct {
	Checkpoint checkpoint.Checkpoint
	// Cosigners son los testigos cuya cosignature verificó, en orden de aparición.
	Cosigners []string
	// ProvableTime es el menor de los timestamps de esas cosignatures: el tiempo
	// demostrable de ADR-002, opuesto al declarado por el propio tenant.
	ProvableTime time.Time
	// IgnoredSigs son las firmas de claves ajenas a la política, que no
	// invalidan el recibo: es la regla de las notas firmadas.
	IgnoredSigs []string
}

// Format serializa el recibo. El separador es la primera línea en blanco: todo
// lo que va después es la nota del checkpoint literal, que a su vez contiene su
// propia línea en blanco entre cuerpo y firmas.
func Format(r Receipt) ([]byte, error) {
	if len(r.CheckpointNote) == 0 {
		return nil, fmt.Errorf("%w: falta la nota del checkpoint", ErrFormat)
	}
	if !bytes.HasSuffix(r.CheckpointNote, []byte("\n")) {
		return nil, fmt.Errorf("%w: la nota debe terminar en salto de línea", ErrFormat)
	}
	var b strings.Builder
	b.WriteString(Magic)
	b.WriteString("\n")
	b.WriteString(strconv.FormatUint(r.Index, 10))
	b.WriteString("\n")
	for _, node := range r.InclusionProof {
		if len(node) != checkpoint.RootSize {
			return nil, fmt.Errorf("%w: nodo de %d bytes, se esperaban %d", ErrFormat, len(node), checkpoint.RootSize)
		}
		b.WriteString(base64.StdEncoding.EncodeToString(node))
		b.WriteString("\n")
	}
	b.WriteString("\n")
	return append([]byte(b.String()), r.CheckpointNote...), nil
}

// Parse lee un recibo. Es estricto con el encabezado y con la codificación de
// los nodos, porque dos recibos con los mismos datos deben tener los mismos
// bytes: es lo que permite compararlos y firmarlos aguas arriba.
func Parse(data []byte) (Receipt, error) {
	rest, ok := cutPrefixLine(data, Magic)
	if !ok {
		return Receipt{}, fmt.Errorf("%w: se esperaba %q en la primera línea", ErrFormat, Magic)
	}

	indexLine, rest, ok := cutLine(rest)
	if !ok {
		return Receipt{}, fmt.Errorf("%w: falta la línea del índice", ErrFormat)
	}
	if indexLine == "" || (len(indexLine) > 1 && indexLine[0] == '0') {
		return Receipt{}, fmt.Errorf("%w: índice no canónico %q", ErrFormat, indexLine)
	}
	index, err := strconv.ParseUint(indexLine, 10, 64)
	if err != nil {
		return Receipt{}, fmt.Errorf("%w: índice %q: %w", ErrFormat, indexLine, err)
	}

	var nodes [][]byte
	for {
		line, next, ok := cutLine(rest)
		if !ok {
			return Receipt{}, fmt.Errorf("%w: falta la línea en blanco que separa el checkpoint", ErrFormat)
		}
		rest = next
		if line == "" {
			break
		}
		node, err := base64.StdEncoding.Strict().DecodeString(line)
		if err != nil {
			return Receipt{}, fmt.Errorf("%w: nodo %q: %w", ErrFormat, line, err)
		}
		if len(node) != checkpoint.RootSize {
			return Receipt{}, fmt.Errorf("%w: nodo de %d bytes, se esperaban %d", ErrFormat, len(node), checkpoint.RootSize)
		}
		nodes = append(nodes, node)
	}

	if len(rest) == 0 {
		return Receipt{}, fmt.Errorf("%w: falta la nota del checkpoint", ErrFormat)
	}
	// Simétrico a Format: una nota sin salto final está truncada, y aceptarla
	// dejaría recibos que Parse admite pero Format no puede reserializar.
	if !bytes.HasSuffix(rest, []byte("\n")) {
		return Receipt{}, fmt.Errorf("%w: la nota del checkpoint está truncada", ErrFormat)
	}
	return Receipt{Index: index, InclusionProof: nodes, CheckpointNote: rest}, nil
}

// Verify comprueba el recibo contra la política, sin tocar el ledger.
//
// entryHash es el hash del bloque, que es exactamente la hoja del árbol de
// Merkle según PROTOCOL.md §2. Se importa internal/ledger solo por sus
// funciones puras de verificación: no se consulta ningún almacén.
func (r Receipt) Verify(leafData []byte, p Policy) (Result, error) {
	if err := p.validate(); err != nil {
		return Result{}, err
	}
	// La longitud esperada es la de leaf_data bajo la regla vigente, no la de un
	// hash: bajo leaf/v2 la hoja son 96 bytes (PROTOCOL.md §2.1). Comprobarla aquí
	// es lo que convierte un verificador que se quedó en leaf/v1 en un error
	// inmediato en vez de un "la entrada no está incluida" que manda a buscar el
	// problema en el árbol.
	if len(leafData) != ledger.LeafDataSize {
		return Result{}, fmt.Errorf("%w: leaf_data mide %d bytes, se esperaban %d (%s)",
			ErrFormat, len(leafData), ledger.LeafDataSize, ledger.LeafRule)
	}

	logVerifier, err := checkpoint.NewVerifier(p.Origin, p.LogKey)
	if err != nil {
		return Result{}, err
	}
	verifiers := []note.Verifier{logVerifier}
	witnessNames := make(map[uint32]string, len(p.Witnesses))
	for name, pub := range p.Witnesses {
		v, err := witness.NewVerifier(name, pub)
		if err != nil {
			return Result{}, fmt.Errorf("%w: testigo %q: %w", ErrPolicy, name, err)
		}
		verifiers = append(verifiers, v)
		witnessNames[v.KeyHash()] = name
	}

	c, n, err := checkpoint.Verify(r.CheckpointNote, verifiers...)
	if err != nil {
		return Result{}, err
	}
	if c.Origin != p.Origin {
		return Result{}, fmt.Errorf("%w: %q != %q", ErrOrigin, c.Origin, p.Origin)
	}

	res := Result{Checkpoint: c}
	logSigned := false
	var earliest time.Time
	for _, sig := range n.Sigs {
		if sig.Name == logVerifier.Name() && sig.Hash == logVerifier.KeyHash() {
			logSigned = true
			continue
		}
		name, isWitness := witnessNames[sig.Hash]
		if !isWitness || name != sig.Name {
			continue
		}
		ts, err := cosignatureTime(sig.Base64)
		if err != nil {
			return Result{}, fmt.Errorf("%w: testigo %q: %w", ErrFormat, sig.Name, err)
		}
		res.Cosigners = append(res.Cosigners, sig.Name)
		if earliest.IsZero() || ts.Before(earliest) {
			earliest = ts
		}
	}
	// Las firmas de claves que la política no conoce se ignoran sin romper nada.
	for _, sig := range n.UnverifiedSigs {
		res.IgnoredSigs = append(res.IgnoredSigs, sig.Name)
	}
	res.ProvableTime = earliest

	if !logSigned {
		return Result{}, fmt.Errorf("%w: el checkpoint no está firmado por la clave del log", ErrOrigin)
	}
	if len(res.Cosigners) < p.Quorum {
		return Result{}, fmt.Errorf("%w: %d de %d", ErrQuorum, len(res.Cosigners), p.Quorum)
	}

	if r.Index >= c.Size {
		return Result{}, fmt.Errorf("%w: índice %d, tamaño %d", ErrIndex, r.Index, c.Size)
	}
	if c.Size > uint64(maxInt) || r.Index > uint64(maxInt) {
		return Result{}, fmt.Errorf("%w: tamaño o índice fuera de rango en esta plataforma", ErrIndex)
	}
	if err := ledger.VerifyInclusion(leafData, int(r.Index), int(c.Size),
		r.InclusionProof, c.RootHash); err != nil {
		return Result{}, fmt.Errorf("%w: %w", ErrInclusion, err)
	}
	return res, nil
}

const maxInt = int(^uint(0) >> 1)

// validate comprueba que la política sea utilizable.
func (p Policy) validate() error {
	if p.Origin == "" {
		return fmt.Errorf("%w: falta el origin", ErrPolicy)
	}
	if len(p.LogKey) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: la clave del log debe medir %d bytes", ErrPolicy, ed25519.PublicKeySize)
	}
	if p.Quorum < 0 {
		return fmt.Errorf("%w: quórum negativo", ErrPolicy)
	}
	if p.Quorum > len(p.Witnesses) {
		return fmt.Errorf("%w: quórum de %d con %d testigos configurados",
			ErrPolicy, p.Quorum, len(p.Witnesses))
	}
	return nil
}

// cosignatureTime extrae el instante de una cosignature ya verificada.
func cosignatureTime(b64 string) (time.Time, error) {
	raw, err := base64.StdEncoding.Strict().DecodeString(b64)
	if err != nil {
		return time.Time{}, err
	}
	if len(raw) < 4 {
		return time.Time{}, witness.ErrCosignature
	}
	return witness.Timestamp(raw[4:]) // los 4 primeros bytes son el key hash
}

// cutPrefixLine consume una línea concreta al principio de data.
func cutPrefixLine(data []byte, want string) ([]byte, bool) {
	line, rest, ok := cutLine(data)
	if !ok || line != want {
		return nil, false
	}
	return rest, true
}

// cutLine parte data en la primera línea y el resto. Exige el salto de línea:
// una última línea sin terminar es un recibo truncado.
func cutLine(data []byte) (string, []byte, bool) {
	i := bytes.IndexByte(data, '\n')
	if i < 0 {
		return "", nil, false
	}
	return string(data[:i]), data[i+1:], true
}
