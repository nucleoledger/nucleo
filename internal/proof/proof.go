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
	"encoding/binary"
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
	// ErrSignature indica que una línea de firma de una clave que la política
	// conoce no verifica (PROTOCOL.md §3.3).
	ErrSignature = errors.New("proof: una firma de una clave conocida no verifica")
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
	// SignerKey es la clave pública del tenant que firma los BLOQUES (ADR-017).
	//
	// Obligatoria para verificar un recibo. Sin ella, "firmado por el emisor"
	// se comprobaría contra la clave que trae el propio recibo en su header, y
	// eso es una afirmación del recibo sobre sí mismo: la segunda auditoría
	// adversarial emitió un recibo de un bloque firmado por una clave ajena, bajo
	// el checkpoint del log real, y los tres verificadores lo dieron por bueno.
	// La clave del firmante tiene que venir de fuera, como la del log.
	SignerKey ed25519.PublicKey
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
	// LogExtraSigs son las firmas ADICIONALES del propio log: líneas con el nombre
	// del origin que no son su firma Ed25519 y miden lo que una ML-DSA-44 (ADR-007).
	// No se verifican aquí y no cuentan para nada, pero tampoco son "claves que no
	// conoces": llevan el nombre del log. TypeScript las separó en el Sprint 7e y Go
	// no, y el diferencial —al comparar el dictamen entero y no solo el veredicto—
	// encontró la asimetría en su primera ejecución.
	LogExtraSigs []string
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

// VerifyNote comprueba una nota de checkpoint bajo la política: la firma del
// log con la clave de la política, las cosignatures de los testigos aceptados, y
// el quórum. Devuelve qué testigos verificaron y el tiempo demostrable.
//
// Es la ÚNICA definición de "esta nota está atestiguada" del proyecto, y por eso
// vive aquí y la llaman dos sitios: la verificación de un recibo, y la apertura
// del ledger (ADR-016). Antes la apertura tenía su propia idea —"una nota con una
// línea de 76 bytes"— y la auditoría adversarial demostró que esa idea la
// satisfacía cualquiera con escritura en la base. Dos definiciones de atestación
// es una de más.
func VerifyNote(noteBytes []byte, p Policy) (Result, error) {
	if err := p.validate(); err != nil {
		return Result{}, err
	}
	logVerifier, err := checkpoint.NewVerifier(p.Origin, p.LogKey)
	if err != nil {
		return Result{}, err
	}
	verifiers := []note.Verifier{logVerifier}
	witnessVerifiers := make(map[string]*witness.Verifier, len(p.Witnesses))
	for name, pub := range p.Witnesses {
		v, err := witness.NewVerifier(name, pub)
		if err != nil {
			return Result{}, fmt.Errorf("%w: testigo %q: %w", ErrPolicy, name, err)
		}
		verifiers = append(verifiers, v)
		witnessVerifiers[name] = v
	}

	// x/mod abre la nota, comprueba su estructura y la firma del log. NO basta
	// para contar: descarta sin verificarlas las firmas repetidas de una clave
	// conocida y se queda con la primera. Por eso las líneas se leen aquí.
	c, n, err := checkpoint.Verify(noteBytes, verifiers...)
	if err != nil {
		return Result{}, err
	}
	if c.Origin != p.Origin {
		return Result{}, fmt.Errorf("%w: %q != %q", ErrOrigin, c.Origin, p.Origin)
	}
	text, lines, err := signatureLines(noteBytes)
	if err != nil {
		return Result{}, err
	}

	// Reglas de PROTOCOL.md §3.3 (ADR-018 C):
	//   - toda línea de una clave conocida verifica, o la nota es inválida;
	//   - un testigo cuenta una vez;
	//   - su tiempo es el de su cosignature MÁS TEMPRANA entre las que verifican.
	// La tercera auditoría dio con las dos formas de fallar esto: con la primera
	// línea como fecha, el orden de las líneas —que elige el emisor— decidía el
	// tiempo demostrable, y Go y TypeScript daban veredictos opuestos.
	res := Result{Checkpoint: c}
	logSigned := false
	var earliest time.Time
	counted := make(map[string]bool, len(witnessVerifiers))
	for _, l := range lines {
		if l.name == logVerifier.Name() && l.hash == logVerifier.KeyHash() {
			if !logVerifier.Verify(text, l.sig) {
				return Result{}, fmt.Errorf("%w: una línea de la firma del log", ErrSignature)
			}
			logSigned = true
			continue
		}
		v, ok := witnessVerifiers[l.name]
		if !ok || v.KeyHash() != l.hash {
			continue
		}
		if !v.Verify(text, l.sig) {
			return Result{}, fmt.Errorf("%w: una cosignature del testigo %q", ErrSignature, l.name)
		}
		ts, err := witness.Timestamp(l.sig)
		if err != nil {
			return Result{}, fmt.Errorf("%w: testigo %q: %w", ErrFormat, l.name, err)
		}
		if !counted[l.name] {
			counted[l.name] = true
			res.Cosigners = append(res.Cosigners, l.name)
		}
		if earliest.IsZero() || ts.Before(earliest) {
			earliest = ts
		}
	}
	// Las firmas de claves que la política no conoce se ignoran sin romper nada.
	for _, sig := range n.UnverifiedSigs {
		if sig.Name == p.Origin && esFirmaMLDSA(sig.Base64) {
			res.LogExtraSigs = append(res.LogExtraSigs, sig.Name)
			continue
		}
		res.IgnoredSigs = append(res.IgnoredSigs, sig.Name)
	}
	res.ProvableTime = earliest

	if !logSigned {
		return Result{}, fmt.Errorf("%w: el checkpoint no está firmado por la clave del log", ErrOrigin)
	}
	if len(res.Cosigners) < p.Quorum {
		return Result{}, fmt.Errorf("%w: %d de %d", ErrQuorum, len(res.Cosigners), p.Quorum)
	}
	return res, nil
}

// mldsaSignatureSize es lo que mide una firma ML-DSA-44 (FIPS 204). Se compara el
// tamaño porque el key ID de una clave desconocida no se puede recomputar: es lo mismo
// que hace el verificador de TypeScript, y con el mismo número.
const mldsaSignatureSize = 2420

// esFirmaMLDSA dice si el blob de una firma tiene el tamaño de una ML-DSA-44, sin los
// 4 bytes del key ID.
func esFirmaMLDSA(b64 string) bool {
	raw, err := base64.StdEncoding.Strict().DecodeString(b64)
	return err == nil && len(raw) == 4+mldsaSignatureSize
}

// sigLine es una línea del bloque de firmas de una nota, sin interpretar.
type sigLine struct {
	name string
	hash uint32
	// sig es la firma sin los 4 bytes del key ID.
	sig []byte
}

// maxSigLines es el máximo de líneas de firma de una nota (PROTOCOL.md §3.3).
const maxSigLines = 100

// signatureLines separa el texto firmado de sus líneas de firma con las reglas de
// PROTOCOL.md §3.3. Se llama DESPUÉS de checkpoint.Verify, así que la estructura
// ya la validó x/mod; lo que aquí se añade es tener TODAS las líneas, repetidas
// incluidas.
func signatureLines(msg []byte) ([]byte, []sigLine, error) {
	split := bytes.LastIndex(msg, []byte("\n\n"))
	if split < 0 {
		return nil, nil, fmt.Errorf("%w: la nota no separa cuerpo y firmas", ErrFormat)
	}
	text, block := msg[:split+1], msg[split+2:]
	if len(block) == 0 || block[len(block)-1] != '\n' {
		return nil, nil, fmt.Errorf("%w: el bloque de firmas no termina en salto de línea", ErrFormat)
	}
	var out []sigLine
	for _, raw := range strings.Split(string(block[:len(block)-1]), "\n") {
		rest, ok := strings.CutPrefix(raw, "— ")
		if !ok {
			return nil, nil, fmt.Errorf("%w: línea de firma sin el prefijo de signed-note", ErrFormat)
		}
		name, b64, ok := strings.Cut(rest, " ")
		if !ok {
			return nil, nil, fmt.Errorf("%w: línea de firma sin nombre y firma", ErrFormat)
		}
		// Strict: base64 CANÓNICO (regla 4). x/mod usa el decodificador no estricto, y
		// dos textos para los mismos bytes son dos recibos para una sola firma.
		blob, err := base64.StdEncoding.Strict().DecodeString(b64)
		if err != nil || len(blob) < 5 {
			return nil, nil, fmt.Errorf("%w: firma de %q ilegible", ErrFormat, name)
		}
		out = append(out, sigLine{name: name, hash: binary.BigEndian.Uint32(blob[:4]), sig: blob[4:]})
		if len(out) > maxSigLines {
			return nil, nil, fmt.Errorf("%w: más de %d líneas de firma", ErrFormat, maxSigLines)
		}
	}
	return text, out, nil
}

// RequireWitnesses exige que la política pueda verificar algo: al menos un testigo y
// quórum de al menos uno. Lo llama quien verifica un RECIBO (PROTOCOL.md §3.2,
// ADR-018). validate admite quórum 0 porque lo usan piezas que solo comprueban la
// firma del log; un recibo con esa política daba "válido" sin que ningún tercero
// hubiera firmado nada —la tercera auditoría lo enseñó en los tres verificadores—,
// y la ausencia de testigos no es un modo: es un campo olvidado.
func (p Policy) RequireWitnesses() error {
	if len(p.Witnesses) == 0 || p.Quorum < 1 {
		return fmt.Errorf("%w: una política de recibos exige al menos un testigo y quórum de al menos 1 "+
			"(trae %d testigos y quórum %d)", ErrPolicy, len(p.Witnesses), p.Quorum)
	}
	return nil
}

// RequireSignerKey exige que la política traiga la clave del firmante de bloques.
// Lo llama quien verifica un RECIBO: una nota de checkpoint no tiene firmante de
// bloques, así que VerifyNote no lo pide, pero un recibo sin esta clave en la
// política no puede afirmar autoría (ADR-017).
func (p Policy) RequireSignerKey() error {
	if len(p.SignerKey) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: falta la clave del firmante de bloques (signerKey), o no mide %d bytes",
			ErrPolicy, ed25519.PublicKeySize)
	}
	return nil
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

	res, err := VerifyNote(r.CheckpointNote, p)
	if err != nil {
		return Result{}, err
	}
	c := res.Checkpoint

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
	// La misma clave bajo dos nombres contaría dos veces: la cosignature no lleva el
	// nombre del testigo, así que se copia bajo el otro recalculando el key ID.
	porClave := make(map[string]string, len(p.Witnesses))
	for name, pub := range p.Witnesses {
		if otro, ok := porClave[string(pub)]; ok {
			return fmt.Errorf("%w: la misma clave está bajo dos nombres (%q y %q)", ErrPolicy, otro, name)
		}
		porClave[string(pub)] = name
	}
	return nil
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
