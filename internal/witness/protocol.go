package witness

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
)

// Formato de cable de c2sp.org/tlog-witness. La versión exacta del spec que se
// implementa está registrada en docs/adr/ADR-011-witness-http.md, con el sha256
// del documento: si el spec cambia, ese hash deja de coincidir.
//
// Aquí no se inventa nada. Cada regla de este fichero sale de una frase del
// documento, y donde el documento no dice nada hay un // SPEC-CHECK.

const (
	// AddCheckpointPath es la ruta del envío, bajo el prefijo de submission.
	AddCheckpointPath = "/add-checkpoint"
	// SizeContentType es el Content-Type que el spec fija para el cuerpo del 409.
	SizeContentType = "text/x.tlog.size"
	// MaxProofLines es el máximo de líneas de prueba que el cliente puede enviar.
	MaxProofLines = 63
)

// ErrMalformedRequest indica un cuerpo de petición que no respeta el formato.
var ErrMalformedRequest = errors.New("witness: petición mal formada")

// AddCheckpointRequest es el cuerpo de un add-checkpoint.
type AddCheckpointRequest struct {
	// OldSize es el tamaño del último checkpoint que el cliente cree cosignado.
	OldSize uint64
	// Proof es la prueba de consistencia de OldSize al tamaño del checkpoint.
	Proof [][]byte
	// Note es el checkpoint verbatim, con sus firmas.
	Note []byte
}

// MarshalAddCheckpoint serializa la petición: línea "old <n>", una línea en
// base64 por nodo de la prueba, línea vacía, y el checkpoint tal cual. Cada
// línea termina en U+000A.
func MarshalAddCheckpoint(r AddCheckpointRequest) ([]byte, error) {
	if len(r.Proof) > MaxProofLines {
		return nil, fmt.Errorf("%w: %d líneas de prueba, el máximo es %d",
			ErrMalformedRequest, len(r.Proof), MaxProofLines)
	}
	if len(r.Note) == 0 {
		return nil, fmt.Errorf("%w: checkpoint vacío", ErrMalformedRequest)
	}
	var b bytes.Buffer
	// El spec exige decimal ASCII sin ceros a la izquierda, y "0" para el cero:
	// es exactamente lo que produce FormatUint.
	b.WriteString("old " + strconv.FormatUint(r.OldSize, 10) + "\n")
	for _, node := range r.Proof {
		b.WriteString(base64.StdEncoding.EncodeToString(node) + "\n")
	}
	b.WriteString("\n")
	b.Write(r.Note)
	return b.Bytes(), nil
}

// UnmarshalAddCheckpoint parsea el cuerpo de un add-checkpoint.
func UnmarshalAddCheckpoint(body []byte) (AddCheckpointRequest, error) {
	// La línea vacía separa la cabecera del checkpoint. Se busca la PRIMERA
	// ocurrencia de "\n\n": la línea "old" nunca está vacía y las de prueba
	// tampoco, así que la primera es el separador. La nota lleva su propia línea
	// en blanco entre cuerpo y firmas, y por eso hay que cortar por la primera y
	// no por la última.
	i := bytes.Index(body, []byte("\n\n"))
	if i < 0 {
		return AddCheckpointRequest{}, fmt.Errorf("%w: no hay línea vacía que separe la cabecera del checkpoint", ErrMalformedRequest)
	}
	head, note := body[:i+1], body[i+2:]
	if len(note) == 0 {
		return AddCheckpointRequest{}, fmt.Errorf("%w: checkpoint vacío", ErrMalformedRequest)
	}

	lines := bytes.Split(bytes.TrimSuffix(head, []byte("\n")), []byte("\n"))
	rest, ok := bytes.CutPrefix(lines[0], []byte("old "))
	if !ok {
		return AddCheckpointRequest{}, fmt.Errorf("%w: la primera línea no es \"old <tamaño>\"", ErrMalformedRequest)
	}
	old, err := parseDecimal(string(rest))
	if err != nil {
		return AddCheckpointRequest{}, err
	}

	proofLines := lines[1:]
	if len(proofLines) > MaxProofLines {
		return AddCheckpointRequest{}, fmt.Errorf("%w: %d líneas de prueba, el máximo es %d",
			ErrMalformedRequest, len(proofLines), MaxProofLines)
	}
	var proof [][]byte
	for _, l := range proofLines {
		node, err := base64.StdEncoding.DecodeString(string(l))
		if err != nil {
			return AddCheckpointRequest{}, fmt.Errorf("%w: nodo de prueba en base64 inválido: %v", ErrMalformedRequest, err)
		}
		proof = append(proof, node)
	}
	return AddCheckpointRequest{OldSize: old, Proof: proof, Note: note}, nil
}

// parseDecimal aplica la regla del spec: decimal ASCII sin ceros a la izquierda,
// salvo el propio "0". strconv.ParseUint aceptaría "007", y aceptarlo aquí
// abriría dos codificaciones para el mismo tamaño.
func parseDecimal(s string) (uint64, error) {
	if s == "" {
		return 0, fmt.Errorf("%w: tamaño vacío", ErrMalformedRequest)
	}
	if len(s) > 1 && s[0] == '0' {
		return 0, fmt.Errorf("%w: tamaño %q con ceros a la izquierda", ErrMalformedRequest, s)
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, fmt.Errorf("%w: tamaño %q no es decimal ASCII", ErrMalformedRequest, s)
		}
	}
	n, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%w: tamaño %q: %v", ErrMalformedRequest, s, err)
	}
	return n, nil
}

// SignatureLines extrae de una nota cosignada las líneas de firma que NO estaban
// en la original. Es el cuerpo de la respuesta 200: el spec pide las líneas de
// firma del testigo, no la nota entera.
func SignatureLines(original, cosigned []byte) ([]byte, error) {
	origSigs, err := sigBlock(original)
	if err != nil {
		return nil, err
	}
	newSigs, err := sigBlock(cosigned)
	if err != nil {
		return nil, err
	}
	had := map[string]bool{}
	for _, l := range bytes.Split(bytes.TrimSuffix(origSigs, []byte("\n")), []byte("\n")) {
		had[string(l)] = true
	}
	var out bytes.Buffer
	for _, l := range bytes.Split(bytes.TrimSuffix(newSigs, []byte("\n")), []byte("\n")) {
		if len(l) == 0 || had[string(l)] {
			continue
		}
		out.Write(l)
		out.WriteByte('\n')
	}
	if out.Len() == 0 {
		return nil, errors.New("witness: la nota cosignada no añadió ninguna firma")
	}
	return out.Bytes(), nil
}

// sigBlock devuelve el bloque de firmas de una nota: lo que sigue a la última
// línea en blanco.
func sigBlock(msg []byte) ([]byte, error) {
	i := bytes.LastIndex(msg, []byte("\n\n"))
	if i < 0 {
		return nil, fmt.Errorf("%w: la nota no separa cuerpo y firmas", ErrMalformedRequest)
	}
	return msg[i+2:], nil
}

// MonitorPath devuelve la ruta de monitorización de un origin:
// <origin hash>/checkpoint, con el hash SHA-256 del origin en hex minúscula.
func MonitorPath(origin string) string {
	return "/" + OriginHash(origin) + "/checkpoint"
}

// OriginHash es el SHA-256 del origin en hexadecimal minúsculo, tal como lo
// define el spec para la ruta de monitorización.
func OriginHash(origin string) string {
	sum := sha256.Sum256([]byte(origin))
	return hex.EncodeToString(sum[:])
}
