package witness

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"

	"github.com/nucleoledger/nucleo/internal/checkpoint"
)

// maxRequestBody acota el cuerpo de una petición. El spec no fija un límite,
// pero un testigo es un servicio público sin autenticación —cualquiera puede
// enviarle un checkpoint— y aceptar cuerpos sin tope sería regalar un ataque de
// agotamiento de memoria. 64 KiB sobran: 63 líneas de prueba son unos 3 KiB.
const maxRequestBody = 64 << 10

// Server expone un testigo por HTTP según c2sp.org/tlog-witness.
type Server struct {
	w *Witness
}

// NewServer envuelve un testigo.
func NewServer(w *Witness) *Server { return &Server{w: w} }

// Handler devuelve el enrutador con las dos rutas del spec. Núcleo usa el mismo
// prefijo para envío y monitorización, que el spec permite explícitamente.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST "+AddCheckpointPath, s.addCheckpoint)
	mux.HandleFunc("GET /{originHash}/checkpoint", s.monitorCheckpoint)
	return mux
}

// addCheckpoint implementa POST <submission prefix>/add-checkpoint.
func (s *Server) addCheckpoint(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxRequestBody))
	if err != nil {
		fail(w, http.StatusBadRequest, "cuerpo ilegible: %v", err)
		return
	}
	req, err := UnmarshalAddCheckpoint(body)
	if err != nil {
		fail(w, http.StatusBadRequest, "%v", err)
		return
	}

	cosigned, err := s.w.CosignAt(req.OldSize, req.Note, req.Proof)
	if err != nil {
		s.failCosign(w, err)
		return
	}
	lines, err := SignatureLines(req.Note, cosigned)
	if err != nil {
		fail(w, http.StatusInternalServerError, "%v", err)
		return
	}

	// SPEC-CHECK: el spec fija el Content-Type de la respuesta 409
	// (text/x.tlog.size) y no dice nada del de la 200. Se emite text/plain,
	// que es lo que el cuerpo es —líneas de firma de nota en UTF-8—.
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write(lines)
}

// failCosign traduce el error del testigo al código que manda el spec. La tabla
// completa está en ADR-011.
func (s *Server) failCosign(w http.ResponseWriter, err error) {
	var conflict *ConflictError
	switch {
	case errors.Is(err, ErrUnknownLog):
		fail(w, http.StatusNotFound, "origin desconocido")
	case errors.Is(err, ErrBadSignature):
		fail(w, http.StatusForbidden, "%v", err)
	case errors.Is(err, ErrOldSize):
		fail(w, http.StatusBadRequest, "%v", err)
	case errors.As(err, &conflict):
		// El 409 es el único error con cuerpo especificado: el tamaño del
		// último checkpoint cosignado, en decimal y con salto de línea. Es lo
		// que permite a un log honesto que perdió el hilo construir la prueba
		// correcta y reintentar sin adivinar.
		w.Header().Set("Content-Type", SizeContentType)
		w.WriteHeader(http.StatusConflict)
		fmt.Fprintf(w, "%d\n", conflict.LastSize)
	case errors.Is(err, ErrUnprocessable), errors.Is(err, checkpoint.ErrFormat),
		errors.Is(err, checkpoint.ErrRootSize), errors.Is(err, checkpoint.ErrOrigin):
		fail(w, http.StatusUnprocessableEntity, "%v", err)
	default:
		fail(w, http.StatusInternalServerError, "%v", err)
	}
}

// monitorCheckpoint implementa GET <monitoring prefix>/<origin hash>/checkpoint.
//
// No es un extra de comodidad: es la única vía por la que un log puede descubrir
// que su fichero local fue truncado, porque el recuerdo que lo desmiente vive
// fuera de su disco. Ver ADR-009, hallazgo ALTO de la auditoría externa.
func (s *Server) monitorCheckpoint(w http.ResponseWriter, r *http.Request) {
	want := r.PathValue("originHash")

	// El testigo indexa por origin, y el spec direcciona por su hash. Se
	// recorren los logs conocidos buscando el que casa: son unos pocos por
	// testigo, y así no hace falta guardar un índice inverso que podría
	// desincronizarse del estado real.
	origin, ok := s.w.originByHash(want)
	if !ok {
		fail(w, http.StatusNotFound, "origin desconocido")
		return
	}
	note, err := s.w.LastNote(origin)
	if errors.Is(err, ErrNoState) {
		fail(w, http.StatusNotFound, "este testigo nunca cosignó un checkpoint de ese log")
		return
	}
	if err != nil {
		fail(w, http.StatusInternalServerError, "%v", err)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Length", strconv.Itoa(len(note)))
	w.Write(note)
}

// fail escribe un error con su código.
//
// SPEC-CHECK: el spec solo especifica el cuerpo de la respuesta 409. Para el
// resto se emite una línea de texto en claro, pensada para que un operador
// humano lea el motivo en un log. Ningún cliente debe parsearla.
func fail(w http.ResponseWriter, code int, format string, args ...any) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(code)
	fmt.Fprintf(w, format+"\n", args...)
}
