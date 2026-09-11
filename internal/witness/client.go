package witness

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"golang.org/x/mod/sumdb/note"
)

// maxResponseBody acota lo que el cliente acepta de un testigo. Un testigo es
// una parte independiente: útil, pero no de fiar hasta que sus firmas verifican.
const maxResponseBody = 256 << 10

// ErrNoCosignature indica que el testigo respondió sin ninguna cosignature
// válida de la clave que este cliente tiene por suya.
//
// Es el rechazo central de este fichero. Un 200 no prueba nada: lo único que
// prueba algo es una cosignature que verifica. Sin ella no hay atestación, por
// muy bien formada que venga la respuesta.
var ErrNoCosignature = errors.New("witness: la respuesta no trae una cosignature válida del testigo")

// Client habla el protocolo c2sp.org/tlog-witness con un testigo remoto.
//
// Va siempre atado a la identidad del testigo —nombre y clave pública— porque
// sin ella no puede distinguir una cosignature de una cadena de bytes con la
// forma correcta. Construirlo sin clave sería construir un cliente que se cree
// lo que le digan.
type Client struct {
	// BaseURL es el prefijo del testigo, sin barra final.
	BaseURL string
	// HTTP es el cliente a usar; nil usa http.DefaultClient.
	HTTP *http.Client

	verifier *Verifier
}

// NewClient construye un cliente contra el prefijo dado, atado a la identidad
// del testigo.
//
// El nombre y la clave son OBLIGATORIOS. c2sp.org/tlog-witness dice que el
// cliente «MUST ignore any cosignatures from unknown keys» y describe el flujo
// correcto: concatenar la respuesta al checkpoint y abrirla con una función de
// verificación configurada con las claves de los testigos en los que confía. Sin
// clave no hay nada que configurar, así que un cliente sin clave no puede
// cumplir el protocolo.
func NewClient(baseURL, witnessName string, witnessKey ed25519.PublicKey) (*Client, error) {
	v, err := NewVerifier(witnessName, witnessKey)
	if err != nil {
		return nil, err
	}
	return &Client{BaseURL: strings.TrimSuffix(baseURL, "/"), verifier: v}, nil
}

// WitnessName devuelve el nombre del testigo con el que habla este cliente.
func (c *Client) WitnessName() string { return c.verifier.Name() }

// verifyCosigned exige al menos una cosignature válida del testigo sobre la
// nota, e ignora en silencio las firmas de claves desconocidas.
//
// Las dos mitades son del spec y ninguna sobra: ignorar lo desconocido es lo que
// permite que un checkpoint circule con firmas de terceros que este cliente no
// conoce; exigir una válida es lo que impide que esas firmas ajenas pasen por
// atestación.
func (c *Client) verifyCosigned(msg []byte) error {
	_, err := c.CosignatureTime(msg)
	return err
}

// CosignatureTime devuelve el instante que este testigo afirma, tras VERIFICAR
// su cosignature sobre la nota.
//
// El timestamp vive dentro del blob de firma, así que leerlo sin comprobar la
// firma sería leer lo que quiera contarnos quien controle los bytes: exactamente
// el defecto que la auditoría encontró en el cálculo del tiempo demostrable,
// donde una fecha se sacaba de la FORMA del blob. Aquí el orden es al revés:
// primero abre la nota contra la clave del testigo, y solo entonces lee.
//
// Que devuelva un instante y no un booleano es lo que permite guardar "cuándo
// avaló un tercero esto por última vez" sin volver a pedir la clave del testigo
// en cada invocación de la CLI.
func (c *Client) CosignatureTime(msg []byte) (time.Time, error) {
	n, err := note.Open(msg, note.VerifierList(c.verifier))
	if err != nil {
		return time.Time{}, fmt.Errorf("%w: %w", ErrNoCosignature, err)
	}
	for _, sig := range n.Sigs {
		if sig.Name != c.verifier.Name() || sig.Hash != c.verifier.KeyHash() {
			continue
		}
		raw, err := base64.StdEncoding.Strict().DecodeString(sig.Base64)
		if err != nil {
			return time.Time{}, fmt.Errorf("%w: blob de firma ilegible: %w", ErrNoCosignature, err)
		}
		// Los 4 primeros bytes son el key hash que antepone note.
		if len(raw) < keyHashPrefix {
			return time.Time{}, fmt.Errorf("%w: blob de %d bytes", ErrCosignature, len(raw))
		}
		return Timestamp(raw[keyHashPrefix:])
	}
	return time.Time{}, fmt.Errorf("%w: la nota abrió pero sin firma de %q", ErrNoCosignature, c.verifier.Name())
}

// keyHashPrefix son los 4 bytes de key ID que note pone delante de cada firma.
const keyHashPrefix = 4

func (c *Client) httpClient() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return http.DefaultClient
}

// AddCheckpoint envía un checkpoint con su prueba de consistencia y devuelve la
// nota COSIGNADA Y VERIFICADA: el checkpoint original más las líneas de firma
// que el testigo añadió, comprobadas contra su clave.
//
// Devuelve la nota entera y no las líneas sueltas a propósito. Si devolviera las
// líneas, quien llama tendría que ensamblarlas, y el ensamblaje de bytes sin
// verificar es exactamente donde se cuela una atestación falsa. Aquí solo salen
// bytes ya comprobados.
//
// Ante un 409 devuelve *ConflictError con el tamaño que el testigo dice
// recordar, que es lo que permite reintentar con la prueba correcta en vez de
// adivinar. Ese tamaño NO está autenticado: sirve para reintentar, nunca para
// concluir nada.
func (c *Client) AddCheckpoint(ctx context.Context, oldSize uint64, proof [][]byte, msg []byte) ([]byte, error) {
	body, err := MarshalAddCheckpoint(AddCheckpointRequest{OldSize: oldSize, Proof: proof, Note: msg})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+AddCheckpointPath, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "text/plain; charset=utf-8")

	resp, err := c.httpClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("witness: add-checkpoint: %w", err)
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBody))
	if err != nil {
		return nil, fmt.Errorf("witness: add-checkpoint: %w", err)
	}

	switch resp.StatusCode {
	case http.StatusOK:
		cosigned := append(append([]byte{}, msg...), respBody...)
		if err := c.verifyCosigned(cosigned); err != nil {
			return nil, err
		}
		return cosigned, nil
	case http.StatusConflict:
		size, err := parseDecimal(strings.TrimSuffix(string(respBody), "\n"))
		if err != nil {
			return nil, fmt.Errorf("witness: 409 con cuerpo ilegible %q: %w", respBody, err)
		}
		return nil, &ConflictError{
			LastSize: size,
			Reason:   fmt.Errorf("el testigo recuerda un árbol de %d y se le declaró %d", size, oldSize),
		}
	default:
		return nil, fmt.Errorf("witness: add-checkpoint: HTTP %d: %s",
			resp.StatusCode, strings.TrimSpace(string(respBody)))
	}
}

// ErrNoWitnessCheckpoint indica que el testigo nunca cosignó para ese origin.
var ErrNoWitnessCheckpoint = errors.New("witness: el testigo no tiene checkpoint de ese log")

// Checkpoint pide al testigo el último checkpoint que cosignó para un origin, y
// devuelve la nota SOLO si lleva una cosignature válida del testigo.
//
// Esta llamada es la mitigación del hallazgo ALTO de la primera auditoría: es la
// forma de que un log compare su estado local con una memoria que no está en su
// disco. Pero una nota sin verificar no es memoria de nadie: el spec permite
// delegar el prefijo de monitorización a una CDN y no autentica el canal, así
// que sin comprobar la firma esto sería creerse lo que devuelva un intermediario
// cualquiera. Con la firma comprobada, lo peor que puede hacer ese intermediario
// es servir una nota vieja y GENUINA, que es un problema distinto y se trata en
// logsync.
func (c *Client) Checkpoint(ctx context.Context, origin string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+MonitorPath(origin), nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("witness: checkpoint de %q: %w", origin, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBody))
	if err != nil {
		return nil, fmt.Errorf("witness: checkpoint de %q: %w", origin, err)
	}
	switch resp.StatusCode {
	case http.StatusOK:
		if err := c.verifyCosigned(body); err != nil {
			return nil, err
		}
		return body, nil
	case http.StatusNotFound:
		return nil, ErrNoWitnessCheckpoint
	default:
		return nil, fmt.Errorf("witness: checkpoint de %q: HTTP %d: %s",
			origin, resp.StatusCode, strings.TrimSpace(string(body)))
	}
}
