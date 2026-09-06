package witness

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// maxResponseBody acota lo que el cliente acepta de un testigo. Un testigo es
// una parte independiente: útil, pero no de fiar hasta que sus firmas verifican.
const maxResponseBody = 256 << 10

// Client habla el protocolo c2sp.org/tlog-witness con un testigo remoto.
type Client struct {
	// BaseURL es el prefijo del testigo, sin barra final.
	BaseURL string
	// HTTP es el cliente a usar; nil usa http.DefaultClient.
	HTTP *http.Client
}

// NewClient construye un cliente contra el prefijo dado.
func NewClient(baseURL string) *Client {
	return &Client{BaseURL: strings.TrimSuffix(baseURL, "/")}
}

func (c *Client) httpClient() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return http.DefaultClient
}

// AddCheckpoint envía un checkpoint con su prueba de consistencia y devuelve las
// líneas de firma que el testigo añadió.
//
// Ante un 409 devuelve *ConflictError con el tamaño que el testigo dice
// recordar, que es lo que permite reintentar con la prueba correcta en vez de
// adivinar.
func (c *Client) AddCheckpoint(ctx context.Context, oldSize uint64, proof [][]byte, note []byte) ([]byte, error) {
	body, err := MarshalAddCheckpoint(AddCheckpointRequest{OldSize: oldSize, Proof: proof, Note: note})
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
		return respBody, nil
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

// Checkpoint pide al testigo el último checkpoint que cosignó para un origin.
//
// Esta llamada es la mitigación del hallazgo ALTO de la auditoría externa: es la
// forma de que un log compare su estado local con una memoria que no está en su
// disco y que, por tanto, no pudo truncar quien truncó el fichero.
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
		return body, nil
	case http.StatusNotFound:
		return nil, ErrNoWitnessCheckpoint
	default:
		return nil, fmt.Errorf("witness: checkpoint de %q: HTTP %d: %s",
			origin, resp.StatusCode, strings.TrimSpace(string(body)))
	}
}
