// Package reconcile compara lo que el sistema vivo dice HOY con lo que el
// ledger selló en su momento.
//
// Esta es la razón de ser de Núcleo, y conviene decirla sin rodeos. Un log
// firmado prueba que un registro existía y no ha cambiado DENTRO del log. No
// prueba nada sobre la base de datos operativa de la que salió: ahí un UPDATE
// convierte una factura de 10.000 en una de 1.000 sin dejar rastro, y el ledger
// ni se entera, porque nadie le preguntó.
//
// La reconciliación es quien pregunta. Recorre los registros vivos, recomputa el
// hash de cada uno y lo contrasta con el payload_hash sellado. Donde los dos no
// coinciden, hay un registro que fue alterado después de sellarse, y el reporte
// dice cuál, cuándo se selló y qué decía entonces.
//
// El ledger no impide la alteración. La hace visible, y eso es lo que se puede
// prometer de verdad.
package reconcile

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/nucleoledger/nucleo/internal/ledger"
	"github.com/nucleoledger/nucleo/internal/store"
)

// Record es un registro tal como lo devuelve HOY el sistema vivo.
type Record struct {
	// Index es el bloque del ledger al que corresponde.
	Index uint64
	// Payload son los bytes actuales del registro.
	Payload []byte
	// Extra marca un registro que el sistema vivo tiene y el ledger no selló.
	// Solo tiene sentido si la fuente sabe reconocerlos; si no, se deja en false.
	Extra bool
}

// Source entrega los registros vivos, uno a uno.
//
// Es un callback y no una lista porque un sistema real puede tener millones de
// registros y no caben en memoria. Devolver un error aborta el recorrido.
type Source func(yield func(Record) error) error

// Status clasifica cada registro comparado.
type Status string

const (
	// StatusVerified indica que el registro vivo es idéntico al sellado.
	StatusVerified Status = "verificado"
	// StatusAltered indica que el registro vivo NO coincide con lo sellado.
	StatusAltered Status = "discrepancia"
	// StatusMissing indica un bloque sellado que el sistema vivo ya no tiene.
	StatusMissing Status = "faltante"
	// StatusExtra indica un registro vivo que nunca se selló.
	StatusExtra Status = "no sellado"
)

// Finding describe un registro que no cuadra.
type Finding struct {
	Status Status `json:"status"`
	Index  uint64 `json:"index,omitempty"`
	// SealedHash es el payload_hash que está en el ledger.
	SealedHash string `json:"sealed_hash,omitempty"`
	// CurrentHash es el SHA-256 de lo que el sistema vivo devuelve hoy.
	CurrentHash string `json:"current_hash,omitempty"`
	// SealedAt es el tiempo DECLARADO del bloque. Se llama así, y no "fecha",
	// porque es el reloj del emisor: sitúa el sellado, no lo demuestra. El
	// tiempo demostrable de ese bloque está en su recibo.
	SealedAt string `json:"sealed_at,omitempty"`
	// Tenant y Type ayudan a localizar el registro en el sistema vivo.
	Tenant string `json:"tenant,omitempty"`
	Type   string `json:"type,omitempty"`
}

// Report es el resultado de un recorrido completo.
type Report struct {
	// TreeSize es el número de bloques del ledger en el momento del cotejo.
	TreeSize uint64 `json:"tree_size"`
	// Checked es cuántos registros vivos se compararon.
	Checked int `json:"checked"`
	// Verified es cuántos coincidieron.
	Verified int `json:"verified"`
	// Findings son los que no. Van ordenados por índice.
	Findings []Finding `json:"findings"`
	// FullVerify recoge el resultado de VerifyFull si se pidió.
	FullVerify *FullVerifyResult `json:"full_verify,omitempty"`
}

// FullVerifyResult cuenta si la verificación exhaustiva del ledger pasó.
type FullVerifyResult struct {
	Run bool   `json:"run"`
	OK  bool   `json:"ok"`
	Err string `json:"error,omitempty"`
}

// Altered devuelve solo las discrepancias, que es lo que hay que mirar primero.
func (r *Report) Altered() []Finding {
	var out []Finding
	for _, f := range r.Findings {
		if f.Status == StatusAltered {
			out = append(out, f)
		}
	}
	return out
}

// JSON serializa el reporte.
func (r *Report) JSON() ([]byte, error) { return json.MarshalIndent(r, "", "  ") }

// Ledger es lo que la reconciliación necesita del ledger sellado.
type Ledger interface {
	Count() (int, error)
	Blocks(from, to uint64) ([]*ledger.Block, error)
}

// Options ajusta el recorrido.
type Options struct {
	// IncludeFullVerify ejecuta la verificación exhaustiva del ledger como parte
	// del cotejo.
	//
	// Es la ejecución PROGRAMADA que promete la enmienda de ADR-009. La apertura
	// rápida no recomprueba las firmas históricas amparadas por un checkpoint
	// cosignado; VerifyFull sí, y dejarlo a que alguien "sospeche" es dejarlo
	// sin hacer. La reconciliación es el momento natural: ya se está mirando
	// todo.
	IncludeFullVerify bool
}

// FullVerifier es lo que hace falta para la verificación exhaustiva. Lo cumple
// *store.Store.
type FullVerifier interface {
	VerifyFull() (store.OpenResult, error)
}

// Reconcile recorre los registros vivos y los contrasta con lo sellado.
func Reconcile(l Ledger, src Source, opts Options) (*Report, error) {
	n, err := l.Count()
	if err != nil {
		return nil, err
	}
	blocks, err := l.Blocks(0, uint64(n))
	if err != nil {
		return nil, err
	}

	sealed := make(map[uint64]*ledger.Block, len(blocks))
	for _, b := range blocks {
		sealed[b.Header.Index] = b
	}

	rep := &Report{TreeSize: uint64(n)}
	seen := make(map[uint64]bool, len(blocks))

	err = src(func(rec Record) error {
		rep.Checked++
		sum := sha256.Sum256(rec.Payload)
		current := hex.EncodeToString(sum[:])

		if rec.Extra {
			rep.Findings = append(rep.Findings, Finding{
				Status: StatusExtra, Index: rec.Index, CurrentHash: current,
			})
			return nil
		}

		b, ok := sealed[rec.Index]
		if !ok {
			rep.Findings = append(rep.Findings, Finding{
				Status: StatusExtra, Index: rec.Index, CurrentHash: current,
			})
			return nil
		}
		seen[rec.Index] = true

		if b.Header.PayloadHash == current {
			rep.Verified++
			return nil
		}
		rep.Findings = append(rep.Findings, Finding{
			Status:      StatusAltered,
			Index:       rec.Index,
			SealedHash:  b.Header.PayloadHash,
			CurrentHash: current,
			SealedAt:    b.Header.Timestamp,
			Tenant:      b.Header.Tenant,
			Type:        b.Header.Type,
		})
		return nil
	})
	if err != nil {
		return nil, err
	}

	// Lo que el ledger selló y el sistema vivo ya no tiene. Un registro que
	// desaparece de la base operativa es tan relevante como uno alterado, y sin
	// esta pasada no se vería: nadie lo trae para compararlo.
	for _, b := range blocks {
		if seen[b.Header.Index] {
			continue
		}
		rep.Findings = append(rep.Findings, Finding{
			Status:     StatusMissing,
			Index:      b.Header.Index,
			SealedHash: b.Header.PayloadHash,
			SealedAt:   b.Header.Timestamp,
			Tenant:     b.Header.Tenant,
			Type:       b.Header.Type,
		})
	}
	sortFindings(rep.Findings)

	if opts.IncludeFullVerify {
		fv, ok := l.(FullVerifier)
		if !ok {
			return nil, fmt.Errorf("reconcile: se pidió verificación exhaustiva y el ledger no la ofrece")
		}
		rep.FullVerify = &FullVerifyResult{Run: true, OK: true}
		if _, err := fv.VerifyFull(); err != nil {
			rep.FullVerify.OK = false
			rep.FullVerify.Err = err.Error()
		}
	}
	return rep, nil
}

// sortFindings ordena por índice y, a igual índice, por estado, para que dos
// ejecuciones del mismo cotejo produzcan el mismo reporte.
func sortFindings(fs []Finding) {
	for i := 1; i < len(fs); i++ {
		for j := i; j > 0 && less(fs[j], fs[j-1]); j-- {
			fs[j], fs[j-1] = fs[j-1], fs[j]
		}
	}
}

func less(a, b Finding) bool {
	if a.Index != b.Index {
		return a.Index < b.Index
	}
	return a.Status < b.Status
}

// SealedTime parsea el tiempo declarado de un hallazgo.
func (f Finding) SealedTime() (time.Time, error) {
	return time.Parse(time.RFC3339Nano, f.SealedAt)
}

// FromSlice construye una Source desde una lista en memoria, para casos
// pequeños y para los tests.
func FromSlice(records []Record) Source {
	return func(yield func(Record) error) error {
		for _, r := range records {
			if err := yield(r); err != nil {
				return err
			}
		}
		return nil
	}
}
