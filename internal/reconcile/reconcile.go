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

	"github.com/nucleoledger/nucleo/internal/erasure"
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
	// StatusUnauthorizedErasure indica un evento de supresión que no lleva una
	// autorización válida de la clave de supresión de la política (ADR-032). Es un
	// hallazgo de integridad: quien tiene la clave del tenant —la del servidor— puede
	// sellar un evento, y sin autorización no dice nada.
	StatusUnauthorizedErasure Status = "supresión no autorizada"
)

// Finding describe un registro que no cuadra.
type Finding struct {
	Status Status `json:"status"`
	// Index va SIEMPRE, sin omitempty: el bloque 0 es un bloque como los demás y
	// con omitempty un hallazgo sobre el primer registro del ledger salía sin
	// índice. Quien lee el informe no puede distinguir "índice 0" de "no me lo
	// dijeron", y el primer registro es justo el que más ejemplos tienen delante.
	Index uint64 `json:"index"`
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
	// Reason dice por qué un evento de supresión no está autorizado. Solo va en ese
	// estado.
	Reason string `json:"reason,omitempty"`
}

// Autoria dice qué clave de la política autorizó un evento de supresión (ADR-033 §C).
type Autoria struct {
	// AuthorizedBy es el miembro de la política que trae la clave: "erasureKey" o
	// "retiredErasureKeys".
	AuthorizedBy string `json:"authorized_by"`
	// ErasureKey es la clave, en hexadecimal.
	ErasureKey string `json:"erasure_key"`
	// Cutoff es su corte, si es una clave retirada; no va si es la actual.
	Cutoff *uint64 `json:"cutoff,omitempty"`
}

func autoria(v erasure.Verdict) Autoria {
	if !v.Retired {
		return Autoria{AuthorizedBy: "erasureKey", ErasureKey: v.Key}
	}
	c := v.Cutoff
	return Autoria{AuthorizedBy: "retiredErasureKeys", ErasureKey: v.Key, Cutoff: &c}
}

// Describe dice la clave en una frase, para el texto.
func (a Autoria) Describe() string {
	if a.Cutoff == nil {
		return "la clave actual (erasureKey " + a.ErasureKey + ")"
	}
	return fmt.Sprintf("la clave retirada %s, cuyo corte es el índice %d", a.ErasureKey, *a.Cutoff)
}

// Erased es un bloque cuyo contenido se suprimió.
type Erased struct {
	// Index es el bloque cuyo contenido se suprimió.
	Index uint64 `json:"index"`
	// SealedHash es su payload_hash, que sigue en la cadena.
	SealedHash string `json:"sealed_hash"`
	// SealedAt es su tiempo declarado.
	SealedAt string `json:"sealed_at"`
	// ErasedBy es el bloque del evento de supresión.
	ErasedBy uint64 `json:"erased_by"`
	// ErasedAt es el tiempo declarado del evento.
	ErasedAt string `json:"erased_at"`
	// La clave que autorizó el evento ErasedBy.
	Autoria
}

// Regularized es un evento de supresión que no estaba autorizado y que otro posterior,
// autorizado, regularizó (ADR-033, decisión 4; PROTOCOL 0.8-draft §5.1). No es un
// hallazgo, y tampoco desaparece: sale en cada reconciliación, para siempre, porque el
// evento sigue en la cadena y quien audite tiene que verlo.
type Regularized struct {
	// Index es el bloque del evento no autorizado.
	Index uint64 `json:"index"`
	// SealedHash es su payload_hash.
	SealedHash string `json:"sealed_hash"`
	// SealedAt es su tiempo declarado.
	SealedAt string `json:"sealed_at"`
	// RegularizedBy es el bloque del evento autorizado que lo regulariza: el de menor
	// índice, si hay varios.
	RegularizedBy uint64 `json:"regularized_by"`
	// Reason es por qué el evento Index no estaba autorizado.
	Reason string `json:"reason"`
	// La clave que autorizó el evento RegularizedBy.
	Autoria
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
	// Erased son los bloques que el sistema vivo ya no tiene porque su contenido se
	// suprimió (ADR-031). No son hallazgos: hay un evento sellado que lo dice, y la
	// clave de supresión de la política lo autorizó (ADR-032).
	Erased []Erased `json:"erased"`
	// Regularized son los eventos de supresión no autorizados que uno posterior, autorizado,
	// regularizó. Van siempre, vacíos si no hay ninguno, como Findings y Erased.
	Regularized []Regularized `json:"regularized"`
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

	// Erasure es el origin y la clave de supresión de la política (ADR-032). Un evento
	// de supresión solo cuenta si su autorización verifica con ella; sin ella —sin
	// política, o con una política sin erasureKey— ninguno cuenta, y todos son
	// hallazgos.
	Erasure erasure.Authority
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

	// Findings arranca como una lista VACÍA, no nil. La diferencia solo se ve al
	// serializar: una lista nil se convierte en `null` y una vacía en `[]`, y el
	// contrato de docs/CLI-JSON.md promete un array. Un consumidor estricto
	// (ADR-025) que lo lea como array se rompería justo en el caso bueno —el cotejo
	// que cuadra— si esto fuera nil.
	rep := &Report{TreeSize: uint64(n), Findings: []Finding{}, Erased: []Erased{}, Regularized: []Regularized{}}

	// Los eventos de supresión, y cuáles están autorizados. Se leen del ledger firmado
	// y de la política, y de nada más: la reconciliación no abre el vault, y un
	// marcador fuera de la cadena lo podría poner cualquiera que escriba el fichero.
	autorizados, noAutorizados, regularizados := clasificaEventos(blocks, opts.Erasure)
	rep.Regularized = append(rep.Regularized, regularizados...)
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
		// Los eventos de supresión los sella Núcleo, no el sistema vivo: no le faltan.
		if b.Header.Type == erasure.Type {
			continue
		}
		if a := eventoQueSuprime(autorizados, b); a != nil {
			rep.Erased = append(rep.Erased, Erased{
				Index:      b.Header.Index,
				SealedHash: b.Header.PayloadHash,
				SealedAt:   b.Header.Timestamp,
				ErasedBy:   a.evento.Header.Index,
				ErasedAt:   a.evento.Header.Timestamp,
				Autoria:    autoria(a.veredicto),
			})
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
	rep.Findings = append(rep.Findings, noAutorizados...)
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

// autorizacion es un evento de supresión autorizado: cubre los bloques de su
// contenido con índice ≤ through.
type autorizacion struct {
	evento    *ledger.Block
	through   uint64
	veredicto erasure.Verdict
}

// clasificaEventos aplica PROTOCOL §5.1: devuelve los eventos autorizados, por el
// contenido que suprimen; un hallazgo por cada evento que no lo está y nadie regularizó;
// y los regularizados.
//
// El contenido de un evento no está en la cadena —se sella con su hash—, así que se
// busca entre los bloques anteriores: el que, puesto en el evento, da su payload_hash.
//
// Va en dos pasadas, porque quien regulariza un evento es POSTERIOR a él: primero se
// decide cada evento como siempre (autorizado o no, ADR-032 y ADR-033 §C); después, cada
// no autorizado que suprime un contenido sellado antes se coteja con los autorizados.
func clasificaEventos(blocks []*ledger.Block, auth erasure.Authority) (map[string][]autorizacion, []Finding, []Regularized) {
	// copias guarda, por el payload_hash que tendría su evento, el contenido y el ÚLTIMO
	// bloque que lo selló hasta el punto del recorrido. Para la condición 4 de la
	// regularización hace falta el máximo índice de las copias anteriores al evento, no
	// el primero: un contenido sellado dos veces, con una autorización que solo cubre la
	// primera copia, no regulariza la supresión de las dos.
	type contenido struct {
		hash   string
		ultima uint64
	}
	copias := map[string]contenido{}
	type evento struct {
		b *ledger.Block
		// hash es el contenido que suprime y maxAntes, el último bloque con ese contenido
		// anterior al evento; ok dice si lo hay (la condición 2 de §5.1).
		hash     string
		maxAntes uint64
		ok       bool
		err      error
	}
	var eventos []evento
	autorizados := map[string][]autorizacion{}
	for _, b := range blocks {
		if b.Header.Type != erasure.Type {
			if eph, err := erasure.EventPayloadHash(b.Header.PayloadHash); err == nil {
				copias[eph] = contenido{hash: b.Header.PayloadHash, ultima: b.Header.Index}
			}
			continue
		}
		c, ok := copias[b.Header.PayloadHash]
		ev := evento{b: b, hash: c.hash, maxAntes: c.ultima, ok: ok && c.ultima < b.Header.Index}
		if !ev.ok {
			ev.err = fmt.Errorf("%w: no suprime ningún contenido anterior de la cadena", erasure.ErrNotAuthorized)
		} else {
			v, err := auth.Check(b, c.hash)
			if err == nil {
				autorizados[c.hash] = append(autorizados[c.hash], autorizacion{evento: b, through: v.Through, veredicto: v})
			}
			ev.err = err
		}
		eventos = append(eventos, ev)
	}

	var hallazgos []Finding
	var regularizados []Regularized
	for _, ev := range eventos {
		if ev.err == nil {
			continue
		}
		b := ev.b
		if ev.ok {
			if r := regulariza(autorizados[ev.hash], b.Header.Index, ev.maxAntes); r != nil {
				regularizados = append(regularizados, Regularized{
					Index:         b.Header.Index,
					SealedHash:    b.Header.PayloadHash,
					SealedAt:      b.Header.Timestamp,
					RegularizedBy: r.evento.Header.Index,
					Reason:        ev.err.Error(),
					Autoria:       autoria(r.veredicto),
				})
				continue
			}
		}
		hallazgos = append(hallazgos, Finding{
			Status:     StatusUnauthorizedErasure,
			Index:      b.Header.Index,
			SealedHash: b.Header.PayloadHash,
			SealedAt:   b.Header.Timestamp,
			Tenant:     b.Header.Tenant,
			Type:       b.Header.Type,
			Reason:     ev.err.Error(),
		})
	}
	return autorizados, hallazgos, regularizados
}

// regulariza busca, entre los eventos autorizados de un contenido —en orden de la
// cadena—, el primero que regulariza el evento no autorizado del índice e
// (ADR-033, decisión 4; PROTOCOL 0.8-draft §5.1). Que R esté en la lista ya es la
// condición 1 (autorizado, con las claves de SU índice) y la 3 (el mismo contenido, luego
// el mismo payload_hash). Quedan:
//
//   - la 2: R es posterior a E. Un evento sin autorización sellado después de una
//     supresión legítima sigue siendo el servidor sellando lo que nadie autorizó;
//   - la 4: el through de R llega a la última copia del contenido anterior a E. El
//     through de E no se usa: viene de una autorización que no vale.
func regulariza(autorizados []autorizacion, e, maxAntes uint64) *autorizacion {
	for i := range autorizados {
		r := &autorizados[i]
		if r.evento.Header.Index > e && r.through >= maxAntes {
			return r
		}
	}
	return nil
}

// eventoQueSuprime devuelve el primer evento autorizado que cubre a b, o nil. Lo cubre
// si su autorización llega hasta b (through ≥ b.index): una autorización anterior a b
// suprimió una copia anterior del mismo contenido, y b la volvió a sellar después. Como
// through es anterior al evento, el evento es posterior a b.
func eventoQueSuprime(autorizados map[string][]autorizacion, b *ledger.Block) *autorizacion {
	lista := autorizados[b.Header.PayloadHash]
	for i := range lista {
		if lista[i].through >= b.Header.Index {
			return &lista[i]
		}
	}
	return nil
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
