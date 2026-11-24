package void

import (
	"fmt"

	"github.com/nucleoledger/nucleo/internal/erasure"
	"github.com/nucleoledger/nucleo/internal/ledger"
)

// Las reglas de validez de PROTOCOL 0.9-draft §5.2 (ADR-035, decisión 5). Viven aquí, y
// no en la reconciliación, porque las usan dos: reconcile, para decidir qué anulaciones
// cuentan, y la CLI, para no sellar una segunda anulación de lo ya anulado. Dos
// implementaciones de la regla acabarían diciendo cosas distintas.

// Los motivos de cada regla, tal como los dice la reconciliación (y los vectores de
// testdata/vectors/void/reconcile.json).
const (
	MotivoR1 = "el payload_cid de la anulación no tiene la forma nucleo-void@v1:<índice>"
	MotivoR2 = "la anulación apunta a un bloque que no es anterior a ella"
	motivoR3 = "la anulación no corresponde al contenido del bloque %d"
	MotivoR4 = "no se anula un evento de Núcleo"
	MotivoR5 = "la anulación es de otro tenant que la emisión"
	// El de R6 lleva el índice de la emisión y el de la primera anulación.
	motivoR6 = "la emisión del bloque %d ya está anulada por el bloque %d"
)

// Valid es una anulación válida: Event anula Target.
type Valid struct {
	Event  *ledger.Block
	Target *ledger.Block
}

// Invalid es un evento de anulación que no cuenta, con la primera regla que incumple.
type Invalid struct {
	Event *ledger.Block
	// Rule es "R1" … "R6". "R6" es la anulación repetida; las demás, la inválida.
	Rule   string
	Reason string
	// FirstVoid es, solo con R6, el índice de la primera anulación válida de la emisión.
	FirstVoid uint64
}

// Result clasifica los eventos de anulación de una cadena, en el orden de la cadena.
type Result struct {
	Valid   []Valid
	Invalid []Invalid
}

// VoidOf devuelve la anulación válida del bloque index, o nil si no está anulado.
func (r Result) VoidOf(index uint64) *Valid {
	for i := range r.Valid {
		if r.Valid[i].Target.Header.Index == index {
			return &r.Valid[i]
		}
	}
	return nil
}

// Evaluate aplica R1–R6 a cada bloque de tipo Type. Las reglas se comprueban en orden y
// se informa la primera que falla. R6 solo mira anulaciones VÁLIDAS anteriores: una
// inválida no anula nada, así que no impide la válida que venga después.
func Evaluate(blocks []*ledger.Block) Result {
	porIndice := make(map[uint64]*ledger.Block, len(blocks))
	for _, b := range blocks {
		porIndice[b.Header.Index] = b
	}
	var res Result
	primera := map[uint64]uint64{} // emisión → índice de su primera anulación válida
	for _, v := range blocks {
		if v.Header.Type != Type {
			continue
		}
		mal := func(regla, motivo string) {
			res.Invalid = append(res.Invalid, Invalid{Event: v, Rule: regla, Reason: motivo})
		}
		i, err := ParseCID(v.Header.PayloadCID)
		if err != nil {
			mal("R1", MotivoR1)
			continue
		}
		if i >= v.Header.Index {
			mal("R2", MotivoR2)
			continue
		}
		b, ok := porIndice[i]
		if !ok {
			mal("R3", fmt.Sprintf(motivoR3, i))
			continue
		}
		if want, err := EventPayloadHash(i, b.Header.PayloadHash); err != nil || want != v.Header.PayloadHash {
			mal("R3", fmt.Sprintf(motivoR3, i))
			continue
		}
		if erasure.Reserved(b.Header.Type) {
			mal("R4", MotivoR4)
			continue
		}
		if b.Header.Tenant != v.Header.Tenant {
			mal("R5", MotivoR5)
			continue
		}
		if p, ya := primera[i]; ya {
			res.Invalid = append(res.Invalid, Invalid{Event: v, Rule: "R6",
				Reason: fmt.Sprintf(motivoR6, i, p), FirstVoid: p})
			continue
		}
		primera[i] = v.Header.Index
		res.Valid = append(res.Valid, Valid{Event: v, Target: b})
	}
	return res
}
