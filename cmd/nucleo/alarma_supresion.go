package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/nucleoledger/nucleo/internal/erasure"
	"github.com/nucleoledger/nucleo/internal/ledger"
	"github.com/nucleoledger/nucleo/internal/store"
)

// La alarma de supresión (ADR-031, enmienda del Sprint 18).
//
// Una supresión es destructiva y excepcional, y aunque exija dos tarjetas, alguien
// tiene que enterarse de cada una. Así que cada supresión deja una alarma con el
// mecanismo de ADR-028 —viaja en el JSON de cada comando y la recogen los hooks de los
// SDK— que solo se calla cuando alguien la reconoce con `nucleo alert ack`.
//
// La diferencia con la alarma de frescura es de dónde sale. Las supresiones pendientes
// se DEDUCEN de la cadena: cada evento nucleo.erasure.v1 sin su reconocimiento en
// log_state está abierto. Borrar la tabla de reconocimientos, o la de detalles, no
// esconde ninguna supresión: la vuelve a abrir. Lo único que la cierra es un `alert ack`
// —que no pide passphrase, como en ADR-028: ver el límite en GARANTIAS—.

// Claves de log_state de la alarma de supresión. Van por el HASH del evento y no por su
// índice: un reconocimiento escrito por adelantado para un índice futuro no podría
// acertar el hash del bloque que todavía no existe.
const (
	// metaSupresionDetalle guarda lo que el evento no dice —qué contenido y qué bloques—,
	// escrito en la misma transacción que el evento.
	metaSupresionDetalle = "log/erasure/v1/"
	// metaSupresionAck guarda el reconocimiento de cada evento.
	metaSupresionAck = "log/erasure-ack/v1/"
)

// detalleSupresion es lo que se guarda bajo metaSupresionDetalle.
type detalleSupresion struct {
	ErasedPayloadHash string   `json:"erased_payload_hash"`
	Blocks            []uint64 `json:"blocks"`
}

// ackSupresion es lo que se guarda bajo metaSupresionAck.
type ackSupresion struct {
	AckedAt string `json:"acked_at"`
	AckedBy string `json:"acked_by,omitempty"`
}

// supresionAbierta es una supresión que nadie ha reconocido.
type supresionAbierta struct {
	Evento  *ledger.Block
	Detalle *detalleSupresion
}

// alertaSupresion es lo que un comando sabe de las supresiones sin reconocer.
type alertaSupresion struct {
	Abiertas []supresionAbierta
	// Leida es false si no se pudo leer el ledger: entonces no se sabe si hay alguna, y
	// se publica así en vez de decir «ninguna».
	Leida bool
}

// alarmaDeSupresion lee las supresiones sin reconocer. Como registraAlarma, nunca hace
// fallar al comando: si no puede leer, lo dice por stderr y lo publica.
func alarmaDeSupresion(e *env, s *store.Store) alertaSupresion {
	eventos, err := s.BlocksOfType(erasure.Type)
	if err != nil {
		avisoDeSupresion(e, err)
		return alertaSupresion{}
	}
	out := alertaSupresion{Leida: true}
	for _, ev := range eventos {
		_, err := s.State(metaSupresionAck + ev.Hash)
		if err == nil {
			continue
		}
		if !errors.Is(err, store.ErrNotFound) {
			avisoDeSupresion(e, err)
			return alertaSupresion{}
		}
		a := supresionAbierta{Evento: ev}
		if raw, err := s.State(metaSupresionDetalle + ev.Hash); err == nil {
			var d detalleSupresion
			if json.Unmarshal([]byte(raw), &d) == nil {
				a.Detalle = &d
			}
		}
		out.Abiertas = append(out.Abiertas, a)
	}
	if len(out.Abiertas) > 0 {
		fmt.Fprintf(e.stderr, "⚠ %d supresión(es) de contenido sin reconocer (la última, en el bloque %d).\n"+
			"  Alguien con dos tarjetas de respaldo suprimió contenido de este ledger. Si fue\n"+
			"  legítimo, `nucleo alert ack` lo deja reconocido; si nadie sabe nada, es un incidente.\n",
			len(out.Abiertas), out.Abiertas[len(out.Abiertas)-1].Evento.Header.Index)
	}
	return out
}

// reconoceSupresiones marca como reconocidas todas las abiertas y devuelve cuántas.
func reconoceSupresiones(s *store.Store, abiertas []supresionAbierta, por string) (int, error) {
	ack, err := marshalJSON(ackSupresion{AckedAt: now().UTC().Format(time.RFC3339), AckedBy: por})
	if err != nil {
		return 0, err
	}
	for i, a := range abiertas {
		if err := s.PutState(metaSupresionAck+a.Evento.Hash, string(ack)); err != nil {
			return i, err
		}
	}
	return len(abiertas), nil
}

func avisoDeSupresion(e *env, err error) {
	fmt.Fprintf(e.stderr, "AVISO: no se pudo leer si hay supresiones sin reconocer: %v\n", err)
}

// json es el objeto "erasure_alert" de la salida para máquinas (docs/CLI-JSON.md).
func (a alertaSupresion) json() map[string]any {
	abiertas := make([]map[string]any, 0, len(a.Abiertas))
	for _, x := range a.Abiertas {
		m := map[string]any{
			"index":     x.Evento.Header.Index,
			"hash":      x.Evento.Hash,
			"erased_at": x.Evento.Header.Timestamp,
		}
		if x.Detalle != nil {
			m["erased_payload_hash"] = x.Detalle.ErasedPayloadHash
			m["blocks"] = x.Detalle.Blocks
		}
		abiertas = append(abiertas, m)
	}
	estado := alarmaNinguna
	if len(abiertas) > 0 {
		estado = alarmaAbierta
	}
	return map[string]any{
		"state":     estado,
		"persisted": a.Leida,
		"open":      abiertas,
	}
}
