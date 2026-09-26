package main

import (
	"fmt"
	"time"

	"github.com/nucleoledger/nucleo/internal/store"
)

// La alarma de frescura, durable (ADR-028).
//
// El aviso por stderr del Sprint 7 suponía un cron que manda stderr al correo. En el
// hosting real el cron termina en `> /dev/null 2>&1` y el ERP que llama a `seal` desde
// PHP tira stderr, así que la alarma sonaba donde no había nadie. Ahora, además, cada
// comando que juzga la frescura deja el veredicto en el ledger, y cualquier comando
// posterior —y el hook del SDK— lo ve.
//
// Toda la lógica vive aquí, en un sitio: seal, status, verify, reconcile, sync y
// `alert` llaman a registraAlarma y publican alerta.json(). Seis comandos decidiendo
// cada uno cuándo se abre o se cierra una alarma divergirían en dos sprints.

// Estados de la alarma, tal como salen en el JSON. Conjunto cerrado.
const (
	alarmaNinguna    = "none"
	alarmaAbierta    = "open"
	alarmaReconocida = "acked"
)

// alerta es lo que un comando sabe de la alarma después de juzgar la frescura.
type alerta struct {
	// Estado es "none", "open" o "acked".
	Estado string
	// Registro es la alarma guardada, si Estado no es "none".
	Registro store.StaleAlarm
	// Nueva es true solo en el comando que la abrió.
	Nueva bool
	// Guardada dice si lo que se publica es lo que hay en el ledger. Con false, la
	// alarma se vio pero no se pudo escribir —un fichero de solo lectura—, y el
	// integrador tiene que saberlo para no fiarse de la durabilidad.
	Guardada bool
}

// estadoDe traduce un registro guardado a su estado.
func estadoDe(a store.StaleAlarm) string {
	if a.AckedAt != "" {
		return alarmaReconocida
	}
	return alarmaAbierta
}

// registraAlarma aplica el veredicto de frescura a la alarma guardada: la abre si la
// atestación está vieja y no había ninguna, la conserva —con su reconocimiento— si ya
// la había, y la cierra si la atestación vuelve a estar fresca (ADR-028 §C).
//
// Nunca hace fallar al comando que la llama. Si no puede leer o escribir el ledger, lo
// dice por stderr y publica persisted:false: `status` sobre un fichero de solo lectura
// tiene que seguir contestando.
func registraAlarma(e *env, s *store.Store, st staleness) alerta {
	previa, hay, err := s.StaleAlarm()
	if err != nil {
		avisoDeAlarma(e, "leer", err)
		return alerta{Estado: alarmaNinguna, Guardada: false}
	}
	vieja := st.Stale && !st.Empty
	switch {
	case vieja && hay:
		return alerta{Estado: estadoDe(previa), Registro: previa, Guardada: true}

	case vieja:
		a := store.StaleAlarm{
			StaleSince:     staleSince(st).UTC().Format(time.RFC3339),
			EmittedAt:      now().UTC().Format(time.RFC3339),
			ThresholdHours: st.Threshold.Hours(),
			Reason:         motivoDeAlarma(st),
		}
		if err := s.PutStaleAlarm(a); err != nil {
			avisoDeAlarma(e, "guardar", err)
			return alerta{Estado: alarmaAbierta, Registro: a, Nueva: true, Guardada: false}
		}
		return alerta{Estado: alarmaAbierta, Registro: a, Nueva: true, Guardada: true}

	case hay && st.Future:
		// Con un reloj que va por detrás del testigo no se puede juzgar la frescura, así
		// que tampoco se puede dar la alarma por resuelta: se deja como estaba.
		return alerta{Estado: estadoDe(previa), Registro: previa, Guardada: true}

	case hay:
		return cierraAlarma(e, s, previa)

	default:
		return alerta{Estado: alarmaNinguna, Guardada: true}
	}
}

// cierraAlarma borra una alarma que ha dejado de tener motivo.
func cierraAlarma(e *env, s *store.Store, previa store.StaleAlarm) alerta {
	if err := s.ClearStaleAlarm(); err != nil {
		avisoDeAlarma(e, "cerrar", err)
		return alerta{Estado: estadoDe(previa), Registro: previa, Guardada: false}
	}
	return alerta{Estado: alarmaNinguna, Guardada: true}
}

// leeAlarma publica la alarma tal como está, sin juzgar nada: para `sync`, cuya
// apertura es anterior al contacto con el testigo y no sirve para decidir.
func leeAlarma(e *env, s *store.Store) alerta {
	a, hay, err := s.StaleAlarm()
	if err != nil {
		avisoDeAlarma(e, "leer", err)
		return alerta{Estado: alarmaNinguna, Guardada: false}
	}
	if !hay {
		return alerta{Estado: alarmaNinguna, Guardada: true}
	}
	return alerta{Estado: estadoDe(a), Registro: a, Guardada: true}
}

// staleSince es desde cuándo está vieja: la última atestación que cuenta más el umbral.
// Sin ninguna que cuente, no hay un instante mejor que el de ahora.
func staleSince(st staleness) time.Time {
	if st.Known {
		return st.Record.At.Add(st.Threshold)
	}
	return now()
}

// motivoDeAlarma dice por qué, con los tres casos que distingue checkStaleness.
func motivoDeAlarma(st staleness) string {
	switch {
	case st.Known:
		return "age"
	case st.Policy:
		return "no_attestation_under_policy"
	default:
		return "never_attested"
	}
}

func avisoDeAlarma(e *env, que string, err error) {
	fmt.Fprintf(e.stderr, "AVISO: no se pudo %s la alarma de frescura en el ledger: %v\n"+
		"       La alarma se ha visto pero no dura: el siguiente comando no la encontrará.\n", que, err)
}

// json es el objeto "alert" de la salida para máquinas (docs/CLI-JSON.md).
func (a alerta) json() map[string]any {
	out := map[string]any{
		"state":     a.Estado,
		"new":       a.Nueva,
		"persisted": a.Guardada,
	}
	if a.Estado == alarmaNinguna {
		return out
	}
	out["stale_since"] = a.Registro.StaleSince
	out["alert_emitted_at"] = a.Registro.EmittedAt
	out["threshold_hours"] = a.Registro.ThresholdHours
	out["reason"] = a.Registro.Reason
	if a.Registro.AckedAt != "" {
		out["alert_acked_at"] = a.Registro.AckedAt
		if a.Registro.AckedBy != "" {
			out["acked_by"] = a.Registro.AckedBy
		}
	}
	return out
}

// printAlerta es la línea de la salida para personas.
func printAlerta(e *env, a alerta) {
	switch a.Estado {
	case alarmaAbierta:
		e.printf("alarma    : ✘ ABIERTA, sin reconocer: la atestación está vieja desde %s\n", a.Registro.StaleSince)
		e.printf("            Registrada el %s. Se cierra sola con el próximo `nucleo sync` que\n", a.Registro.EmittedAt)
		e.printf("            salga bien; `nucleo alert ack` dice que alguien se ha enterado.\n")
	case alarmaReconocida:
		quien := ""
		if a.Registro.AckedBy != "" {
			quien = " por " + a.Registro.AckedBy
		}
		e.printf("alarma    : ◐ reconocida%s el %s; sigue abierta hasta que un `nucleo sync`\n", quien, a.Registro.AckedAt)
		e.printf("            salga bien (vieja desde %s)\n", a.Registro.StaleSince)
	}
	if !a.Guardada {
		e.printf("            (NO se pudo guardar en el ledger: ver el aviso de arriba)\n")
	}
}
