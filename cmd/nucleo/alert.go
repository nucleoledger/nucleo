package main

import (
	"errors"
	"flag"
	"time"
)

// cmdAlert es `nucleo alert status | ack` (ADR-028 §C).
//
// status enseña la alarma de frescura —y, como cualquier comando que juzga la
// frescura, la abre o la cierra según el veredicto—. ack deja constancia de que
// alguien se ha enterado: no la cierra, porque lo que la cierra es una atestación
// fresca, y el hook del SDK deja de llamar.
func cmdAlert(e *env, args []string) error {
	if len(args) == 0 {
		return usageErr("uso: nucleo alert status [--exit-code] | nucleo alert ack [--by NOMBRE]")
	}
	switch args[0] {
	case "status":
		return cmdAlertStatus(e, args[1:])
	case "ack":
		return cmdAlertAck(e, args[1:])
	default:
		return usageErr("alert: subcomando desconocido %q; son `status` y `ack`", args[0])
	}
}

func cmdAlertStatus(e *env, args []string) error {
	fs := flag.NewFlagSet("alert status", flag.ContinueOnError)
	fs.SetOutput(e.stderr)
	pf := registerPolicyFlags(fs)
	exitCode := fs.Bool("exit-code", false, "sale con 3 si hay una alarma abierta sin reconocer, para scripts que no leen JSON")
	if err := fs.Parse(args); err != nil {
		return usageErr("%v", err)
	}
	wp, _, err := pf.resolve(e)
	if err != nil {
		return err
	}
	s, res, err := e.openStoreWith(wp)
	if err != nil {
		return err
	}
	defer s.Close()

	st, err := checkStaleness(s, res, wp != nil, now(), e.staleAfter, res.TreeSize)
	if err != nil {
		return err
	}
	alarma := registraAlarma(e, s, st)
	e.out(map[string]any{
		"alert":     alarma.json(),
		"freshness": st.json(),
	}, func() {
		if alarma.Estado == alarmaNinguna {
			e.printf("alarma    : ✔ ninguna abierta\n")
		}
		printAlerta(e, alarma)
		printFreshness(e, st)
	})

	// --exit-code es para quien vigila desde un script sin parsear JSON. Solo la alarma
	// abierta y SIN reconocer devuelve 3: una reconocida ya tiene a alguien encima, y
	// avisar otra vez es entrenar a la gente a ignorar el aviso.
	if *exitCode && alarma.Estado == alarmaAbierta {
		return &exitError{
			code:     exitSyncFail,
			err:      errors.New("hay una alarma de frescura abierta sin reconocer"),
			reported: true,
		}
	}
	return nil
}

func cmdAlertAck(e *env, args []string) error {
	fs := flag.NewFlagSet("alert ack", flag.ContinueOnError)
	fs.SetOutput(e.stderr)
	por := fs.String("by", "", "quién se ha enterado: queda anotado junto al reconocimiento")
	if err := fs.Parse(args); err != nil {
		return usageErr("%v", err)
	}
	// Sin política: reconocer no juzga nada, anota. Y no pide la passphrase, porque
	// log_state no se firma: quien opera el despliegue tiene que poder hacerlo desde
	// cualquier terminal, a las tres de la mañana, sin la tarjeta de respaldo.
	s, _, err := e.openStoreWith(nil)
	if err != nil {
		return err
	}
	defer s.Close()

	previa := leeAlarma(e, s)
	reconocida := false
	switch previa.Estado {
	case alarmaNinguna:
		// Nada que reconocer no es un error: un script que reconoce por si acaso tiene
		// que poder hacerlo sin distinguir el caso.
	case alarmaReconocida:
		// El primer reconocimiento es el que vale; repetirlo no lo reescribe.
	default:
		a := previa.Registro
		a.AckedAt = now().UTC().Format(time.RFC3339)
		a.AckedBy = *por
		if err := s.PutStaleAlarm(a); err != nil {
			return err
		}
		previa = alerta{Estado: alarmaReconocida, Registro: a, Guardada: true}
		reconocida = true
	}

	e.out(map[string]any{
		"acked": reconocida,
		"alert": previa.json(),
	}, func() {
		switch {
		case reconocida:
			e.printf("✔ alarma reconocida (vieja desde %s).\n", previa.Registro.StaleSince)
			e.printf("  El hook del SDK deja de avisar. La alarma sigue abierta hasta que un\n")
			e.printf("  `nucleo sync` salga bien, y entonces se cierra sola.\n")
		case previa.Estado == alarmaReconocida:
			e.printf("La alarma ya estaba reconocida el %s; no se cambia nada.\n", previa.Registro.AckedAt)
		default:
			e.printf("No hay ninguna alarma de frescura abierta: nada que reconocer.\n")
		}
	})
	return nil
}
