// nucleo es la CLI de Núcleo: el modo primario de uso según ADR-005.
//
// Se invoca por ejecución, sin daemon, para que funcione en el hosting
// compartido donde vive el parque de facturación al que apunta el proyecto.
//
// # Códigos de salida
//
// Están documentados porque un script los va a leer, y porque el 3 no es un
// error más: es un incidente operativo.
//
//	0  todo correcto
//	1  error de uso o de entrada (falta un argumento, no se puede leer un fichero)
//	2  LA VERIFICACIÓN FALLÓ: hay una alteración o una discrepancia
//	3  LA SINCRONIZACIÓN CON EL TESTIGO FALLÓ
//
// El 2 y el 3 se separan del 1 a propósito. Un 1 dice que la orden estaba mal
// dada; un 2 dice que los datos no cuadran con lo que se selló; un 3 dice que no
// se pudo obtener atestación, y si se repite hay que mirarlo, porque un testigo
// inalcanzable de forma sostenida es indistinguible de uno al que se está
// impidiendo hablar.
package main

import (
	"errors"
	"fmt"
	"os"
)

// Códigos de salida de la CLI.
const (
	exitOK       = 0
	exitUsage    = 1
	exitVerify   = 2
	exitSyncFail = 3
)

// exitError lleva el código con el que terminar.
type exitError struct {
	code int
	err  error
	// reported marca los resultados que el subcomando ya explicó por su cuenta.
	// Una reconciliación con hallazgos no es un fallo del programa: el cotejo
	// hizo su trabajo y ya imprimió qué encontró. Volver a soltar "error:"
	// encima haría parecer roto lo que funcionó.
	reported bool
}

func (e *exitError) Error() string { return e.err.Error() }
func (e *exitError) Unwrap() error { return e.err }

// usageErr, verifyErr y syncErr construyen errores con su código.
func usageErr(format string, args ...any) error {
	return &exitError{code: exitUsage, err: fmt.Errorf(format, args...)}
}

func verifyErr(format string, args ...any) error {
	return &exitError{code: exitVerify, err: fmt.Errorf(format, args...)}
}

func syncErr(format string, args ...any) error {
	return &exitError{code: exitSyncFail, err: fmt.Errorf(format, args...)}
}

// commands es la tabla de subcomandos.
var commands = map[string]func(*env, []string) error{
	"init":      cmdInit,
	"status":    cmdStatus,
	"verify":    cmdVerify,
	"seal":      cmdSeal,
	"receipt":   cmdReceipt,
	"reconcile": cmdReconcile,
	"sync":      cmdSync,
	"witness":   cmdWitness,
	"backup":    cmdBackup,
	"restore":   cmdRestore,
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run ejecuta la CLI y devuelve el código de salida. Está separado de main para
// que los tests puedan invocarla sin matar el proceso.
func run(args []string, stdout, stderr *os.File) int {
	e := &env{stdout: stdout, stderr: stderr}
	err := dispatch(e, args)
	if err == nil {
		return exitOK
	}
	code := exitUsage
	var ee *exitError
	if errors.As(err, &ee) {
		code = ee.code
	}
	reported := ee != nil && ee.reported
	if e.json {
		if !reported {
			e.printJSON(map[string]any{"ok": false, "error": err.Error(), "exit_code": code})
		}
	} else {
		if !reported {
			fmt.Fprintln(stderr, "error:", err)
		}
		if code == exitSyncFail {
			fmt.Fprintln(stderr)
			fmt.Fprintln(stderr, "  Esto es un INCIDENTE, no un aviso. Si se repite, alguien o algo")
			fmt.Fprintln(stderr, "  está impidiendo que el testigo vea este log, y sin testigo la")
			fmt.Fprintln(stderr, "  historia local no está garantizada. Revísalo.")
		}
	}
	return code
}
