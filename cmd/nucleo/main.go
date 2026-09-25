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

	"github.com/nucleoledger/nucleo/internal/ledger"
	"github.com/nucleoledger/nucleo/internal/store"
	"github.com/nucleoledger/nucleo/internal/vault"
)

// Códigos de salida de la CLI.
const (
	exitOK       = 0
	exitUsage    = 1
	exitVerify   = 2
	exitSyncFail = 3
)

// Clases del error en la salida JSON (ADR-027).
//
// El código de salida dice EN QUÉ salió mal; la clase dice QUÉ CLASE DE PROBLEMA
// es, que es lo que un programa necesita para decidir. Son ortogonales: un
// código 1 puede ser una bandera mal escrita (usage) o un recibo que todavía no
// se puede emitir porque ningún testigo cubrió el bloque (transient), y lo que
// hay que hacer con cada uno es opuesto.
//
// Cuatro valores y nada más. La lista cerrada es la mitad del contrato: un
// consumidor puede rechazar lo que no conozca en vez de interpretarlo a la baja.
const (
	// claseUso: lo que se pidió no se puede pedir así. No se reintenta.
	claseUso = "usage"
	// claseTransitoria: se resuelve sola o con un reintento.
	claseTransitoria = "transient"
	// claseEntorno: el despliegue está roto y lo arregla una persona.
	claseEntorno = "environment"
	// claseIntegridad: la verificación falló. Es un incidente.
	claseIntegridad = "integrity"
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
	// class es la clase del error (ADR-027), cuando el subcomando la sabe mejor
	// que la regla general. Vacía significa "decídela por la cadena o por el
	// código", que es lo que hace claseDelError.
	class string
}

// conClase marca un error con su clase. Devuelve el mismo error para poder
// escribir `return usageErr(...).conClase(claseTransitoria)` en una línea.
func (e *exitError) conClase(clase string) *exitError {
	e.class = clase
	return e
}

func (e *exitError) Error() string { return e.err.Error() }
func (e *exitError) Unwrap() error { return e.err }

// usageErr, verifyErr y syncErr construyen errores con su código.
//
// Devuelven *exitError y no error para poder encadenar `.conClase(...)` en el
// mismo return (ADR-027). Nunca devuelven nil, que es la única forma de que un
// puntero tipado como error engañe a una comparación.
func usageErr(format string, args ...any) *exitError {
	return &exitError{code: exitUsage, err: fmt.Errorf(format, args...)}
}

func verifyErr(format string, args ...any) *exitError {
	return &exitError{code: exitVerify, err: fmt.Errorf(format, args...)}
}

func syncErr(format string, args ...any) *exitError {
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
			e.printJSON(map[string]any{
				"ok":        false,
				"error":     err.Error(),
				"exit_code": code,
				// ADR-027: la clase va en el JSON y NO en la salida para personas.
				// A una persona se le dice qué hacer en su idioma; "[transient]"
				// sería jerga del motor llegando al usuario (ADR-020 §E).
				"error_class": claseDelError(err, code),
			})
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

// claseDelError decide la clase del error, en un solo sitio (ADR-027 §D).
//
// Tres reglas, en este orden:
//
//  1. la clase EXPLÍCITA que puso el subcomando, porque es el único que sabe que
//     un recibo sin checkpoint se arregla sincronizando;
//  2. los centinelas que ya existen en internal/: los creó el Sprint 10 para que
//     el mensaje dijera qué comprobar, y describen exactamente el mismo hecho;
//  3. el código de salida, que es el comportamiento de siempre.
//
// Un único lugar que clasifica es la diferencia entre un contrato y una costumbre:
// noventa sitios eligiendo por su cuenta divergen en tres sprints.
func claseDelError(err error, code int) string {
	var ee *exitError
	if errors.As(err, &ee) && ee.class != "" {
		return ee.class
	}

	switch {
	// Otro proceso tiene el ledger tomado: el reintento es la respuesta correcta.
	case errors.Is(err, store.ErrBusy):
		return claseTransitoria
	// El disco, los permisos y la E/S: no hay reintento que los arregle.
	case errors.Is(err, store.ErrReadOnly),
		errors.Is(err, store.ErrDiskFull),
		errors.Is(err, store.ErrIO),
		errors.Is(err, store.ErrInternalDB):
		return claseEntorno
	// Un ledger de otra regla de hoja —uno de v0.1.0-alpha abierto con este
	// binario— tampoco es un error de la llamada: la llamada está bien y el
	// ledger es de otra versión. Lo arregla una persona, eligiendo el binario
	// que corresponde o empezando un ledger nuevo (PROTOCOL.md §2.1). Salió al
	// preparar v0.2.0-alpha, abriendo un ledger real de v0.1.0-alpha.
	case errors.Is(err, store.ErrLeafRule):
		return claseEntorno
	// El fichero no es un ledger, o la cadena no encaja: eso es integridad,
	// aunque llegue por el camino de un error de apertura.
	case errors.Is(err, store.ErrNotALedger),
		errors.Is(err, ledger.ErrPrevHashMismatch),
		errors.Is(err, ledger.ErrIndexSequence),
		errors.Is(err, ledger.ErrUnexpectedSigner):
		return claseIntegridad
	// La passphrase no abre este vault: la entrada estaba mal, y repetirla da lo
	// mismo. Es uso, no entorno.
	case errors.Is(err, vault.ErrUnwrap):
		return claseUso
	}

	switch code {
	case exitVerify:
		return claseIntegridad
	case exitSyncFail:
		return claseTransitoria
	default:
		return claseUso
	}
}
