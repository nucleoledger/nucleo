package main

import (
	"fmt"
	"time"

	"github.com/nucleoledger/nucleo/internal/ledger"
)

// saltoSospechoso es el salto de reloj a partir del cual el sellado avisa.
//
// Un día. Por debajo, un reloj que corre adelantado es lo normal en máquinas sin NTP y
// no merece ruido; por encima, casi siempre es un salto —NTP que corrige de golpe, una
// VM clonada, un contenedor con la fecha de la imagen— y las consecuencias no son
// simétricas: un bloque con fecha futura BLOQUEA el sellado hasta esa fecha.
const saltoSospechoso = 24 * time.Hour

// relojCoherente compara el reloj de esta máquina con el último bloque sellado y
// traduce lo que encuentre a algo que un operador pueda arreglar.
//
// Los dos casos son del ensayo de operación del Sprint 10, escenario 7:
//
//   - El reloj se va ATRÁS —NTP mal, una VM restaurada— y el sellado fallaba con
//     "ledger: timestamp anterior al del bloque previo". Es exacto y no dice nada: quien
//     lo lee no sabe que el problema está en su reloj, ni que basta esperar o arreglar
//     la hora. El protocolo no puede ceder (PROTOCOL §1: los bloques no retroceden en el
//     tiempo), así que lo que se arregla es el mensaje.
//   - El reloj se va ADELANTE y el sellado funciona… y deja un bloque con fecha futura
//     que impide sellar hasta que el reloj la alcance. En el ensayo, un salto de un año
//     dejó el ledger sin poder sellar durante un año, y el mensaje que lo explicaba era
//     el mismo "timestamp anterior al del bloque previo". Eso ya no pasa callado: se
//     avisa ANTES de escribirlo, cuando todavía se puede parar con Ctrl-C.
func relojCoherente(e *env, prev *ledger.Block, h ledger.Header) error {
	if prev == nil {
		return nil
	}
	anterior, err := prev.Header.Time()
	if err != nil {
		return nil // un header ilegible es problema de la verificación, no del reloj
	}
	ahora, err := h.Time()
	if err != nil {
		return nil
	}

	if ahora.Before(anterior) {
		return usageErr("el reloj de esta máquina (%s) va POR DETRÁS del último bloque sellado (%s).\n"+
			"  Un bloque no puede llevar fecha anterior al anterior (PROTOCOL.md §1), así que no se\n"+
			"  puede sellar hasta que el reloj vuelva a su hora.\n"+
			"  Qué mirar: el reloj del sistema y NTP. Si la máquina se restauró desde una copia o\n"+
			"  una instantánea, es lo primero que se descoloca.\n"+
			"  Si el que está mal es el bloque —porque un salto de reloj lo escribió con fecha\n"+
			"  futura—, no hay forma de reescribirlo: el ledger es append-only. Habría que esperar a\n"+
			"  esa fecha o empezar un ledger nuevo, y en los dos casos conviene decidirlo con calma.",
			ahora.UTC().Format(time.RFC3339), anterior.UTC().Format(time.RFC3339))
	}

	if salto := ahora.Sub(anterior); salto > saltoSospechoso {
		fmt.Fprintf(e.stderr,
			"AVISO: el reloj de esta máquina va %s por delante del último bloque (%s).\n"+
				"       El bloque que estás sellando llevará la fecha %s, y un bloque con fecha\n"+
				"       futura IMPIDE sellar hasta que el reloj la alcance: si esto es un salto de\n"+
				"       reloj y no el paso del tiempo, para aquí y arregla la hora primero.\n",
			humanDuration(salto), anterior.UTC().Format(time.RFC3339), ahora.UTC().Format(time.RFC3339))
	}
	return nil
}
