package main

import (
	"errors"
	"math/rand"
	"time"

	"github.com/nucleoledger/nucleo/internal/ledger"
	"github.com/nucleoledger/nucleo/internal/store"
)

// El sellado reintenta cuando otro proceso le gana la carrera.
//
// Sale del ensayo de operación del Sprint 10, escenario 6: dos workers de un ERP
// sellando a la vez contra el mismo ledger perdían UN TERCIO de los sellados. Dos
// motivos, los dos por lo mismo —el bloque se construye y se firma FUERA de la
// transacción, leyendo el último bloque antes—:
//
//   - SQLite en WAL devuelve BUSY inmediato cuando una transacción diferida intenta
//     escribir después de que otra haya confirmado; `busy_timeout` no reintenta eso. Se
//     arregla abriendo la transacción en modo `immediate` (ver internal/store).
//   - Y aun así, el bloque que acabamos de firmar puede haber dejado de seguir al
//     último: el otro proceso ya insertó el suyo. La comprobación de encadenamiento de
//     ADR-020 §C lo caza DENTRO de la transacción —que es lo correcto— y el sellado
//     falla con "índice fuera de secuencia".
//
// Lo segundo no se arregla con candados: se arregla volviendo a intentarlo, que es lo
// que haría a mano quien viera el error. Nada se ha escrito cuando falla, así que el
// reintento es seguro; y la clave de idempotencia se vuelve a mirar en cada intento, así
// que dos reintentos con la misma clave no duplican (ADR-020 §D).
const intentosDeSellado = 5

// sellarConReintentos ejecuta el intento hasta que deja de ser una carrera perdida.
func sellarConReintentos(intento func() error) error {
	var err error
	for i := 0; i < intentosDeSellado; i++ {
		err = intento()
		if err == nil || !esCarreraPerdida(err) {
			return err
		}
		// Espera corta y desigual: dos procesos que reintentan al mismo ritmo se
		// vuelven a chocar. El último intento espera unos 150 ms, que es más que de
		// sobra para un sellado que tarda 100.
		espera := time.Duration(5+rand.Intn(25)) * time.Millisecond * time.Duration(i+1)
		time.Sleep(espera)
	}
	return err
}

// esCarreraPerdida dice si el error es de los que un reintento arregla.
//
// La lista es corta a propósito: un ledger sin permisos, un disco lleno o un contenido
// que no descifra NO se arreglan reintentando, y reintentarlos solo retrasaría el
// mensaje que el operador necesita leer.
func esCarreraPerdida(err error) bool {
	return errors.Is(err, store.ErrBusy) ||
		errors.Is(err, ledger.ErrIndexSequence) ||
		errors.Is(err, ledger.ErrPrevHashMismatch)
}
