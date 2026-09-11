package main

import (
	"fmt"
	"time"

	"github.com/nucleoledger/nucleo/internal/store"
)

// DefaultStaleAfter es el umbral por omisión: 72 horas.
//
// Tres días es un compromiso deliberado entre dos errores. Más corto y un
// despliegue que sincroniza a diario dispararía la alarma cada fin de semana
// largo, con lo que la gente aprendería a ignorarla —y una alarma que se ignora
// es peor que no tenerla—. Más largo y una atestación puede estar muerta media
// semana sin que nadie se entere, que es justo el agujero operativo que la
// revisión externa señaló: "sin sync con alarma, el sistema abre bonito y no
// atestado… si alguien mira status. Nadie mira status".
//
// No es un número con fundamento criptográfico y no pretende serlo: es una
// decisión de operación, y por eso se puede cambiar con --stale-after.
const DefaultStaleAfter = 72 * time.Hour

// staleness es el veredicto sobre la frescura de la atestación.
type staleness struct {
	// Known es false cuando este despliegue nunca obtuvo una atestación
	// verificada. Es el caso MÁS grave, no la ausencia de información.
	Known bool
	// Record es el registro guardado, si Known.
	Record store.AttestationRecord
	// Age es lo que ha pasado desde el instante que afirmó el testigo.
	Age time.Duration
	// Threshold es el umbral con el que se juzgó.
	Threshold time.Duration
	// Stale es el veredicto: hay que avisar.
	Stale bool
	// Future es true si el instante atestiguado está en el futuro respecto al
	// reloj local. No es un ataque: lo normal es un reloj mal puesto en una de
	// las dos máquinas. Pero se dice, porque silenciarlo convertiría un reloj
	// roto en una atestación eternamente fresca.
	Future bool
	// Empty es true cuando el ledger no tiene ni un bloque.
	//
	// Con cero bloques no hay nada que atestiguar, así que avisar sería gritar
	// por algo que no existe. Y eso tiene un coste real: el primer `status` de
	// quien acaba de instalar esto saldría con una alarma, aprendería en ese
	// mismo momento que las alarmas de este programa se pueden ignorar, y para
	// cuando la alarma importe ya estará entrenado para no leerla.
	Empty bool
}

// checkStaleness juzga la frescura de la última atestación verificada.
//
// Usa el instante que afirmó el TESTIGO, no el reloj local del momento en que se
// guardó. Los dos están en el registro y la diferencia importa: el reloj local
// es el de la máquina que podría querer que la alarma no suene.
func checkStaleness(s *store.Store, now time.Time, threshold time.Duration, treeSize uint64) (staleness, error) {
	out := staleness{Threshold: threshold, Empty: treeSize == 0}
	r, ok, err := s.LastAttested()
	if err != nil {
		return out, err
	}
	if !ok {
		// Sin registro, el veredicto es "viejo". Un despliegue que nunca obtuvo
		// atestación está exactamente igual de desamparado que uno cuya última
		// atestación es de hace un año, y tratar la ausencia como "sin datos,
		// mejor callar" sería dejar en silencio el peor de los dos casos.
		out.Stale = true
		return out, nil
	}
	out.Known = true
	out.Record = r
	out.Age = now.Sub(r.At)
	if out.Age < 0 {
		out.Future = true
		out.Age = 0
	}
	out.Stale = out.Age > threshold
	return out, nil
}

// json devuelve los campos que van a la salida para máquinas.
//
// Van en un objeto propio y no sueltos porque quien automatiza esto lo hace en un
// cron: lo que necesita es poder leer un booleano sin parsear prosa.
func (st staleness) json() map[string]any {
	out := map[string]any{
		// Con el ledger vacío, stale se reporta como false: no hay historia que
		// pueda estar desamparada. El campo está igualmente para que quien
		// automatice no tenga que distinguir el caso.
		"stale":           st.Stale && !st.Empty,
		"threshold_hours": st.Threshold.Hours(),
		"attested_ever":   st.Known,
	}
	if st.Known {
		out["attested_at"] = st.Record.At.Format(time.RFC3339)
		out["attested_size"] = st.Record.Size
		out["witness"] = st.Record.Witness
		out["age_hours"] = st.Age.Hours()
		out["recorded_at"] = st.Record.RecordedAt.Format(time.RFC3339)
		if st.Future {
			out["clock_skew"] = true
		}
	}
	return out
}

// warn escribe el aviso en STDERR si procede, y dice si escribió algo.
//
// Va a stderr a propósito, y también en modo --json: es la única forma de que un
// cron que redirige stdout a un fichero y stderr al correo del administrador
// haga sonar la alarma sin que nadie haya tenido que programar nada. Un campo en
// el JSON que nadie lee no es una alarma; es un dato.
func (st staleness) warn(e *env) bool {
	if st.Empty || (!st.Stale && !st.Future) {
		return false
	}
	if st.Future {
		fmt.Fprintf(e.stderr,
			"AVISO: la última atestación dice ser del futuro (%s, reloj local %s).\n"+
				"       Uno de los dos relojes está mal puesto. Mientras siga así, la\n"+
				"       comprobación de frescura no significa nada.\n",
			st.Record.At.Format(time.RFC3339), now().UTC().Format(time.RFC3339))
		if !st.Stale {
			return true
		}
	}
	if !st.Known {
		fmt.Fprintf(e.stderr,
			"AVISO: este ledger NUNCA ha obtenido una atestación verificada.\n"+
				"       Que la cadena sea localmente válida no dice que esté completa: un\n"+
				"       prefijo truncado es indistinguible de la historia entera mientras\n"+
				"       nadie de fuera haya visto una raíz. Ejecuta `nucleo sync`.\n")
		return true
	}
	fmt.Fprintf(e.stderr,
		"AVISO: la última atestación verificada es de hace %s (umbral: %s).\n"+
			"       %s la firmó el %s, cubriendo %d bloques. Desde entonces, lo\n"+
			"       que respalda esta historia es solo este disco.\n"+
			"       Si hay un `nucleo sync` en el cron, probablemente lleva %s roto.\n",
		humanDuration(st.Age), humanDuration(st.Threshold),
		st.Record.Witness, st.Record.At.Format(time.RFC3339), st.Record.Size,
		humanDuration(st.Age))
	return true
}

// humanDuration redondea a algo que una persona lea de un vistazo. Un aviso que
// dice "72h3m17.4s" obliga a hacer cuentas justo cuando hay prisa.
func humanDuration(d time.Duration) string {
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%d segundos", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%d minutos", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%d horas", int(d.Hours()))
	default:
		return fmt.Sprintf("%d días", int(d.Hours()/24))
	}
}
