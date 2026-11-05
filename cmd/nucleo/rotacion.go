package main

import (
	"encoding/json"

	"github.com/nucleoledger/nucleo/internal/policy"
	"github.com/nucleoledger/nucleo/internal/reconcile"
	"github.com/nucleoledger/nucleo/internal/store"
)

// rotacionSupresion es el fragmento de retiredErasureKeys que sync imprime para rotar la
// clave de supresión (ADR-033, decisión 3): sin `erasure-key rotate`, la política nueva se
// escribe a mano, pero nadie calcula el corte a ojo.
type rotacionSupresion struct {
	// Retired es el valor que la política nueva tiene que llevar en retiredErasureKeys: la
	// erasureKey actual con su corte —si autorizó algo dentro de lo atestiguado— y las que
	// el fichero ya retiraba, con sus cortes de siempre. Vacío si no hay ninguna: entonces
	// la política nueva no lleva el miembro (un objeto vacío es inválido, PROTOCOL §3.2).
	Retired map[string]uint64 `json:"retiredErasureKeys"`
	// AttestedSize es el tamaño del checkpoint que este sync acaba de atestiguar: el corte
	// es un índice menor que él.
	AttestedSize uint64 `json:"attested_size"`

	actual     string // la erasureKey del fichero
	corte      uint64
	hayActual  bool // la clave actual autorizó algún evento dentro de lo atestiguado
	yaRetirada int  // cuántas traía el fichero
}

// fragmentoDeRotacion calcula el fragmento con la política f, cuya erasureKey no está
// vacía, sobre los attested primeros bloques del ledger. El corte de la clave actual es el
// mayor índice de un evento nucleo.erasure.v1 que ella autoriza (PROTOCOL §5.1) dentro del
// checkpoint atestiguado: por construcción, nunca queda por encima de lo atestiguado, que
// es la condición de ADR-033 §B y §D.
func fragmentoDeRotacion(s *store.Store, f *policy.File, attested uint64) (*rotacionSupresion, error) {
	r := &rotacionSupresion{Retired: map[string]uint64{}, AttestedSize: attested, actual: f.ErasureKey,
		yaRetirada: len(f.RetiredErasureKeys)}
	for k, c := range f.RetiredErasureKeys {
		r.Retired[k] = c
	}
	if attested > 0 {
		blocks, err := s.Blocks(0, attested)
		if err != nil {
			return nil, err
		}
		for _, ev := range reconcile.AuthorizedEvents(blocks, f.ErasureAuthority()) {
			if !ev.Verdict.Retired && ev.Verdict.Key == f.ErasureKey {
				r.corte, r.hayActual = ev.Index, true
			}
		}
	}
	if r.hayActual {
		r.Retired[f.ErasureKey] = r.corte
	}
	return r, nil
}

// imprime escribe el fragmento para personas, listo para pegar en el JSON de la política.
func (r *rotacionSupresion) imprime(e *env) {
	linea := func() {
		raw, _ := json.Marshal(r.Retired) // un map de claves ordena sus miembros
		e.printf("    \"retiredErasureKeys\": %s\n", raw)
	}
	e.printf("\n")
	if r.hayActual {
		e.printf("  Si rotas la clave de supresión, la política nueva lleva, además de la erasureKey nueva:\n")
		linea()
		e.printf("  El corte de la clave actual, %d, es el último evento que autorizó dentro de los %d\n", r.corte, r.AttestedSize)
		e.printf("  bloques que el testigo acaba de atestiguar (ADR-033).\n")
		return
	}
	e.printf("  Ninguna supresión autorizada con la clave actual está atestiguada: al rotarla no hace\n")
	e.printf("  falta retiredErasureKeys para ella.\n")
	if r.yaRetirada > 0 {
		e.printf("  La política nueva sigue llevando las que esta ya retiraba:\n")
		linea()
	}
}
