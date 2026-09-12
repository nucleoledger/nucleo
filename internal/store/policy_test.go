package store

import (
	"crypto/ed25519"
	"errors"
	"testing"
)

// TestOpenWithWitnessesRechazaPoliticaQueNoVerificaNada es el segundo hallazgo
// ALTO de la segunda auditoría adversarial: OpenWithWitnesses(path,
// WitnessPolicy{}) —la llamada más natural para un integrador distraído— y la
// variante con testigos y quórum 0 devolvían "verified" sobre un ledger forjado.
// Sin ninguna cosignature comprobada, se concedía el atajo de ADR-009.
//
// Se prueba sobre el ledger forjado de la primera auditoría (clave del log
// sustituida), que es exactamente el que una política vacía "verificaba".
func TestOpenWithWitnessesRechazaPoliticaQueNoVerificaNada(t *testing.T) {
	path, _ := forjarLedger(t, true)
	real := testWitnessPolicy(t)

	for nombre, wp := range map[string]WitnessPolicy{
		"la llamada ingenua: WitnessPolicy{}": {},
		"testigos reales, quórum 0":           {Witnesses: real.Witnesses, Quorum: 0},
		"quórum mayor que los testigos":       {Witnesses: real.Witnesses, Quorum: 2},
		"testigo con nombre vacío":            {Witnesses: map[string]ed25519.PublicKey{"": real.Witnesses["witness.example/w"]}, Quorum: 1},
		"testigo con clave corta":             {Witnesses: map[string]ed25519.PublicKey{"w": make([]byte, 31)}, Quorum: 1},
	} {
		t.Run(nombre, func(t *testing.T) {
			s, res, err := OpenWithWitnesses(path, wp)
			if err == nil {
				s.Close()
				t.Fatalf("EXPLOTADO: OpenWithWitnesses aceptó y devolvió %+v", res)
			}
			if !errors.Is(err, ErrPolicy) {
				t.Errorf("err = %v, want ErrPolicy: el rechazo tiene que ser de política, no de integridad", err)
			}
		})
	}

	// Control: la misma base con la política real sigue cayendo por integridad
	// —el bloque reescrito—, no por política.
	if _, _, err := OpenWithWitnesses(path, real); !errors.Is(err, ErrIntegrity) {
		t.Errorf("con política real: err = %v, want ErrIntegrity", err)
	}
}
