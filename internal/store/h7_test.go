package store

import (
	"errors"
	"testing"
)

// TestH7NoPoderCompararNoEsCompararBien es el H7 de la auditoría externa.
//
// La comparación de identidad —origin y clave del log de la política contra lo que el
// ledger declara en vault_meta— se OMITÍA cuando faltaban los metadatos, y omitirla
// devolvía nil: "no pude comparar" contado como "la comparación no presenta problema".
// Es el patrón que ADR-016 cerró en la atestación, en otro sitio.
//
// Lo que lo hace explotable y no teórico: vault_meta es MUTABLE por diseño —no lleva los
// disparadores append-only del ledger, porque guarda parámetros de derivación que
// cambian—, así que quien pueda escribir el fichero puede BORRAR esas dos filas. Y
// borrarlas no degradaba el veredicto: lo silenciaba.
func TestH7NoPoderCompararNoEsCompararBien(t *testing.T) {
	otraClave, _ := testKeys(t, 42)

	// La política de la víctima: su origin y su clave del log. Es la que un cron
	// tendría escrita en un fichero desde el primer día.
	politicaVictima := func(t *testing.T) WitnessPolicy {
		wp := testWitnessPolicy(t)
		wp.Origin = testOrigin
		wp.LogKey = func() []byte { k, _ := testKeys(t, 7); return k }()
		return wp
	}

	t.Run("control: la identidad declarada y correcta abre", func(t *testing.T) {
		path := seedAttested(t, 5, 5)
		s, _, err := OpenWithWitnesses(path, politicaVictima(t))
		if err != nil {
			t.Fatalf("la identidad correcta debería abrir: %v", err)
		}
		s.Close()
	})

	t.Run("control: la identidad declarada y distinta se rechaza", func(t *testing.T) {
		path := seedAttested(t, 5, 5)
		wp := politicaVictima(t)
		wp.LogKey = otraClave
		if _, _, err := OpenWithWitnesses(path, wp); !errors.Is(err, ErrLogKeyMismatch) {
			t.Errorf("err = %v, want ErrLogKeyMismatch", err)
		}
	})

	// Y el hallazgo: el atacante borra las filas y la comprobación deja de existir.
	//
	// Comprobado quitando el arreglo y volviendo a correr esto, que es lo único que dice
	// si un test prueba algo: SIN la clave del log —y sin las dos— el ledger abría con la
	// identidad de otro log y sin un solo error. Borrar SOLO el origin no era explotable:
	// la comparación de la clave, que sí podía hacerse, seguía cazando la política ajena.
	// El agujero era la clave, y el origin entra aquí por el mismo motivo —una pregunta
	// que no se puede contestar no se contesta con silencio—, no porque se explotara.
	for nombre, claves := range map[string][]string{
		"sin la clave del log":   {MetaLogPubKey},
		"sin el origin":          {MetaOriginKey},
		"sin ninguna de las dos": {MetaLogPubKey, MetaOriginKey},
	} {
		t.Run(nombre, func(t *testing.T) {
			// Sin checkpoints: es el caso peor, porque con ellos la atestación al menos
			// degrada a "presente, no verificada". Sin ellos no quedaba ninguna señal.
			path := seedAttested(t, 5, 0)
			s, _, err := Open(path)
			if err != nil {
				t.Fatal(err)
			}
			for _, k := range claves {
				if _, err := s.db.Exec(`DELETE FROM vault_meta WHERE k = ?`, k); err != nil {
					t.Fatal(err)
				}
			}
			s.Close()

			wp := politicaVictima(t)
			wp.LogKey = otraClave // la política afirma una identidad AJENA
			s, res, err := OpenWithWitnesses(path, wp)
			if err == nil {
				s.Close()
				t.Fatalf("EXPLOTADO: el ledger abrió con la identidad de otro log porque no se podía comparar: %+v", res)
			}
			if !errors.Is(err, ErrIdentityUnknown) && !errors.Is(err, ErrOriginMismatch) && !errors.Is(err, ErrLogKeyMismatch) {
				t.Errorf("err = %v, want un error de identidad", err)
			}
			if !errors.Is(err, ErrIntegrity) {
				t.Errorf("el error debería ser de integridad (código 2 en la CLI): %v", err)
			}
		})
	}

	t.Run("una política que no afirma identidad sigue sin comparar nada", func(t *testing.T) {
		// La diferencia que importa: con --witness-name y --witness-key sueltas no hay
		// ni origin ni clave del log, así que no hay pregunta que contestar y el ledger
		// abre. Lo que se arregló es el silencio ante una pregunta, no la ausencia de
		// pregunta.
		path := seedAttested(t, 5, 0)
		s, _, err := Open(path)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.db.Exec(`DELETE FROM vault_meta WHERE k IN (?, ?)`, MetaLogPubKey, MetaOriginKey); err != nil {
			t.Fatal(err)
		}
		s.Close()

		s, _, err = OpenWithWitnesses(path, testWitnessPolicy(t))
		if err != nil {
			t.Fatalf("una política sin identidad no tiene nada que comparar: %v", err)
		}
		s.Close()
	})
}
