package store

import (
	"errors"
	"testing"

	"github.com/nucleoledger/nucleo/internal/checkpoint"
)

// H1 de la cuarta auditoría: la apertura decidía si la nota ATESTIGUADA y la ÚLTIMA
// son la misma comparando su tree_size, y con eso se saltaba la comprobación de la raíz
// atestiguada. Es inferencia estructural sobre datos que el modelo de amenaza da por
// manipulables, que es la forma de error que ADR-016 cerró para las firmas.
//
// La clave primaria de `checkpoints` impide dos filas del mismo tamaño MIENTRAS la tabla
// sea la que crea el esquema. Quien puede escribir en el fichero puede rehacer la tabla:
// eso hace este test, con dos notas del mismo tamaño firmadas las dos por la clave real
// del log —la situación del log que firma un fork, p. ej. tras restaurar un backup— y
// raíces distintas. La cosignada miente sobre la raíz; la otra dice la verdad.
func TestCheckpointsDelMismoTamanoConRaicesDistintas(t *testing.T) {
	path := seedAttested(t, 5, 5)
	_, logPriv := testKeys(t, 7)

	s, _, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	raizBuena, err := s.Root()
	if err != nil {
		t.Fatal(err)
	}
	s.Close()

	raizFalsa := append([]byte{}, raizBuena...)
	raizFalsa[0] ^= 0xff
	// La honesta va SIN cosignature y la mentirosa CON ella: así la "última" nota es la
	// honesta —y su raíz cuadra— y la "atestiguada" es la otra. Es la combinación en la
	// que la igualdad de tamaño decide, y la que el atacante elegiría.
	firmante, err := checkpoint.NewSigner(testOrigin, logPriv)
	if err != nil {
		t.Fatal(err)
	}
	buena, err := checkpoint.Sign(checkpoint.Checkpoint{Origin: testOrigin, Size: 5, RootHash: raizBuena}, firmante)
	if err != nil {
		t.Fatal(err)
	}
	falsa := cosign(t, 5, raizFalsa, logPriv)

	db := rawDB(t, path)
	dropTriggers(t, db)
	// La tabla, rehecha SIN clave primaria: es lo que haría quien tiene el fichero.
	for _, q := range []string{
		`DROP TABLE checkpoints`,
		`CREATE TABLE checkpoints (tree_size INTEGER NOT NULL, note TEXT NOT NULL)`,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	// La honesta primero: LastCheckpoint se queda con ella (y su raíz cuadra), y
	// LastCosignedCheckpoint sigue buscando hasta la cosignada, que es la mentirosa.
	for _, note := range [][]byte{buena, falsa} {
		if _, err := db.Exec(`INSERT INTO checkpoints (tree_size, note) VALUES (?, ?)`, 5, string(note)); err != nil {
			t.Fatal(err)
		}
	}

	s2, res, err := OpenWithWitnesses(path, testWitnessPolicy(t))
	if err == nil {
		s2.Close()
		t.Fatalf("EXPLOTADO: la apertura concedió %s con una nota atestiguada cuya raíz no es la del árbol", res.Attestation)
	}
	var ie *IntegrityError
	if !errors.As(err, &ie) || ie.Stage != "checkpoint" {
		t.Errorf("err = %v, want un IntegrityError de checkpoint", err)
	}
}
