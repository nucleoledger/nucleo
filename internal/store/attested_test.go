package store

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nucleoledger/nucleo/internal/checkpoint"
	"github.com/nucleoledger/nucleo/internal/ledger"
	"github.com/nucleoledger/nucleo/internal/witness"
)

const testOrigin = "nucleoledger.com/poc"

// cosign firma el checkpoint con la clave del log y le añade una cosignature de
// un testigo real. Se usa el testigo de verdad y no un blob de 72 bytes fabricado
// a mano: lo que se quiere probar es que Open reconoce lo que el sistema emite.
func cosign(t testing.TB, size uint64, root []byte, logPriv ed25519.PrivateKey) []byte {
	t.Helper()
	signer, err := checkpoint.NewSigner(testOrigin, logPriv)
	if err != nil {
		t.Fatal(err)
	}
	msg, err := checkpoint.Sign(checkpoint.Checkpoint{
		Origin: testOrigin, Size: size, RootHash: root,
	}, signer)
	if err != nil {
		t.Fatal(err)
	}
	_, wPriv := testKeys(t, 9)
	w, err := witness.New("witness.example/w", wPriv, func() time.Time { return testBase })
	if err != nil {
		t.Fatal(err)
	}
	if err := w.AddLog(testOrigin, logPriv.Public().(ed25519.PublicKey)); err != nil {
		t.Fatal(err)
	}
	cosigned, err := w.Cosign(msg, nil)
	if err != nil {
		t.Fatal(err)
	}
	return cosigned
}

// seedAttested crea una base con n bloques y un checkpoint COSIGNADO sobre los
// primeros cpSize. Con cpSize == 0 no se guarda checkpoint alguno.
func seedAttested(t *testing.T, n, cpSize int) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "nucleo.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	blocks := chain(t, n, 0)
	leaves := make([][]byte, 0, n)
	for i, b := range blocks {
		if err := s.AppendBlock(b); err != nil {
			t.Fatal(err)
		}
		hb, err := b.HashBytes()
		if err != nil {
			t.Fatal(err)
		}
		leaves = append(leaves, hb)
		if i+1 == cpSize {
			_, logPriv := testKeys(t, 7)
			if err := s.PutCheckpoint(cosign(t, uint64(cpSize), ledger.Root(leaves), logPriv)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestLastCosignedCheckpointIgnoresLogOnlyNotes comprueba que una nota con sola
// la firma del log no cuenta como atestiguada. Es la guarda que impide que el
// atajo de firmas se active sin testigo.
func TestLastCosignedCheckpointIgnoresLogOnlyNotes(t *testing.T) {
	path := seedLedger(t, 5, true) // checkpoint firmado solo por el log
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	if _, err := s.LastCheckpoint(); err != nil {
		t.Fatalf("LastCheckpoint: %v", err)
	}
	if _, err := s.LastCosignedCheckpoint(); !errors.Is(err, ErrNotFound) {
		t.Errorf("LastCosignedCheckpoint = %v, want ErrNotFound: la nota no está cosignada", err)
	}

	path = seedAttested(t, 5, 5)
	s2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	note, err := s2.LastCosignedCheckpoint()
	if err != nil {
		t.Fatalf("LastCosignedCheckpoint sobre nota cosignada: %v", err)
	}
	if c, err := checkpoint.ParseNote(note); err != nil || c.Size != 5 {
		t.Errorf("nota devuelta = %v (size %d), err %v", string(note), c.Size, err)
	}
}

// corruptSignature sustituye la firma de un bloque por ceros, sin tocar su
// header ni su hash. Es la única manipulación que la raíz cosignada NO cubre:
// la firma vive fuera del header, así que no entra en la hoja de Merkle.
func corruptSignature(t *testing.T, path string, idx int) {
	t.Helper()
	db := rawDB(t, path)
	dropTriggers(t, db)
	if _, err := db.Exec(`UPDATE blocks SET signature = ? WHERE idx = ?`,
		strings.Repeat("00", 64), idx); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
}

// TestAttestedOpenSkipsSignaturesUnderCheckpoint es la prueba de que el atajo
// existe de verdad —y, con el mismo gesto, de su precio exacto: la firma de un
// bloque atestiguado se puede corromper sin que la apertura lo note. VerifyFull
// sí lo nota. Está escrito en la enmienda de ADR-009.
func TestAttestedOpenSkipsSignaturesUnderCheckpoint(t *testing.T) {
	path := seedAttested(t, 5, 5)
	corruptSignature(t, path, 1)

	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open debía aceptar: la firma corrompida está bajo la raíz cosignada: %v", err)
	}
	defer s.Close()

	err = s.VerifyFull()
	if err == nil {
		t.Fatal("VerifyFull aceptó un bloque con la firma corrompida")
	}
	var ie *IntegrityError
	if !errors.As(err, &ie) || ie.Stage != "bloque" || ie.Index != 1 {
		t.Fatalf("VerifyFull err = %v, want IntegrityError bloque 1", err)
	}
	if !errors.Is(err, ledger.ErrBadSignature) {
		t.Errorf("la causa no es ErrBadSignature: %v", err)
	}
}

// TestOpenWithoutCosignatureVerifiesEverything es el contrapunto: sin testigo no
// hay atajo, así que la misma corrupción sí frena la apertura.
func TestOpenWithoutCosignatureVerifiesEverything(t *testing.T) {
	for _, c := range []struct {
		name string
		path func() string
	}{
		{"sin checkpoint", func() string { return seedLedger(t, 5, false) }},
		{"checkpoint solo del log", func() string { return seedLedger(t, 5, true) }},
	} {
		t.Run(c.name, func(t *testing.T) {
			path := c.path()
			corruptSignature(t, path, 1)
			s, err := Open(path)
			if err == nil {
				s.Close()
				t.Fatal("Open aceptó una firma corrompida sin checkpoint cosignado que la respalde")
			}
			var ie *IntegrityError
			if !errors.As(err, &ie) || ie.Stage != "bloque" || ie.Index != 1 {
				t.Fatalf("err = %v, want IntegrityError bloque 1", err)
			}
		})
	}
}

// TestAttestedOpenDetectsHistoricalRewrite cubre las dos formas de reescribir un
// bloque histórico bajo un checkpoint cosignado. Ninguna pasa: o rompe la
// atadura header↔hash, o rompe la raíz.
func TestAttestedOpenDetectsHistoricalRewrite(t *testing.T) {
	t.Run("header alterado, hash intacto", func(t *testing.T) {
		path := seedAttested(t, 5, 5)
		db := rawDB(t, path)
		dropTriggers(t, db)
		if _, err := db.Exec(
			`UPDATE blocks SET header_json = replace(header_json, '"tenant":"1790012345001"', '"tenant":"9999999999001"') WHERE idx = 1`); err != nil {
			t.Fatal(err)
		}
		if err := db.Close(); err != nil {
			t.Fatal(err)
		}
		assertIntegrityFailure(t, path, "bloque", 1)
	})

	t.Run("header y hash reescritos a la vez", func(t *testing.T) {
		path := seedAttested(t, 5, 5)
		rewriteBlockConsistently(t, path, 1)
		// La atadura header↔hash vuelve a cuadrar, así que solo la raíz
		// cosignada puede delatarlo. Y lo delata.
		assertIntegrityFailure(t, path, "checkpoint", -1)
	})
}

// rewriteBlockConsistently reescribe el header de un bloque y recomputa su hash
// para que la atadura header↔hash siga cuadrando. La firma queda inválida, que
// es justo lo que el camino rápido no mira: el atacante que sabe lo que hace
// llega hasta aquí y se estrella contra la raíz.
func rewriteBlockConsistently(t *testing.T, path string, idx int) {
	t.Helper()
	db := rawDB(t, path)
	dropTriggers(t, db)

	var headerJSON string
	if err := db.QueryRow(`SELECT header_json FROM blocks WHERE idx = ?`, idx).Scan(&headerJSON); err != nil {
		t.Fatal(err)
	}
	var h ledger.Header
	if err := json.Unmarshal([]byte(headerJSON), &h); err != nil {
		t.Fatal(err)
	}
	h.Tenant = "9999999999001"
	canonical, err := h.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	digest, err := h.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE blocks SET header_json = ?, hash = ? WHERE idx = ?`,
		string(canonical), hex.EncodeToString(digest), idx); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
}

// TestAttestedOpenVerifiesBlocksAfterCheckpoint comprueba que el atajo termina
// donde termina lo atestiguado: los bloques posteriores sí pasan por Ed25519.
func TestAttestedOpenVerifiesBlocksAfterCheckpoint(t *testing.T) {
	for _, idx := range []int{3, 4} { // el checkpoint cubre [0,3)
		path := seedAttested(t, 5, 3)
		corruptSignature(t, path, idx)
		assertIntegrityFailure(t, path, "bloque", int64(idx))
	}
}

// assertIntegrityFailure abre la base y exige que falle en la fase y el bloque
// esperados.
func assertIntegrityFailure(t *testing.T, path, stage string, index int64) {
	t.Helper()
	s, err := Open(path)
	if err == nil {
		s.Close()
		t.Fatal("Open aceptó una base manipulada")
	}
	var ie *IntegrityError
	if !errors.As(err, &ie) {
		t.Fatalf("el error no es *IntegrityError: %v", err)
	}
	if ie.Stage != stage || ie.Index != index {
		t.Fatalf("err = %v, want fase %q bloque %d", err, stage, index)
	}
}

// TestAttestedOpenDetectsRootMismatchOfCosignedCheckpoint cubre el caso en que
// el checkpoint MÁS RECIENTE cuadra pero el cosignado —que es el que respalda el
// atajo— no. Sin esta comprobación el atajo se apoyaría en una promesa falsa.
func TestAttestedOpenDetectsRootMismatchOfCosignedCheckpoint(t *testing.T) {
	path := seedAttested(t, 5, 3)

	// Se añade un checkpoint (solo del log) sobre los 5 bloques reales: ese
	// cuadra. Después se corrompe la raíz del cosignado de tamaño 3.
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	root, err := s.Root()
	if err != nil {
		t.Fatal(err)
	}
	_, logPriv := testKeys(t, 7)
	signer, err := checkpoint.NewSigner(testOrigin, logPriv)
	if err != nil {
		t.Fatal(err)
	}
	note5, err := checkpoint.Sign(checkpoint.Checkpoint{Origin: testOrigin, Size: 5, RootHash: root}, signer)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.PutCheckpoint(note5); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	fake := make([]byte, 32)
	for i := range fake {
		fake[i] = byte(i)
	}
	bogus := cosign(t, 3, fake, logPriv)
	db := rawDB(t, path)
	dropTriggers(t, db)
	if _, err := db.Exec(`UPDATE checkpoints SET note = ? WHERE tree_size = 3`, string(bogus)); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	s2, err := Open(path)
	if err == nil {
		s2.Close()
		t.Fatal("Open aceptó un checkpoint cosignado cuya raíz no es la del ledger")
	}
	var ie *IntegrityError
	if !errors.As(err, &ie) || ie.Stage != "checkpoint" {
		t.Fatalf("err = %v, want IntegrityError en fase checkpoint", err)
	}
	if !strings.Contains(err.Error(), "de 3 bloques") {
		t.Errorf("el error no señala al checkpoint cosignado (tamaño 3): %v", err)
	}
}

// TestVerifyFullOnHealthyLedger es el control negativo de VerifyFull.
func TestVerifyFullOnHealthyLedger(t *testing.T) {
	path := seedAttested(t, 7, 4)
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.VerifyFull(); err != nil {
		t.Errorf("VerifyFull sobre base sana: %v", err)
	}
}

// TestOpenRejectsNonCanonicalHeaderJSON fija lo que la comprobación sobre bytes
// almacenados gana frente a recanonicalizar: el header_json guardado tiene que
// ser la forma canónica JCS, que es lo que se firmó.
//
// Aquí se reescribe el header con el orden de campos de la struct de Go —mismo
// contenido, otros bytes, hash canónico intacto—. Recanonicalizando pasaría sin
// una queja; sobre los bytes guardados no pasa. La base deja de contener lo que
// se firmó y eso tiene que verse.
func TestOpenRejectsNonCanonicalHeaderJSON(t *testing.T) {
	path := seedAttested(t, 5, 5)

	db := rawDB(t, path)
	dropTriggers(t, db)
	var headerJSON string
	if err := db.QueryRow(`SELECT header_json FROM blocks WHERE idx = 2`).Scan(&headerJSON); err != nil {
		t.Fatal(err)
	}
	var h ledger.Header
	if err := json.Unmarshal([]byte(headerJSON), &h); err != nil {
		t.Fatal(err)
	}
	// json.Marshal emite los campos en el orden de declaración; JCS los ordena
	// lexicográficamente. Mismo contenido, otros bytes.
	nonCanonical, err := json.Marshal(h)
	if err != nil {
		t.Fatal(err)
	}
	if string(nonCanonical) == headerJSON {
		t.Fatal("el orden de declaración coincide con el canónico: el test no prueba nada")
	}
	canonical, err := h.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	if string(canonical) != headerJSON {
		t.Fatal("lo guardado no era la forma canónica; la premisa del test es falsa")
	}
	if _, err := db.Exec(`UPDATE blocks SET header_json = ? WHERE idx = 2`, string(nonCanonical)); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	assertIntegrityFailure(t, path, "bloque", 2)
}
