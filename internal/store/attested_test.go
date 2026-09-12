package store

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path/filepath"
	"reflect"
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

// testWitnessPolicy es la política con la que hay que abrir para que las notas de
// cosign() cuenten como atestación VERIFICADA: el testigo de clave 9.
func testWitnessPolicy(t testing.TB) WitnessPolicy {
	t.Helper()
	wPub, _ := testKeys(t, 9)
	return WitnessPolicy{Witnesses: map[string]ed25519.PublicKey{"witness.example/w": wPub}, Quorum: 1}
}

// declareLogKey escribe en vault_meta la clave pública del log de los tests (la 7),
// como hace init. Sin ella, un ledger con checkpoints no abre (ADR-016).
func declareLogKey(t testing.TB, s *Store) {
	t.Helper()
	logPub, _ := testKeys(t, 7)
	if err := s.PutMeta(MetaLogPubKey, logPub); err != nil {
		t.Fatal(err)
	}
	if err := s.PutMeta(MetaOriginKey, []byte(testOrigin)); err != nil {
		t.Fatal(err)
	}
}

// openAttested abre aportando la política de testigos de los tests.
func openAttested(t testing.TB, path string) (*Store, OpenResult, error) {
	t.Helper()
	return OpenWithWitnesses(path, testWitnessPolicy(t))
}

// seedAttested crea una base con n bloques y un checkpoint COSIGNADO sobre los
// primeros cpSize. Con cpSize == 0 no se guarda checkpoint alguno.
func seedAttested(t *testing.T, n, cpSize int) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "nucleo.db")
	s, _, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	// Lo que init deja en claro y la apertura exige desde ADR-016: la clave
	// pública del log con la que tienen que estar firmados los checkpoints.
	declareLogKey(t, s)
	blocks := chain(t, n, 0)
	leaves := make([][]byte, 0, n)
	for i, b := range blocks {
		if err := s.AppendBlock(b); err != nil {
			t.Fatal(err)
		}
		hb, err := b.LeafData()
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
	s, _, err := Open(path)
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
	s2, _, err := openAttested(t, path)
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
// header ni su hash.
//
// Bajo leaf/v1 esta era la única manipulación que la raíz cosignada NO cubría: la
// firma vivía fuera del header y fuera de la hoja. Bajo leaf/v2 la hoja es
// hash ‖ signature, así que esta misma manipulación cambia la raíz.
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

// TestAttestedOpenDetectsCorruptSignatureUnderCheckpoint es el punto ciego de
// leaf/v1, CERRADO. Es el test que justifica ADR-014 entero.
//
// Hasta leaf/v2 este test afirmaba lo contrario: que Open ACEPTABA un bloque
// atestiguado con la firma destrozada, porque la raíz no cubría la columna
// signature y por debajo del checkpoint cosignado las verificaciones Ed25519 se
// saltan por coste. La mitigación documentada era `verify --full`, y la revisión
// externa contestó lo único que se podía contestar: "verify --full no es mitigación
// si nadie lo corre".
//
// Ahora la hoja es hash ‖ signature, así que destrozar la firma cambia la hoja,
// cambia la raíz y la MISMA comprobación que ya se hacía al abrir lo detecta. Sin
// verificar una sola firma Ed25519 de más: lo que detecta la manipulación es el
// árbol, no la criptografía de firma.
func TestAttestedOpenDetectsCorruptSignatureUnderCheckpoint(t *testing.T) {
	path := seedAttested(t, 5, 5)
	corruptSignature(t, path, 1)

	s, _, err := openAttested(t, path)
	if err == nil {
		s.Close()
		t.Fatal("Open aceptó un bloque atestiguado con la firma destrozada: " +
			"leaf/v2 debe cubrir la columna signature")
	}
	// Y el error señala al checkpoint, no al bloque: lo que no cuadra es la raíz
	// reconstruida contra la que el log firmó. Es la forma correcta de decirlo —el
	// bloque 1 por separado no tiene nada de raro, es el conjunto el que miente.
	if !errors.Is(err, ErrIntegrity) {
		t.Errorf("err = %v, want ErrIntegrity", err)
	}

	// Y es determinista: no depende de en qué orden se leyeron las filas.
	if _, _, err := openAttested(t, path); err == nil {
		t.Fatal("la segunda apertura tampoco debía pasar")
	}
}

// TestVerifyFullCazaUnaFirmaInvalidaYaATESTIGUADA cubre el hueco que leaf/v2 NO
// cierra, y es el que justifica que VerifyFull siga existiendo.
//
// leaf/v2 garantiza que los BYTES de la firma son los que había cuando se cosignó
// la raíz. No garantiza que esos bytes fueran una firma válida: un emisor puede
// escribir basura en la columna, calcular la raíz sobre esa basura y hacérsela
// cosignar a un testigo. El testigo no verifica firmas de bloque —no es su trabajo
// ni tiene las claves— así que cosignará encantado.
//
// Contra eso, la apertura rápida no puede hacer nada por diseño: por debajo del
// checkpoint cosignado se salta las verificaciones Ed25519, que es de donde sale
// 412 ms en vez de 8 s. Quien quiera descartarlo ejecuta la ruta exhaustiva. La
// diferencia con antes es importante: ese hueco exige un emisor deshonesto desde el
// principio, no un atacante que entra después a una base ya cerrada.
func TestVerifyFullCazaUnaFirmaInvalidaYaATESTIGUADA(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nucleo.db")
	s, _, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	declareLogKey(t, s)
	for _, b := range chain(t, 5, 0) {
		if err := s.AppendBlock(b); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	// El emisor destroza la firma ANTES de atestiguar.
	corruptSignature(t, path, 1)

	s2 := openUnverified(t, path)
	leaves, err := s2.LeafData()
	if err != nil {
		t.Fatal(err)
	}
	_, logPriv := testKeys(t, 7)
	if err := s2.PutCheckpoint(cosign(t, 5, ledger.Root(leaves), logPriv)); err != nil {
		t.Fatal(err)
	}
	if err := s2.Close(); err != nil {
		t.Fatal(err)
	}

	// La apertura pasa: la raíz cosignada CUADRA con lo que hay en disco, basura
	// incluida. Es la propiedad de leaf/v2 funcionando, no un fallo.
	s3, res, err := openAttested(t, path)
	if err != nil {
		t.Fatalf("Open debía pasar: la raíz cosignada cuadra con el contenido: %v", err)
	}
	defer s3.Close()
	if !res.Attested() {
		t.Fatal("la base debería reportarse atestiguada")
	}

	// Y la ruta exhaustiva lo caza, nombrando el bloque.
	_, err = s3.VerifyFull()
	if err == nil {
		t.Fatal("VerifyFull aceptó un bloque cuya firma no verifica")
	}
	var ie *IntegrityError
	if !errors.As(err, &ie) || ie.Stage != "bloque" || ie.Index != 1 {
		t.Fatalf("VerifyFull err = %v, want IntegrityError bloque 1", err)
	}
	if !errors.Is(err, ledger.ErrBadSignature) {
		t.Errorf("la causa no es ErrBadSignature: %v", err)
	}
}

// openUnverified abre la base saltándose la verificación de integridad, que es lo
// único que permite montar el escenario de arriba: un emisor con la base ya en la
// mano no pasa por Open.
func openUnverified(t *testing.T, path string) *Store {
	t.Helper()
	s, err := connect(path)
	if err != nil {
		t.Fatal(err)
	}
	return s
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
			s, _, err := Open(path)
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
	s, _, err := openAttested(t, path)
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
	s, _, err := openAttested(t, path)
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

	s2, _, err := openAttested(t, path)
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
	s, _, err := openAttested(t, path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.VerifyFull(); err != nil {
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

// TestRollbackWithCheckpointDeletionOpensUnattested reproduce EXACTAMENTE el
// escenario de la auditoría externa, que es el límite honesto de lo que un
// fichero puede probar sobre sí mismo.
//
// El atacante controla el fichero: borra los disparadores, vacía la tabla de
// checkpoints y trunca los bloques a un prefijo. Lo que queda es una cadena
// perfectamente válida —encadena, las firmas verifican, no hay checkpoint que
// contradiga nada— pero es la historia de AYER. Ninguna comprobación interna
// puede detectarlo, y no por un defecto de implementación: el fichero entero es
// suyo, así que cualquier prueba que viviera dentro también sería suya.
//
// Open acepta, porque negarse sería negarse a abrir cualquier ledger sin
// testigo, incluido uno recién creado. Lo que NO hace es callarse: Attested
// queda en false y el estado viaja en el resultado.
//
// La detección definitiva está fuera del fichero y es tarea del Sprint 3: al
// sincronizar, preguntar al testigo cuál fue el último checkpoint que cosignó
// de nuestro origin. El testigo recuerda un árbol de 5 y aquí solo hay 3; ahí
// se acaba el disimulo. Ese es el motivo de que exista internal/witness.
func TestRollbackWithCheckpointDeletionOpensUnattested(t *testing.T) {
	path := seedAttested(t, 5, 5)

	// Control: antes del ataque, la historia está atestiguada.
	s, res, err := openAttested(t, path)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Attested() || res.AttestedSize != 5 || res.TreeSize != 5 {
		t.Fatalf("estado inicial = %+v, want atestiguada hasta 5 de 5", res)
	}
	if got := s.Attestation(); !reflect.DeepEqual(got, res) {
		t.Errorf("Attestation() = %+v, want %+v", got, res)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	// El ataque, por SQL directo: sin disparadores, sin checkpoints y con la
	// historia recortada a los tres primeros bloques.
	db := rawDB(t, path)
	dropTriggers(t, db)
	if _, err := db.Exec(`DELETE FROM checkpoints`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`DELETE FROM blocks WHERE idx >= 3`); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	s2, res2, err := openAttested(t, path)
	if err != nil {
		t.Fatalf("Open rechazó un prefijo íntegro: %v", err)
	}
	defer s2.Close()

	if res2.Attested() {
		t.Error("la historia truncada se declaró atestiguada")
	}
	if res2.AttestedSize != 0 {
		t.Errorf("AttestedSize = %d, want 0", res2.AttestedSize)
	}
	if res2.TreeSize != 3 {
		t.Errorf("TreeSize = %d, want 3", res2.TreeSize)
	}
	if !strings.Contains(res2.String(), "SIN ATESTIGUAR") {
		t.Errorf("el estado no se anuncia como no atestiguado: %q", res2.String())
	}

	// Y la verificación exhaustiva tampoco lo detecta, porque no hay nada que
	// detectar dentro del fichero: el prefijo es íntegro.
	if _, err := s2.VerifyFull(); err != nil {
		t.Errorf("VerifyFull sobre un prefijo íntegro: %v", err)
	}
}

// TestOpenResultReportsPartialAttestation cubre el caso intermedio: hay testigo,
// pero cubre menos bloques de los que hay. Es el estado normal entre un
// checkpoint y el siguiente, y el resultado tiene que distinguirlo de los otros
// dos en vez de reducirlo a "atestiguada, sí o no".
func TestOpenResultReportsPartialAttestation(t *testing.T) {
	path := seedAttested(t, 7, 4)
	s, res, err := openAttested(t, path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	if !res.Attested() || res.AttestedSize != 4 || res.TreeSize != 7 {
		t.Fatalf("estado = %+v, want atestiguada hasta 4 de 7", res)
	}
	if !strings.Contains(res.String(), "hasta 4 de 7") {
		t.Errorf("el estado no dice hasta dónde llega el testigo: %q", res.String())
	}
}
