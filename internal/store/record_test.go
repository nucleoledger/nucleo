package store

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/nucleoledger/nucleo/internal/ledger"
)

// bloqueDe sella un bloque con el payload dado, encadenado tras prev.
func bloqueDe(t testing.TB, prev *ledger.Block, payload []byte, keyByte byte) *ledger.Block {
	t.Helper()
	pub, priv := testKeys(t, keyByte)
	sum := sha256.Sum256(payload)
	n := 0
	if prev != nil {
		n = int(prev.Header.Index) + 1
	}
	h, err := ledger.NewHeader(prev, testTenant, "sri.factura.v1", payload,
		"blob://"+hex.EncodeToString(sum[:]), pub, testBase.Add(time.Duration(n)*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	b, err := ledger.Seal(h, priv)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestAppendRecordEscribeTodoODaNada es la regresión de H8: el sellado era tres
// escrituras sueltas, y un fallo en medio dejaba un blob sin bloque que —por ser
// payload_hash la clave primaria— bloqueaba el reintento de ESE documento para
// siempre. Ver ADR-020 §C.
//
// El fallo se provoca DESPUÉS de escribir el contenido, que es el único sitio donde la
// atomicidad se puede demostrar: un valor nulo en vault_meta, que el esquema rechaza por
// NOT NULL. Si la transacción no existiera, el contenido se quedaría escrito.
func TestAppendRecordEscribeTodoODaNada(t *testing.T) {
	s := openTemp(t)
	payload := []byte("factura 001")
	g := bloqueDe(t, nil, payload, 0)
	if err := s.AppendRecord(Record{Block: g}); err != nil {
		t.Fatal(err)
	}

	segundo := bloqueDe(t, g, []byte("contenido del sellado que falla"), 0)
	otroHash := segundo.Header.PayloadHash

	err := s.AppendRecord(Record{
		Block: segundo,
		Blob:  &Blob{PayloadHash: otroHash, Ciphertext: []byte("ct"), Nonce: []byte("n"), CreatedAt: "2026-09-05T12:00:00Z"},
		Meta:  map[string][]byte{"commit/v1/" + otroHash: nil}, // NOT NULL: falla aquí
		State: map[string]string{"seal/idempotency/v1/x": `{"key":"x"}`},
	})
	if err == nil {
		t.Fatal("un valor nulo en vault_meta no puede entrar")
	}
	if jergaDelMotor.MatchString(err.Error()) {
		t.Errorf("el mensaje lleva jerga del motor: %q", err.Error())
	}

	// Y NADA de lo que iba con él quedó escrito, ni lo que se escribió ANTES de fallar.
	if _, err := s.GetBlob(otroHash); !errors.Is(err, ErrNotFound) {
		t.Errorf("quedó el contenido del sellado fallido: err = %v", err)
	}
	if _, err := s.GetMeta("commit/v1/" + otroHash); !errors.Is(err, ErrNotFound) {
		t.Errorf("quedaron los compromisos del sellado fallido: err = %v", err)
	}
	if _, err := s.State("seal/idempotency/v1/x"); !errors.Is(err, ErrNotFound) {
		t.Errorf("quedó la clave de idempotencia del sellado fallido: err = %v", err)
	}
	if n, err := s.Count(); err != nil || n != 1 {
		t.Errorf("bloques = %d (err %v), want 1", n, err)
	}

	// Y el reintento del MISMO documento entra, que es lo que el huérfano impedía.
	if err := s.AppendRecord(Record{
		Block: segundo,
		Blob:  &Blob{PayloadHash: otroHash, Ciphertext: []byte("ct"), Nonce: []byte("n"), CreatedAt: "2026-09-05T12:00:00Z"},
	}); err != nil {
		t.Fatalf("el reintento debería entrar: %v", err)
	}
	if n, _ := s.Count(); n != 2 {
		t.Errorf("bloques = %d tras el reintento, want 2", n)
	}
}

// TestAppendRecordExigeQueElBloqueEncadene: la validación del encadenamiento ocurre
// dentro de la transacción, leyendo el último bloque persistido.
func TestAppendRecordExigeQueElBloqueEncadene(t *testing.T) {
	s := openTemp(t)
	g := bloqueDe(t, nil, []byte("cero"), 0)
	uno := bloqueDe(t, g, []byte("uno"), 0)
	dos := bloqueDe(t, uno, []byte("dos"), 0)
	if err := s.AppendRecord(Record{Block: g}); err != nil {
		t.Fatal(err)
	}
	if err := s.AppendRecord(Record{Block: dos}); err == nil {
		t.Error("el bloque 2 no puede seguir al 0")
	}
	if err := s.AppendRecord(Record{Block: nil}); err == nil {
		t.Error("un registro sin bloque no es un registro")
	}
}

// TestAppendRecordGuardaLosCuatro comprueba el camino feliz completo.
func TestAppendRecordGuardaLosCuatro(t *testing.T) {
	s := openTemp(t)
	payload := []byte("factura 002")
	sum := sha256.Sum256(payload)
	hash := hex.EncodeToString(sum[:])
	b := bloqueDe(t, nil, payload, 1)

	if err := s.AppendRecord(Record{
		Block: b,
		Blob:  &Blob{PayloadHash: hash, Ciphertext: []byte("cifrado"), Nonce: []byte("nonce"), CreatedAt: "2026-09-05T12:00:00Z"},
		Meta:  map[string][]byte{"commit/v1/" + hash: []byte(`{"cedula":"c"}`)},
		State: map[string]string{"seal/idempotency/v1/k": `{"key":"factura-002"}`},
	}); err != nil {
		t.Fatal(err)
	}

	if _, err := s.GetBlob(hash); err != nil {
		t.Errorf("el contenido: %v", err)
	}
	if v, err := s.GetMeta("commit/v1/" + hash); err != nil || string(v) != `{"cedula":"c"}` {
		t.Errorf("los compromisos: %q (err %v)", v, err)
	}
	if v, err := s.State("seal/idempotency/v1/k"); err != nil || v != `{"key":"factura-002"}` {
		t.Errorf("la clave de idempotencia: %q (err %v)", v, err)
	}
	if idx, err := s.BlocksWithPayload(hash); err != nil || len(idx) != 1 || idx[0] != 0 {
		t.Errorf("BlocksWithPayload = %v (err %v), want [0]", idx, err)
	}
}

// TestBlocksWithPayloadEncuentraLosDuplicados: el mismo contenido sellado dos veces
// son dos bloques (ADR-020 §A), y hay que poder nombrarlos.
func TestBlocksWithPayloadEncuentraLosDuplicados(t *testing.T) {
	s := openTemp(t)
	payload := []byte("el mismo contenido")
	b0 := bloqueDe(t, nil, payload, 2)
	b1 := bloqueDe(t, b0, []byte("otro"), 2)
	b2 := bloqueDe(t, b1, payload, 2)
	for _, b := range []*ledger.Block{b0, b1, b2} {
		if err := s.AppendRecord(Record{Block: b}); err != nil {
			t.Fatal(err)
		}
	}
	sum := sha256.Sum256(payload)
	idx, err := s.BlocksWithPayload(hex.EncodeToString(sum[:]))
	if err != nil {
		t.Fatal(err)
	}
	if len(idx) != 2 || idx[0] != 0 || idx[1] != 2 {
		t.Errorf("BlocksWithPayload = %v, want [0 2]", idx)
	}

	// Un hash que no está no encuentra nada, y uno mal formado no llega a consultar.
	if idx, err := s.BlocksWithPayload(strings.Repeat("ab", 32)); err != nil || len(idx) != 0 {
		t.Errorf("hash ausente: %v (err %v)", idx, err)
	}
	if _, err := s.BlocksWithPayload("no-es-un-hash"); err == nil {
		t.Error("un hash mal formado debería rechazarse antes de consultar")
	}
}

// jergaDelMotor caza lo que no puede salir por un mensaje de esta biblioteca: el
// vocabulario del motor SQLite y sus códigos de resultado.
var jergaDelMotor = regexp.MustCompile(`(?i)sqlite|constraint|SQL logic|\(\d{3,4}\)`)

// TestErroresDeLaBaseSonClasesNoVolcados es la regresión de ADR-020 §E. La cuarta
// auditoría encontró "UNIQUE constraint failed: blobs.payload_hash (1555)" saliendo por
// la primera línea de la CLI y, en --json, dentro del campo "error".
func TestErroresDeLaBaseSonClasesNoVolcados(t *testing.T) {
	s := openTemp(t)
	payload := []byte("factura 003")
	sum := sha256.Sum256(payload)
	hash := hex.EncodeToString(sum[:])

	if err := s.PutBlob(hash, []byte("ct"), []byte("n")); err != nil {
		t.Fatal(err)
	}
	err := s.PutBlob(hash, []byte("otro"), []byte("n"))
	if !errors.Is(err, ErrDuplicateBlob) {
		t.Fatalf("err = %v, want ErrDuplicateBlob", err)
	}
	if jergaDelMotor.MatchString(err.Error()) {
		t.Errorf("el mensaje lleva jerga del motor: %q", err.Error())
	}
	// El error del driver NO se pierde: sigue envuelto para quien depure.
	var conCodigo interface{ Code() int }
	if !errors.As(err, &conCodigo) {
		t.Error("el error del driver debería seguir envuelto")
	}

	// Y el ledger append-only: dos veces el mismo índice.
	b := bloqueDe(t, nil, payload, 3)
	if err := s.AppendRecord(Record{Block: b}); err != nil {
		t.Fatal(err)
	}
	err = insertBlock(s.db, b)
	if !errors.Is(err, ErrAppendOnly) {
		t.Errorf("reinsertar un bloque: err = %v, want ErrAppendOnly", err)
	}
	if jergaDelMotor.MatchString(err.Error()) {
		t.Errorf("el mensaje lleva jerga del motor: %q", err.Error())
	}
}

// TestRollbackRegistradoDuraHastaQueSeResuelve: la constancia del rollback (ensayo de
// operación del Sprint 10, escenario 4) se escribe, se lee y solo se borra a mano por
// quien comprueba que el problema está resuelto —que en la CLI es una sincronización que
// vuelve a cuadrar—.
func TestRollbackRegistradoDuraHastaQueSeResuelve(t *testing.T) {
	s := openTemp(t)

	if _, hay, err := s.Rollback(); err != nil || hay {
		t.Fatalf("un ledger nuevo no tiene rollback: hay=%v err=%v", hay, err)
	}

	r := RollbackRecord{At: "2026-09-23T05:50:21Z", LocalSize: 1322, WitnessSize: 1422, Witness: "witness.example/w1"}
	if err := s.PutRollback(r); err != nil {
		t.Fatal(err)
	}
	got, hay, err := s.Rollback()
	if err != nil || !hay {
		t.Fatalf("hay=%v err=%v", hay, err)
	}
	if got != r {
		t.Errorf("registro = %+v, want %+v", got, r)
	}

	// Sobrevive a cerrar y volver a abrir: si no, la alarma seguiría siendo la de un
	// proceso y no la del ledger.
	path := s.path
	s.Close()
	s2, _, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	if got, hay, _ := s2.Rollback(); !hay || got != r {
		t.Errorf("tras reabrir: hay=%v registro=%+v", hay, got)
	}

	if err := s2.ClearRollback(); err != nil {
		t.Fatal(err)
	}
	if _, hay, _ := s2.Rollback(); hay {
		t.Error("ClearRollback no lo borró")
	}
	// Borrar dos veces no es un error: el efecto deseado ya se cumplió.
	if err := s2.ClearRollback(); err != nil {
		t.Errorf("borrar dos veces: %v", err)
	}
}
