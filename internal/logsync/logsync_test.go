package logsync

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"errors"
	"fmt"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/nucleoledger/nucleo/internal/checkpoint"
	"github.com/nucleoledger/nucleo/internal/ledger"
	"github.com/nucleoledger/nucleo/internal/store"
	"github.com/nucleoledger/nucleo/internal/witness"
	_ "modernc.org/sqlite"
)

const (
	testOrigin = "nucleoledger.com/sync"
	testTenant = "1790012345001"
)

var testBase = time.Date(2026, 9, 6, 9, 0, 0, 0, time.UTC)

func keyFrom(b byte) ed25519.PrivateKey {
	s := make([]byte, ed25519.SeedSize)
	for i := range s {
		s[i] = b + byte(i)
	}
	return ed25519.NewKeyFromSeed(s)
}

// scene monta las dos partes separadas: un log con su base y un testigo con la
// suya, hablando por HTTP.
type scene struct {
	t       *testing.T
	dbPath  string
	store   *store.Store
	adapter *StoreLog
	client  *witness.Client
	witness *witness.Witness
	server  *httptest.Server
	tenant  ed25519.PrivateKey
}

// rebind vuelve a montar el adaptador sobre otra apertura de la misma base, con
// un Log NUEVO: es lo que hace un proceso al arrancar.
func (sc *scene) rebind(t *testing.T, s *store.Store) *StoreLog {
	t.Helper()
	signer, err := checkpoint.NewSigner(testOrigin, keyFrom(50))
	if err != nil {
		t.Fatal(err)
	}
	lg, err := checkpoint.NewLog(testOrigin, signer)
	if err != nil {
		t.Fatal(err)
	}
	adapter, err := NewStoreLog(s, lg)
	if err != nil {
		t.Fatal(err)
	}
	sc.store = s
	sc.adapter = adapter
	return adapter
}

func newScene(t *testing.T, blocks int) *scene {
	t.Helper()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "nucleo.db")

	s, _, err := store.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })

	tenantPriv := keyFrom(1)
	tenantPub := tenantPriv.Public().(ed25519.PublicKey)
	var prev *ledger.Block
	for i := 0; i < blocks; i++ {
		h, err := ledger.NewHeader(prev, testTenant, "sri.factura.v1",
			[]byte(fmt.Sprintf("factura-%d", i)), "blob://x", tenantPub,
			testBase.Add(time.Duration(i)*time.Minute))
		if err != nil {
			t.Fatal(err)
		}
		b, err := ledger.Seal(h, tenantPriv)
		if err != nil {
			t.Fatal(err)
		}
		if err := s.AppendBlock(b); err != nil {
			t.Fatal(err)
		}
		prev = b
	}

	logPriv := keyFrom(50)
	// La clave pública del log en claro, como la deja init: desde ADR-016 la
	// apertura rehúsa una base con checkpoints que no la declare.
	if err := s.PutMeta(store.MetaLogPubKey, logPriv.Public().(ed25519.PublicKey)); err != nil {
		t.Fatal(err)
	}
	if err := s.PutMeta(store.MetaOriginKey, []byte(testOrigin)); err != nil {
		t.Fatal(err)
	}
	logSigner, err := checkpoint.NewSigner(testOrigin, logPriv)
	if err != nil {
		t.Fatal(err)
	}
	lg, err := checkpoint.NewLog(testOrigin, logSigner)
	if err != nil {
		t.Fatal(err)
	}

	st, err := witness.OpenState(filepath.Join(dir, "witness.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	clk := testBase
	w, err := witness.NewWithState("witness.example/w1", keyFrom(90),
		func() time.Time { clk = clk.Add(time.Second); return clk }, st)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.AddLog(testOrigin, logPriv.Public().(ed25519.PublicKey)); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(witness.NewServer(w).Handler())
	t.Cleanup(srv.Close)

	adapter, err := NewStoreLog(s, lg)
	if err != nil {
		t.Fatal(err)
	}
	client, err := witness.NewClient(srv.URL, "witness.example/w1", keyFrom(90).Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	return &scene{
		t: t, dbPath: dbPath, store: s, adapter: adapter,
		client: client, witness: w, server: srv, tenant: tenantPriv,
	}
}

// TestSyncHappyPath cubre el ciclo normal: primera sincronización, extensión y
// llamada sin novedades.
func TestSyncHappyPath(t *testing.T) {
	sc := newScene(t, 5)
	ctx := context.Background()

	res, err := SyncWithWitness(ctx, sc.adapter, sc.client)
	if err != nil {
		t.Fatalf("primera sincronización: %v", err)
	}
	if !res.Fresh || res.WitnessSize != 0 || res.LocalSize != 5 {
		t.Fatalf("resultado = %+v, want testigo nuevo con 5 bloques locales", res)
	}
	if !checkpoint.IsCosigned(res.Cosigned) {
		t.Error("la nota devuelta no está cosignada")
	}

	// Sin bloques nuevos: el testigo está al día y devuelve lo que ya tenía.
	res, err = SyncWithWitness(ctx, sc.adapter, sc.client)
	if err != nil {
		t.Fatalf("segunda sincronización sin novedades: %v", err)
	}
	if res.Fresh || res.WitnessSize != 5 || res.LocalSize != 5 {
		t.Errorf("resultado = %+v, want testigo al día en 5", res)
	}

	// Tres bloques más y una extensión con su prueba de consistencia.
	sc.appendMore(t, 3)
	res, err = SyncWithWitness(ctx, sc.adapter, sc.client)
	if err != nil {
		t.Fatalf("extensión: %v", err)
	}
	if res.WitnessSize != 5 || res.LocalSize != 8 {
		t.Errorf("resultado = %+v, want extensión de 5 a 8", res)
	}
	if last, ok := sc.witness.Last(testOrigin); !ok || last.Size != 8 {
		t.Errorf("el testigo recuerda %+v, want 8", last)
	}
}

// appendMore sella n bloques más sobre la cadena existente.
func (sc *scene) appendMore(t *testing.T, n int) {
	t.Helper()
	prev, err := sc.store.LastBlock()
	if err != nil {
		t.Fatal(err)
	}
	pub := sc.tenant.Public().(ed25519.PublicKey)
	for i := 0; i < n; i++ {
		h, err := ledger.NewHeader(prev, testTenant, "sri.factura.v1",
			[]byte(fmt.Sprintf("extra-%d", i)), "blob://x", pub,
			testBase.Add(time.Duration(100+i)*time.Minute))
		if err != nil {
			t.Fatal(err)
		}
		b, err := ledger.Seal(h, sc.tenant)
		if err != nil {
			t.Fatal(err)
		}
		if err := sc.store.AppendBlock(b); err != nil {
			t.Fatal(err)
		}
		prev = b
	}
}

// TestSyncDetectsLocalRollback es la mitigación del hallazgo ALTO de la
// auditoría externa, reproducida de principio a fin.
//
// El atacante controla el fichero del log: borra los disparadores, vacía la
// tabla de checkpoints y trunca los bloques a un prefijo. Lo que queda encadena
// y verifica; store.Open lo acepta y lo marca NO ATESTIGUADO, que es todo lo
// que puede hacer desde dentro del fichero.
//
// Lo que el atacante no controla es la base del testigo, que está en otra parte.
// El testigo recuerda un árbol de 8 y en disco hay 4: la sincronización lo dice
// con nombre y apellidos.
func TestSyncDetectsLocalRollback(t *testing.T) {
	sc := newScene(t, 8)
	ctx := context.Background()

	if _, err := SyncWithWitness(ctx, sc.adapter, sc.client); err != nil {
		t.Fatal(err)
	}
	if last, _ := sc.witness.Last(testOrigin); last.Size != 8 {
		t.Fatalf("el testigo debería recordar 8, recuerda %d", last.Size)
	}
	if err := sc.store.Close(); err != nil {
		t.Fatal(err)
	}

	// El ataque, por SQL directo sobre el fichero del log.
	db, err := sql.Open("sqlite", "file:"+sc.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, stmt := range []string{
		`DROP TRIGGER IF EXISTS blocks_no_delete`,
		`DROP TRIGGER IF EXISTS blocks_no_update`,
		`DROP TRIGGER IF EXISTS checkpoints_no_delete`,
		`DROP TRIGGER IF EXISTS checkpoints_no_update`,
		`DELETE FROM checkpoints`,
		`DELETE FROM blocks WHERE idx >= 4`,
	} {
		if _, err := db.Exec(stmt); err != nil {
			t.Fatalf("%s: %v", stmt, err)
		}
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	// El fichero truncado abre sin una queja, porque desde dentro es coherente.
	s2, openState, err := store.Open(sc.dbPath)
	if err != nil {
		t.Fatalf("el prefijo truncado no abrió: %v", err)
	}
	defer s2.Close()
	if openState.Attested() {
		t.Error("el prefijo truncado se declaró atestiguado")
	}
	if openState.TreeSize != 4 {
		t.Errorf("TreeSize = %d, want 4", openState.TreeSize)
	}

	// Y aquí se acaba el disimulo.
	sc.adapter.Store = s2
	_, err = SyncWithWitness(ctx, sc.adapter, sc.client)
	var rb *RollbackError
	if !errors.As(err, &rb) {
		t.Fatalf("la sincronización no detectó el truncamiento: %v", err)
	}
	if !errors.Is(err, ErrLocalRollback) {
		t.Errorf("el error no envuelve a ErrLocalRollback: %v", err)
	}
	if rb.LocalSize != 4 || rb.WitnessSize != 8 {
		t.Errorf("RollbackError = %+v, want local 4 y testigo 8", rb)
	}
}

// TestSyncWithoutWitnessMemoryIsNotRollback es el control negativo: un testigo
// que no recuerda nada NO es un rollback. Sin este test, una sincronización que
// gritase siempre pasaría por vigilante.
func TestSyncWithoutWitnessMemoryIsNotRollback(t *testing.T) {
	sc := newScene(t, 3)
	res, err := SyncWithWitness(context.Background(), sc.adapter, sc.client)
	if err != nil {
		t.Fatalf("un testigo sin memoria no es un rollback: %v", err)
	}
	if !res.Fresh {
		t.Error("Fresh = false, want true")
	}
}
