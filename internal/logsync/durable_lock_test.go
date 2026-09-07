package logsync

import (
	"context"
	"errors"
	"testing"

	"github.com/nucleoledger/nucleo/internal/checkpoint"
	"github.com/nucleoledger/nucleo/internal/ledger"
	"github.com/nucleoledger/nucleo/internal/store"
)

// reopen simula el reinicio del proceso del log: cierra la base, la vuelve a
// abrir y construye un Log NUEVO, con el cerrojo en blanco salvo por lo que
// encuentre en disco. Es lo que hace un servicio al arrancar.
func (sc *scene) reopen(t *testing.T) *StoreLog {
	t.Helper()
	if err := sc.store.Close(); err != nil {
		t.Fatal(err)
	}
	s, _, err := store.Open(sc.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	sc.store = s

	signer, err := checkpoint.NewSigner(testOrigin, keyFrom(50))
	if err != nil {
		t.Fatal(err)
	}
	lg, err := checkpoint.NewLog(testOrigin, signer)
	if err != nil {
		t.Fatal(err)
	}
	// Control: recién construido, el Log no recuerda NADA. Todo lo que sepa
	// después vendrá del disco, que es justo lo que este test comprueba.
	if _, ok := lg.Last(); ok {
		t.Fatal("un Log recién construido ya recordaba algo")
	}
	adapter, err := NewStoreLog(s, lg)
	if err != nil {
		t.Fatal(err)
	}
	sc.adapter = adapter
	return adapter
}

// TestLockSurvivesDeathBetweenSignAndCosign cierra el hueco que quedó abierto en
// el sprint anterior.
//
// El log firma un checkpoint y sale a pedir la cosignature. Si el proceso muere
// EN ESE INTERVALO, el checkpoint firmado existe —sus bytes pudieron llegar a
// alguna parte— pero nunca llegó a guardarse junto a los cosignados. Sin memoria
// duradera, el log que arranca después no sabe que ya se comprometió con un
// árbol de 8, y firmaría uno de 5 sin una queja. Un log que se desdice es
// exactamente lo que PROTOCOL.md §3 prohíbe, y que el testigo lo detecte luego
// no arregla que el log lo haya hecho.
func TestLockSurvivesDeathBetweenSignAndCosign(t *testing.T) {
	sc := newScene(t, 8)

	// El log firma... y aquí muere el proceso. NO se llama al testigo.
	signed, err := sc.adapter.SignCheckpoint(8)
	if err != nil {
		t.Fatal(err)
	}
	c, err := checkpoint.ParseNote(signed)
	if err != nil {
		t.Fatal(err)
	}
	if c.Size != 8 {
		t.Fatalf("se firmó un árbol de %d, want 8", c.Size)
	}
	// El testigo no vio nada: sigue sin recordar este log.
	if _, ok := sc.witness.Last(testOrigin); ok {
		t.Fatal("el testigo recuerda algo y no se le llamó")
	}
	// Y en la tabla de checkpoints tampoco hay nada, porque solo se guarda la
	// nota cosignada. Ese es el hueco.
	if _, err := sc.store.LastCheckpoint(); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("LastCheckpoint = %v, want ErrNotFound: aún no hay nada cosignado", err)
	}

	// Reinicio.
	adapter := sc.reopen(t)

	// El cerrojo sigue en pie: se rehidrató del disco.
	last, ok := adapter.Log.Last()
	if !ok {
		t.Fatal("tras reiniciar, el log no recuerda el checkpoint que firmó")
	}
	if last.Size != 8 {
		t.Fatalf("el log recuerda un árbol de %d, want 8", last.Size)
	}

	// Y se niega a desdecirse.
	if _, err := adapter.SignCheckpoint(5); !errors.Is(err, checkpoint.ErrRollback) {
		t.Fatalf("tras reiniciar firmó un árbol MENOR: err = %v, want %v", err, checkpoint.ErrRollback)
	}

	// Lo que sí puede es seguir hacia delante, y completar lo que dejó a medias.
	if _, err := SyncWithWitness(context.Background(), adapter, sc.client); err != nil {
		t.Fatalf("no pudo retomar la sincronización tras el reinicio: %v", err)
	}
	if w, _ := sc.witness.Last(testOrigin); w.Size != 8 {
		t.Errorf("el testigo cosignó %d, want 8", w.Size)
	}
}

// TestLockRefusesSameSizeWithDifferentRootAfterRestart cubre la otra forma de
// desdecirse: mismo tamaño, otra raíz. Es más sutil que el retroceso y
// exactamente igual de grave.
func TestLockRefusesSameSizeWithDifferentRootAfterRestart(t *testing.T) {
	sc := newScene(t, 6)
	if _, err := sc.adapter.SignCheckpoint(6); err != nil {
		t.Fatal(err)
	}
	adapter := sc.reopen(t)

	// Se firma un checkpoint de tamaño 6 con una raíz inventada, saltándose el
	// adaptador —que la calcularía bien— para llegar al cerrojo.
	fake := make([]byte, checkpoint.RootSize)
	for i := range fake {
		fake[i] = byte(i)
	}
	_, err := adapter.Log.Sign(checkpoint.Checkpoint{Origin: testOrigin, Size: 6, RootHash: fake})
	if !errors.Is(err, checkpoint.ErrRollback) {
		t.Errorf("firmó dos raíces distintas para el tamaño 6: err = %v", err)
	}
}

// TestLockIsPersistedBeforeTheNoteIsReturned comprueba el ORDEN, que es lo que
// hace útil al cerrojo: cuando SignCheckpoint devuelve, el compromiso ya está
// en disco. Si se guardara después, la ventana seguiría abierta, solo que más
// estrecha.
func TestLockIsPersistedBeforeTheNoteIsReturned(t *testing.T) {
	sc := newScene(t, 4)
	if raw, err := sc.store.LastSigned(); err != nil || raw != nil {
		t.Fatalf("antes de firmar ya había estado: %v, %v", raw, err)
	}

	signed, err := sc.adapter.SignCheckpoint(4)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := sc.store.LastSigned()
	if err != nil {
		t.Fatal(err)
	}
	if raw == nil {
		t.Fatal("SignCheckpoint devolvió la nota sin haberla persistido")
	}
	if string(raw) != string(signed) {
		t.Error("lo persistido no son los bytes exactos que se devolvieron")
	}
}

// TestBindRejectsForeignState: una memoria con el checkpoint de otro log no se
// acepta. Sería atarse a un cerrojo que no es el suyo.
func TestBindRejectsForeignState(t *testing.T) {
	sc := newScene(t, 3)

	otherPriv := keyFrom(60)
	otherSigner, err := checkpoint.NewSigner("otro.example/log", otherPriv)
	if err != nil {
		t.Fatal(err)
	}
	foreign, err := checkpoint.Sign(checkpoint.Checkpoint{
		Origin: "otro.example/log", Size: 2, RootHash: ledger.Root([][]byte{{1}, {2}}),
	}, otherSigner)
	if err != nil {
		t.Fatal(err)
	}
	if err := sc.store.PutLastSigned(foreign); err != nil {
		t.Fatal(err)
	}

	signer, err := checkpoint.NewSigner(testOrigin, keyFrom(50))
	if err != nil {
		t.Fatal(err)
	}
	lg, err := checkpoint.NewLog(testOrigin, signer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewStoreLog(sc.store, lg); !errors.Is(err, checkpoint.ErrOrigin) {
		t.Errorf("err = %v, want %v", err, checkpoint.ErrOrigin)
	}
}
