package store

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nucleoledger/nucleo/internal/ledger"
)

// TestLaSupresionNoDejaElContenidoEnElDisco: tras suprimir (ADR-031), los bytes del
// contenido cifrado y de sus compromisos no están en ningún fichero de la base, ni en
// el principal ni en el WAL. Sin secure_delete, el DELETE solo marcaba la página como
// libre y los bytes seguían ahí.
func TestLaSupresionNoDejaElContenidoEnElDisco(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nucleo.db")
	s, _, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	// Marcas que no pueden aparecer por casualidad en un fichero SQLite.
	ct := bytes.Repeat([]byte("CIFRADO-SUPRIMIDO-"), 200)
	compromiso := bytes.Repeat([]byte("COMPROMISO-SUPRIMIDO-"), 20)

	g := bloqueDe(t, nil, []byte("factura de María"), 0)
	h := g.Header.PayloadHash
	if err := s.AppendRecord(Record{
		Block: g,
		Blob:  &Blob{PayloadHash: h, Ciphertext: ct, Nonce: []byte("nonce-24-bytes-de-prueba"), CreatedAt: "2026-09-05T12:00:00Z"},
		Meta:  map[string][]byte{"commit/v1/" + h: compromiso},
	}); err != nil {
		t.Fatal(err)
	}
	// El contenido, en el fichero principal: es el caso de un registro sellado hace
	// tiempo, el normal en una supresión.
	if ok, err := s.PurgeWAL(); err != nil || !ok {
		t.Fatalf("PurgeWAL = %v, %v", ok, err)
	}
	if !enDisco(t, path, ct) {
		t.Fatal("la marca no llegó al disco: el test no estaría comprobando nada")
	}

	evento := bloqueDe(t, g, []byte("evento de supresión"), 0)
	if err := s.AppendRecord(Record{Block: evento, EraseBlob: h, DeleteMeta: []string{"commit/v1/" + h}}); err != nil {
		t.Fatal(err)
	}
	if ok, err := s.PurgeWAL(); err != nil || !ok {
		t.Fatalf("PurgeWAL = %v, %v", ok, err)
	}

	if _, err := s.GetBlob(h); !errors.Is(err, ErrNotFound) {
		t.Errorf("el contenido sigue en la tabla: %v", err)
	}
	if _, err := s.GetMeta("commit/v1/" + h); !errors.Is(err, ErrNotFound) {
		t.Errorf("los compromisos siguen en la tabla: %v", err)
	}
	if enDisco(t, path, ct[:64]) {
		t.Error("los bytes del contenido suprimido siguen en un fichero de la base")
	}
	if enDisco(t, path, compromiso[:42]) {
		t.Error("los bytes de los compromisos suprimidos siguen en un fichero de la base")
	}
	if _, err := s.VerifyFull(); err != nil {
		t.Errorf("la cadena no verifica tras la supresión: %v", err)
	}
}

// TestLaSupresionVaConSuEventoONoVa: si el evento no entra, el contenido no se borra.
func TestLaSupresionVaConSuEventoONoVa(t *testing.T) {
	s := openTemp(t)
	g := bloqueDe(t, nil, []byte("factura"), 0)
	h := g.Header.PayloadHash
	if err := s.AppendRecord(Record{
		Block: g,
		Blob:  &Blob{PayloadHash: h, Ciphertext: []byte("ct"), Nonce: []byte("n"), CreatedAt: "2026-09-05T12:00:00Z"},
	}); err != nil {
		t.Fatal(err)
	}
	// Un evento que no sigue al último bloque: otro génesis.
	malo := bloqueDe(t, nil, []byte("evento"), 0)
	if err := s.AppendRecord(Record{Block: malo, EraseBlob: h}); err == nil {
		t.Fatal("un evento que no encadena no puede entrar")
	}
	if _, err := s.GetBlob(h); err != nil {
		t.Errorf("se borró el contenido sin que entrara su evento: %v", err)
	}
}

// enDisco dice si marca aparece en el fichero de la base o en su WAL.
func enDisco(t *testing.T, path string, marca []byte) bool {
	t.Helper()
	for _, f := range []string{path, path + "-wal"} {
		raw, err := os.ReadFile(f)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(raw, marca) {
			return true
		}
	}
	return false
}

// TestBlocksOfType: devuelve los bloques del tipo, y solo esos, aunque otro campo del
// header contenga el texto del tipo.
func TestBlocksOfType(t *testing.T) {
	s := openTemp(t)
	pub, priv := testKeys(t, 0)
	var prev *ledger.Block
	tipos := []struct{ tenant, typ string }{
		{testTenant, "sri.factura.v1"},
		{testTenant, "nucleo.erasure.v1"},
		{`x"type":"nucleo.erasure.v1"`, "sri.factura.v1"}, // el texto, en otro miembro
		{testTenant, "nucleo.erasure.v1"},
		{testTenant, "nucleo_erasure_v1"}, // el _ de LIKE no es comodín aquí
	}
	for i, c := range tipos {
		h, err := ledger.NewHeader(prev, c.tenant, c.typ, []byte{byte(i)}, "none://", pub, testBase.Add(time.Duration(i)*time.Minute))
		if err != nil {
			t.Fatal(err)
		}
		b, err := ledger.Seal(h, priv)
		if err != nil {
			t.Fatal(err)
		}
		if err := s.AppendBlock(b); err != nil {
			t.Fatal(err)
		}
		prev = b
	}
	got, err := s.BlocksOfType("nucleo.erasure.v1")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Header.Index != 1 || got[1].Header.Index != 3 {
		idx := []uint64{}
		for _, b := range got {
			idx = append(idx, b.Header.Index)
		}
		t.Errorf("BlocksOfType = %v, want [1 3]", idx)
	}
}
