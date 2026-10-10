package main

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// TestUnReciboQueNoVerificaNoSeEscribe (revisión del 2026-10-10, hallazgo ALTO): con
// --out, el recibo se verifica ANTES de escribirse. Con una verificación que falla no
// queda nada en el directorio: ni el recibo ni un temporal.
func TestUnReciboQueNoVerificaNoSeEscribe(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "recibo.txt")
	err := entregaRecibo(out, []byte("RECIBO"), func() error { return errors.New("la firma no verifica") })
	if err == nil {
		t.Fatal("entregó un recibo que no verifica")
	}
	var ee *exitError
	if !errors.As(err, &ee) || ee.code != exitVerify {
		t.Errorf("error %v; want el código de verificación %d", err, exitVerify)
	}
	if entradas, _ := os.ReadDir(dir); len(entradas) != 0 {
		t.Fatalf("quedó algo en disco: %v", entradas)
	}
}

// TestUnReciboQueVerificaSeEscribeEntero: si verifica, queda el recibo exacto, en 0600
// donde los permisos significan algo, y sin temporales.
func TestUnReciboQueVerificaSeEscribeEntero(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "recibo.txt")
	llamada := false
	if err := entregaRecibo(out, []byte("RECIBO"), func() error { llamada = true; return nil }); err != nil {
		t.Fatal(err)
	}
	if !llamada {
		t.Fatal("no se verificó")
	}
	got, err := os.ReadFile(out)
	if err != nil || string(got) != "RECIBO" {
		t.Fatalf("recibo escrito %q (%v)", got, err)
	}
	if entradas, _ := os.ReadDir(dir); len(entradas) != 1 {
		t.Errorf("quedaron temporales: %v", entradas)
	}
	if runtime.GOOS != "windows" {
		if st, _ := os.Stat(out); st.Mode().Perm() != 0o600 && guardaPermisos(dir) {
			t.Errorf("permisos %04o; want 0600", st.Mode().Perm())
		}
	}
	// Sin --out no se escribe nada, pero se verifica igual.
	llamada = false
	if err := entregaRecibo("", []byte("RECIBO"), func() error { llamada = true; return nil }); err != nil || !llamada {
		t.Errorf("sin --out: err=%v verificado=%v", err, llamada)
	}
}
