//go:build !windows

package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestGuardaPermisosDiceSiElDirectorioLosGuarda es el control positivo: en un
// sistema de ficheros normal, la prueba tiene que decir que sí.
//
// Si dijera que no, la CLI daría el diagnóstico de "este directorio no guarda
// permisos" en cualquier despliegue de Linux y el consejo bueno —chmod 600— no
// se daría nunca.
func TestGuardaPermisosDiceSiElDirectorioLosGuarda(t *testing.T) {
	dir := t.TempDir()

	// Premisa del test, comprobada y no supuesta: este directorio guarda
	// permisos. Si el TMPDIR del que corre los tests está en un sistema que no
	// los guarda —/mnt/c bajo WSL, por ejemplo—, el control positivo no se puede
	// hacer aquí y decirlo es más honesto que fallar.
	testigo := filepath.Join(dir, "sonda")
	if err := os.WriteFile(testigo, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(testigo)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Skipf("el TMPDIR de este entorno no guarda permisos POSIX (%04o): el control positivo no aplica", st.Mode().Perm())
	}

	if !guardaPermisos(dir) {
		t.Error("guardaPermisos dice que no en un directorio que sí los guarda")
	}

	// Y no deja basura: la prueba se hace con un temporal propio y se borra.
	entradas, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entradas) != 1 {
		t.Errorf("la prueba dejó ficheros detrás: %d entradas", len(entradas))
	}
}

// TestGuardaPermisosNoTocaLaClave: la prueba se hace con un fichero propio, no
// arreglándole el modo a la clave.
//
// Una clave que estuvo expuesta lo estuvo. Corregirle los permisos por detrás
// convertiría un incidente en un silencio.
func TestGuardaPermisosNoTocaLaClave(t *testing.T) {
	dir := t.TempDir()
	clave := filepath.Join(dir, "testigo.db.key")
	if err := os.WriteFile(clave, []byte("no soy una clave"), 0o644); err != nil {
		t.Fatal(err)
	}
	guardaPermisos(dir)
	st, err := os.Stat(clave)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o644 {
		t.Errorf("la clave cambió de permisos a %04o: nadie se lo pidió", st.Mode().Perm())
	}
}

// TestElConsejoDePermisosSeAdaptaAlSistemaDeFicheros: cuando el directorio no
// guarda permisos, el mensaje NO manda hacer un chmod que no va a servir.
//
// Es el hallazgo del Sprint 11: un testigo con su memoria en un repositorio
// montado desde Windows arranca la primera vez —crea la clave— y no vuelve a
// arrancar, con un mensaje que dice exactamente lo único que no funciona ahí.
func TestElConsejoDePermisosSeAdaptaAlSistemaDeFicheros(t *testing.T) {
	const ruta = "/sitio/testigo.db.key"

	conChmod := errorDePermisos(ruta, 0o644, true).Error()
	if !strings.Contains(conChmod, "chmod 600 "+ruta) {
		t.Errorf("el consejo de siempre perdió el chmod:\n%s", conChmod)
	}
	if strings.Contains(conChmod, "--db") {
		t.Errorf("el consejo de siempre no tiene que hablar de mudanzas:\n%s", conChmod)
	}

	sinChmod := errorDePermisos(ruta, 0o777, false).Error()
	if strings.Contains(sinChmod, "Corrígelo con:  chmod") {
		t.Errorf("sigue mandando un chmod que no sirve:\n%s", sinChmod)
	}
	for _, quiero := range []string{"NO\n  guarda permisos POSIX", "/mnt/c", "--db"} {
		if !strings.Contains(sinChmod, quiero) {
			t.Errorf("el mensaje no dice %q:\n%s", quiero, sinChmod)
		}
	}
	// Los dos son errores de USO: lo que está mal es el despliegue, no el ledger.
	for _, err := range []error{errorDePermisos(ruta, 0o644, true), errorDePermisos(ruta, 0o777, false)} {
		var ee *exitError
		if !errors.As(err, &ee) || ee.code != exitUsage {
			t.Errorf("%v no es un error de uso", err)
		}
	}
}

// TestElAvisoDeLaPoliticaTambienSeAdapta: el aviso de permisos de la política
// tampoco manda hacer un chmod donde el chmod no hace nada.
//
// Es el mismo hallazgo que en la clave del testigo, encontrado en la misma
// sesión: el ejemplo de integración imprimía este aviso en CADA comando, y su
// consejo era inseguible.
func TestElAvisoDeLaPoliticaTambienSeAdapta(t *testing.T) {
	conChmod := avisoDePermisosDePolitica("/sitio/politica.json", 0o666, true)
	if !strings.Contains(conChmod, "déjala en 0600 o 0644") {
		t.Errorf("el aviso de siempre cambió:\n%s", conChmod)
	}
	sinChmod := avisoDePermisosDePolitica("/sitio/politica.json", 0o777, false)
	if strings.Contains(sinChmod, "déjala en 0600") {
		t.Errorf("sigue mandando un chmod que no sirve:\n%s", sinChmod)
	}
	for _, quiero := range []string{"NO guarda permisos", "/mnt/c", "0777"} {
		if !strings.Contains(sinChmod, quiero) {
			t.Errorf("el aviso no dice %q:\n%s", quiero, sinChmod)
		}
	}
}
