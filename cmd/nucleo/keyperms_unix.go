//go:build !windows

package main

import (
	"os"
	"path/filepath"
)

// checkKeyPerms rechaza una clave privada que otros usuarios puedan leer.
//
// Un testigo cuya clave privada es legible por cualquier usuario de la máquina
// no atestigua nada: quien la lea puede firmar en su nombre, y las cosignatures
// de ese testigo dejan de significar lo que dicen. Rehusar es la única respuesta
// útil; seguir con un aviso dejaría corriendo un testigo que ya no vale.
func checkKeyPerms(path string) error {
	st, err := os.Stat(path)
	if err != nil {
		return usageErr("no se pudo comprobar la clave del testigo %q: %w", path, err)
	}
	perm := st.Mode().Perm()
	if perm&0o077 == 0 {
		return nil
	}
	return errorDePermisos(path, perm, guardaPermisos(filepath.Dir(path)))
}

// errorDePermisos redacta la negativa, y la redacta distinta según el consejo
// sirva o no.
//
// "Corrígelo con chmod 600" es inútil en un directorio que no guarda los
// permisos POSIX: el chmod contesta que sí y el fichero sigue igual. Ahí el
// problema no es el modo del fichero, es dónde está puesto, y eso es lo que hay
// que decir. Salió del ejemplo de integración del Sprint 11: un testigo montado
// sobre un repositorio en /mnt/c arranca la primera vez —crea la clave— y no
// vuelve a arrancar nunca, con un mensaje que no se puede obedecer.
func errorDePermisos(path string, perm os.FileMode, guarda bool) error {
	if !guarda {
		return usageErr(
			"la clave del testigo %q tiene permisos %04o y el directorio que la contiene NO\n"+
				"  guarda permisos POSIX: `chmod 600` dirá que sí y el fichero seguirá igual. Es lo\n"+
				"  que pasa en /mnt/c bajo WSL y en recursos compartidos de red.\n"+
				"  Mueve la memoria del testigo a un sistema de ficheros que sí los guarde y apunta\n"+
				"  ahí --db, por ejemplo:  --db ~/testigo/testigo.db",
			path, perm)
	}
	return usageErr(
		"la clave del testigo %q tiene permisos %04o: la pueden leer otros usuarios.\n"+
			"  Un testigo cuya clave privada es legible por cualquiera no atestigua nada.\n"+
			"  Corrígelo con:  chmod 600 %s",
		path, perm, path)
}

// guardaPermisos comprueba si un directorio conserva lo que se le pide con chmod.
//
// Lo hace con un fichero temporal propio, no tocando la clave: una clave que
// estuvo expuesta lo estuvo, y arreglarle el modo por detrás ocultaría el
// incidente en vez de resolverlo.
//
// Si la prueba no se puede hacer —directorio de solo lectura, por ejemplo—
// devuelve true, es decir, el mensaje de siempre: inventar un diagnóstico de
// sistema de ficheros porque no se pudo crear un fichero temporal sería peor
// que no diagnosticar nada.
func guardaPermisos(dir string) bool {
	f, err := os.CreateTemp(dir, ".nucleo-perms-*")
	if err != nil {
		return true
	}
	nombre := f.Name()
	defer os.Remove(nombre)
	if err := f.Close(); err != nil {
		return true
	}
	if err := os.Chmod(nombre, 0o600); err != nil {
		return true
	}
	st, err := os.Stat(nombre)
	if err != nil {
		return true
	}
	return st.Mode().Perm() == 0o600
}
