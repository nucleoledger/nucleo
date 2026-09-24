package main

import "os"

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
