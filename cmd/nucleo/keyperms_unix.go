//go:build !windows

package main

import "os"

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
	if perm := st.Mode().Perm(); perm&0o077 != 0 {
		return usageErr(
			"la clave del testigo %q tiene permisos %04o: la pueden leer otros usuarios.\n"+
				"  Un testigo cuya clave privada es legible por cualquiera no atestigua nada.\n"+
				"  Corrígelo con:  chmod 600 %s",
			path, perm, path)
	}
	return nil
}
