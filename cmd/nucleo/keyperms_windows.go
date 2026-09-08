//go:build windows

package main

// checkKeyPerms no comprueba nada en Windows, y conviene decir por qué.
//
// Los permisos que Go expone en Windows a través de FileMode son una traducción
// aproximada: el control de acceso real vive en la ACL del fichero, que no se ve
// desde ahí. Comprobar el bit de "otros" daría un resultado que no significa lo
// que parece —falsos positivos en ficheros perfectamente protegidos y, peor,
// falsos negativos en ficheros abiertos de par en par—.
//
// Una comprobación que puede decir "está bien" cuando no lo está es peor que no
// tenerla: da una confianza que no se ha ganado. Quien despliegue un testigo en
// Windows debe restringir la ACL del fichero por su cuenta; está dicho en
// docs/RELEASING.md.
func checkKeyPerms(path string) error { return nil }
