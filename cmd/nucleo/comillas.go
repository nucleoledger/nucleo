package main

import (
	"runtime"
	"strings"
)

// Las órdenes que la CLI imprime para que alguien las copie (la regla de los mensajes
// de CLAUDE.md: un consejo que no se puede obedecer es peor que ninguno).
//
// Una ruta con espacios tiene que ir entrecomillada, y cómo depende de dónde se pegue la
// orden. El Sprint 19 entrecomillaba con comillas simples en todas partes, y en
// windows-2025 el CI lo cazó: cmd no las entiende, se quedan dentro del argumento, y la
// orden que erase daba para la custodia apuntaba a un fichero que no existe. Así que:
// comillas simples en POSIX y comillas dobles en Windows, donde además la barra invertida
// es el separador de las rutas y por sí sola no obliga a nada.

// argShell devuelve s listo para pegarlo como un argumento en la shell de esta
// plataforma.
func argShell(s string) string { return argShellPara(runtime.GOOS, s) }

// argShellPara es argShell para una plataforma dada; existe para poder probar las dos
// desde cualquiera.
func argShellPara(goos, s string) string {
	if goos == "windows" {
		return argWindows(s)
	}
	return argPOSIX(s)
}

// argPOSIX: tal cual si solo lleva caracteres que ninguna shell POSIX interpreta; si
// no, entre comillas simples, que no expanden nada, con cada ' escrito como '\”.
func argPOSIX(s string) string {
	if s != "" && strings.Trim(s, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_@%+=:,./-") == "" {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// especialesWindows son los caracteres que obligan a entrecomillar en cmd o en
// PowerShell. La barra invertida no está: es el separador de las rutas.
const especialesWindows = " \t&|<>^(),;=!'`$%\"@{}"

// argWindows: tal cual si no lleva nada especial; si no, entre comillas dobles, con las
// reglas con que un programa de Windows parte su línea de órdenes (las de
// CommandLineToArgvW, que sigue Go): las barras invertidas solo cuentan delante de una
// comilla, así que las que quedan justo antes de la comilla de cierre se duplican, y
// una comilla dentro se escribe \". (Una ruta de Windows no puede llevar comillas; se
// cubre igual.)
func argWindows(s string) string {
	if s != "" && !strings.ContainsAny(s, especialesWindows) {
		return s
	}
	var b strings.Builder
	b.WriteByte('"')
	barras := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case '\\':
			barras++
			continue
		case '"':
			b.WriteString(strings.Repeat(`\`, 2*barras+1))
		default:
			b.WriteString(strings.Repeat(`\`, barras))
		}
		barras = 0
		b.WriteByte(c)
	}
	b.WriteString(strings.Repeat(`\`, 2*barras))
	b.WriteByte('"')
	return b.String()
}
