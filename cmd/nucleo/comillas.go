package main

import (
	"path/filepath"
	"runtime"
	"strings"
)

// Las órdenes que la CLI imprime para que alguien las copie (la regla de los mensajes
// de CLAUDE.md: un consejo que no se puede obedecer es peor que ninguno).
//
// Una ruta con espacios tiene que ir entrecomillada, y cómo depende de dónde se pegue la
// orden. El Sprint 19 entrecomillaba con comillas simples en todas partes, y en
// windows-2025 el CI lo cazó: cmd no las entiende, se quedan dentro del argumento, y la
// orden que erase daba para la custodia apuntaba a un fichero que no existe. El 19b pasó
// a comillas dobles en Windows, y la revisión externa del 2026-10-11 (H2, H3) mostró que
// tampoco bastan: dentro de comillas dobles PowerShell expande $HOME y `n, y cmd expande
// %USERNAME%. Ninguna forma sirve para las dos consolas a la vez.
//
// Decisión del dev (Sprint 20b, enmienda de ADR-032 §F): en Windows, las órdenes impresas
// son para PowerShell, la consola por defecto de Windows 10/11; cmd no se promete. En
// PowerShell, las comillas simples no expanden nada. Pegada en cmd, la orden falla a la
// vista —la ruta, con las comillas dentro, no existe—, que es aceptable.
//
// Toda orden impresa empieza por la palabra nucleo, sin comillas. Si alguna vez empezara
// por una ruta entre comillas, en PowerShell tendría que ir precedida de «& »: si no, la
// toma como texto y no la ejecuta.

// argShell devuelve s listo para pegarlo como un argumento en la consola de esta
// plataforma: la shell POSIX, o PowerShell en Windows.
func argShell(s string) string {
	// En Windows, antes de entrecomillar, filepath.Clean quita la \ final de un
	// directorio: PowerShell 5.1 pasa a un programa una ruta con espacios entre comillas
	// dobles, y la \ de antes de la comilla de cierre la escapa y rompe el argv
	// (C:\a b\ llegaba como «C:\a b"»). Es la misma ruta. ("" se deja: Clean daría ".")
	if runtime.GOOS == "windows" && s != "" {
		s = filepath.Clean(s)
	}
	return argShellPara(runtime.GOOS, s)
}

// argShellPara es argShell para una plataforma dada, sin la limpieza de la ruta; existe
// para poder probar las dos desde cualquiera.
func argShellPara(goos, s string) string {
	if goos == "windows" {
		return argPowerShell(s)
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

// comillasSimplesPowerShell son los caracteres que PowerShell toma por comilla simple:
// la ' y las tipográficas ‘ ’ ‚ ‛. Una ruta puede llevar una ’ —un nombre copiado de un
// documento— y, sin duplicarla, cerraría la cadena.
const comillasSimplesPowerShell = "'\u2018\u2019\u201a\u201b"

// argPowerShell: siempre entre comillas simples, que en PowerShell no expanden nada
// —ni $, ni `, ni %, ni !—, con cada comilla simple, de cualquiera de las cinco formas,
// duplicada: así la lee PowerShell como un carácter de la cadena. Siempre, y no solo
// cuando hace falta: en PowerShell hay demasiados caracteres que cambian el sentido de
// una palabra suelta (el guion largo, la #, la @ del principio) para fiarse de una lista.
func argPowerShell(s string) string {
	var b strings.Builder
	b.WriteByte('\'')
	for _, r := range s {
		if strings.ContainsRune(comillasSimplesPowerShell, r) {
			b.WriteRune(r)
		}
		b.WriteRune(r)
	}
	b.WriteByte('\'')
	return b.String()
}
