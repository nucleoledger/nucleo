package main

import (
	"fmt"
	"runtime"
	"runtime/debug"
	"strings"
)

// Lo que dice el binario de sí mismo. Los tres los rellena goreleaser con -X
// (.goreleaser.yaml), y los mismos tres pasa la receta de RELEASING «Compilar desde el
// código». Hasta v0.4.0-alpha esas -X no tenían dónde caer: no había variables con esos
// nombres, y el enlazador ignora en silencio una -X que no encuentra.
//
// En un `go build` a secas están vacíos, y lo que falte se saca de debug.ReadBuildInfo.
var (
	version string
	commit  string
	date    string
)

// versionDevel es lo que se dice cuando no hay versión que decir: la misma palabra que
// usa Go para el módulo principal compilado sin versión.
const versionDevel = "(devel)"

// infoVersion es lo que publica `nucleo version`.
type infoVersion struct {
	Version  string
	Commit   string
	Date     string
	Go       string
	Modified bool
}

// leerVersion combina las -X con la información de compilación. Una -X manda sobre lo
// que diga BuildInfo, campo a campo; `modified` sale siempre de BuildInfo, que es el
// único que lo sabe. bi puede ser nil: un binario sin información de compilación.
func leerVersion(v, c, d string, bi *debug.BuildInfo) infoVersion {
	info := infoVersion{Version: v, Commit: c, Date: d, Go: runtime.Version()}
	if bi != nil {
		if bi.GoVersion != "" {
			info.Go = bi.GoVersion
		}
		if info.Version == "" && bi.Main.Version != versionDevel {
			info.Version = bi.Main.Version
		}
		for _, s := range bi.Settings {
			switch s.Key {
			case "vcs.revision":
				if info.Commit == "" {
					info.Commit = s.Value
				}
			case "vcs.time":
				if info.Date == "" {
					info.Date = s.Value
				}
			case "vcs.modified":
				info.Modified = s.Value == "true"
			}
		}
	}
	if info.Version == "" {
		info.Version = versionDevel
	}
	return info
}

// lineaDeVersion es la salida para personas: una línea.
func (i infoVersion) lineaDeVersion() string {
	partes := []string{"nucleo " + i.Version}
	switch {
	case len(i.Commit) > 7:
		partes = append(partes, "commit "+i.Commit[:7])
	case i.Commit != "":
		partes = append(partes, "commit "+i.Commit)
	default:
		partes = append(partes, "commit desconocido")
	}
	if i.Date != "" {
		partes = append(partes, i.Date)
	} else {
		partes = append(partes, "fecha desconocida")
	}
	partes = append(partes, i.Go)
	if i.Modified {
		partes = append(partes, "con cambios sin commitear")
	}
	return strings.Join(partes, " · ")
}

func cmdVersion(e *env, args []string) error {
	if len(args) > 0 {
		return usageErr("version no lleva argumentos: %q", args)
	}
	bi, _ := debug.ReadBuildInfo()
	info := leerVersion(version, commit, date, bi)
	e.out(map[string]any{
		"version":  info.Version,
		"commit":   info.Commit,
		"date":     info.Date,
		"go":       info.Go,
		"modified": info.Modified,
	}, func() {
		fmt.Fprintln(e.stdout, info.lineaDeVersion())
	})
	return nil
}
