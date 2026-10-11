package main

import (
	"reflect"
	"strings"
	"testing"
)

// partirOrden parte una orden impresa como la partiría quien la pega en la shell de goos:
// en POSIX, con comillas simples, dobles y la barra invertida fuera de comillas; en
// Windows, con las reglas con que un programa parte su línea de órdenes
// (CommandLineToArgvW, las que sigue Go), donde la barra invertida solo cuenta delante
// de una comilla.
func partirOrden(goos, s string) []string {
	if goos == "windows" {
		return partirWindows(s)
	}
	return partirPOSIX(s)
}

func partirPOSIX(s string) []string {
	var out []string
	var cur strings.Builder
	hay := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n':
			if hay {
				out = append(out, cur.String())
				cur.Reset()
				hay = false
			}
		case c == '\'':
			hay = true
			j := strings.IndexByte(s[i+1:], '\'')
			if j < 0 {
				j = len(s) - i - 1
			}
			cur.WriteString(s[i+1 : i+1+j])
			i += j + 1
		case c == '"':
			hay = true
			for i++; i < len(s) && s[i] != '"'; i++ {
				if s[i] == '\\' && i+1 < len(s) && strings.ContainsRune(`"\$`+"`", rune(s[i+1])) {
					i++
				}
				cur.WriteByte(s[i])
			}
		case c == '\\' && i+1 < len(s):
			hay = true
			i++
			cur.WriteByte(s[i])
		default:
			hay = true
			cur.WriteByte(c)
		}
	}
	if hay {
		out = append(out, cur.String())
	}
	return out
}

func partirWindows(s string) []string {
	var out []string
	var cur strings.Builder
	hay, dentro := false, false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case (c == ' ' || c == '\t') && !dentro:
			if hay {
				out = append(out, cur.String())
				cur.Reset()
				hay = false
			}
		case c == '\\':
			hay = true
			n := 0
			for i < len(s) && s[i] == '\\' {
				n++
				i++
			}
			if i < len(s) && s[i] == '"' {
				cur.WriteString(strings.Repeat(`\`, n/2))
				if n%2 == 1 {
					cur.WriteByte('"')
				} else {
					dentro = !dentro
				}
			} else {
				cur.WriteString(strings.Repeat(`\`, n))
				i--
			}
		case c == '"':
			hay = true
			dentro = !dentro
		default:
			hay = true
			cur.WriteByte(c)
		}
	}
	if hay {
		out = append(out, cur.String())
	}
	return out
}

// TestArgShellSobreviveALaShellDeCadaPlataforma: cada argumento, entrecomillado para una
// plataforma y partido con las reglas de esa plataforma, vuelve tal cual. Las dos
// plataformas se prueban desde cualquiera; el caso que el CI cazó en windows-2025 —una
// ruta de Windows con espacios, que se entrecomillaba con comillas simples— va el primero.
func TestArgShellSobreviveALaShellDeCadaPlataforma(t *testing.T) {
	casos := map[string][]string{
		"windows": {
			`C:\Users\RUNNER~1\AppData\Local\Temp\Test 1\001\politica.json`,
			`C:\Users\C-SERMIL\Documents\Obsidian Vault\nucleo\politica.json`,
			`C:\sin\espacios\politica.json`,
			`C:\termina en barra\`,
			`C:\dos barras al final\\`,
			`\\servidor\recurso compartido\p.json`,
			`con'comilla simple`,
			`con"comilla doble`,
			`a&b|c<d>e^f(g)h;i,j=k!l%m`,
			``,
		},
		"linux": {
			`/tmp/con espacios/politica.json`,
			`/tmp/sin-espacios/politica.json`,
			`/tmp/it's/p.json`,
			`/tmp/$HOME y "comillas"/p.json`,
			`/tmp/barra\invertida`,
			`/tmp/a;b&c|d*e?f`,
			``,
		},
	}
	for goos, args := range casos {
		for _, a := range args {
			q := argShellPara(goos, a)
			orden := "nucleo --policy-file " + q + " --through 0"
			want := []string{"nucleo", "--policy-file", a, "--through", "0"}
			if got := partirOrden(goos, orden); !reflect.DeepEqual(got, want) {
				t.Errorf("%s: %q → %s → %q", goos, a, q, got)
			}
		}
	}
	// En Windows, la barra invertida sola no obliga a entrecomillar; en POSIX, sí.
	if q := argShellPara("windows", `C:\sin\espacios\p.json`); q != `C:\sin\espacios\p.json` {
		t.Errorf("windows entrecomilla una ruta sin espacios: %s", q)
	}
	// Y nunca comillas simples en Windows: cmd las deja dentro del argumento.
	if q := argShellPara("windows", `C:\con espacios\p.json`); strings.Contains(q, "'") {
		t.Errorf("windows con comillas simples: %s", q)
	}
}
