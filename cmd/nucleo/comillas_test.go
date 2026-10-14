package main

import (
	"reflect"
	"strings"
	"testing"
)

// partirOrden parte una orden impresa como la partiría quien la pega en la consola de
// goos: en POSIX, con comillas simples, dobles y la barra invertida fuera de comillas; en
// Windows, como PowerShell (comillasPowerShell). Es el modelo, que corre en cualquier
// plataforma; la shell de verdad la ejecuta comillas_shell_test.go.
func partirOrden(goos, s string) []string {
	if goos == "windows" {
		return partirPowerShell(s)
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

// partirPowerShell: palabras separadas por blancos; dentro de comillas simples, nada
// se expande, y una comilla simple —cualquiera de las cinco que PowerShell reconoce—
// seguida de otra es la segunda, como carácter. Fuera de comillas solo se esperan
// palabras sin nada especial, que es lo único que la CLI imprime sin ellas.
func partirPowerShell(s string) []string {
	var out []string
	var cur strings.Builder
	hay := false
	rs := []rune(s)
	esComilla := func(r rune) bool { return strings.ContainsRune(comillasSimplesPowerShell, r) }
	for i := 0; i < len(rs); i++ {
		r := rs[i]
		switch {
		case r == ' ' || r == '\t':
			if hay {
				out = append(out, cur.String())
				cur.Reset()
				hay = false
			}
		case esComilla(r):
			hay = true
			for i++; i < len(rs); i++ {
				if esComilla(rs[i]) {
					if i+1 < len(rs) && esComilla(rs[i+1]) {
						i++
						cur.WriteRune(rs[i])
						continue
					}
					break
				}
				cur.WriteRune(rs[i])
			}
		default:
			hay = true
			cur.WriteRune(r)
		}
	}
	if hay {
		out = append(out, cur.String())
	}
	return out
}

// TestArgShellSobreviveALaShellDeCadaPlataforma: cada argumento, entrecomillado para una
// plataforma y partido con el modelo de su consola, vuelve tal cual. Las dos plataformas
// se prueban desde cualquiera; la consola de verdad, en comillas_shell_test.go.
func TestArgShellSobreviveALaShellDeCadaPlataforma(t *testing.T) {
	casos := map[string][]string{
		"windows": {
			`C:\Users\RUNNER~1\AppData\Local\Temp\Test 1\001\politica.json`,
			`C:\Users\C-SERMIL\Documents\Obsidian Vault\nucleo\politica.json`,
			`C:\sin\espacios\politica.json`,
			`C:\$HOME\p.json`,
			"C:\\foo`nbar\\p.json",
			`C:\%USERNAME%\p.json`,
			`C:\!USERNAME!\p.json`,
			`\\servidor\recurso compartido\p.json`,
			`con'comilla simple`,
			"con\u2019tipográfica y \u2018las otras\u201a\u201b",
			"dos seguidas '' y \u2019\u2019",
			`con"comilla doble`,
			`a&b|c<d>e^f(g)h;i,j=k!l%m`,
			`C:\año\ñandú\p.json`,
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
	// En Windows, siempre comillas simples, aunque la ruta no lleve nada especial.
	if q := argShellPara("windows", `C:\sin\espacios\p.json`); q != `'C:\sin\espacios\p.json'` {
		t.Errorf("windows no entrecomilla una ruta sin espacios: %s", q)
	}
	// Y nunca comillas dobles en Windows: dentro de ellas PowerShell expande $ y `.
	if q := argShellPara("windows", `C:\$HOME\p.json`); strings.Contains(q, `"`) {
		t.Errorf("windows con comillas dobles: %s", q)
	}
}
