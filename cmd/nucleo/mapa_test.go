package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// El mapa del sistema —docs/ARQUITECTURA.md y docs/GARANTIAS.md— cita ficheros,
// funciones, tests y ADR. Un mapa que cita lo que ya no existe miente sin que nadie lo
// note, y en el Sprint 15 dos citas hechas de memoria estaban mal. Este test lo
// convierte en un fallo del CI (Sprint 16).
//
// Convención de cita, la que documentan los dos ficheros:
//
//   - entre comillas invertidas, `ruta/desde/la/raiz` o `ruta/desde/la/raiz#Nombre`;
//     nunca números de línea, que se desfasan solos;
//   - solo se comprueban las rutas cuyo primer tramo es un directorio o fichero de la
//     raíz del repositorio, para no confundir `vault/params/v1` o `ejemplo.ec/x` con
//     ficheros;
//   - en un .go, Nombre es una función, un tipo, un método (Tipo.Metodo), una constante
//     o una variable, y se busca con go/parser; en .ts, .js y .mjs, una función, clase o
//     constante declarada; en .php, Clase o Clase::metodo; en .sh, una función;
//   - cada ADR-NNN que aparezca, citado o no, tiene que existir en docs/adr/.

var documentosDelMapa = []string{"docs/ARQUITECTURA.md", "docs/GARANTIAS.md"}

// TestElMapaNoCitaNadaQueNoExista falla si una cita de los documentos del mapa no
// existe en el repositorio.
func TestElMapaNoCitaNadaQueNoExista(t *testing.T) {
	raiz := filepath.Join("..", "..")
	for _, doc := range documentosDelMapa {
		raw, err := os.ReadFile(filepath.Join(raiz, doc))
		if err != nil {
			t.Fatalf("el mapa no está: %v", err)
		}
		rotas, n := citasRotas(string(raw), raiz)
		if n < 50 {
			t.Errorf("%s cita %d cosas comprobables; un mapa con tan pocas no está mapeando", doc, n)
		}
		for _, r := range rotas {
			t.Errorf("%s: %s", doc, r)
		}
	}
}

// TestElComprobadorDelMapaMuerde: el comprobador detecta una cita inventada de cada
// clase. Sin esto, un comprobador que no comprobara nada pasaría el test de arriba.
func TestElComprobadorDelMapaMuerde(t *testing.T) {
	raiz := filepath.Join("..", "..")
	inventadas := map[string]string{
		"fichero":       "`internal/vault/no-existe.go`",
		"función Go":    "`internal/vault/rekey.go#FuncionInventada`",
		"método Go":     "`internal/vault/rekey.go#Rekey.MetodoInventado`",
		"test":          "`internal/vault/rekey_test.go#TestQueNoExiste`",
		"función TS":    "`sdk/ts/src/receipt.ts#verifyInventado`",
		"método PHP":    "`sdk/php/src/Verifier.php#Verifier::inventado`",
		"función shell": "`scripts/lint.sh#funcionInventada`",
		"ADR":           "la decisión de ADR-999",
	}
	for clase, cita := range inventadas {
		if rotas, _ := citasRotas("texto "+cita+" más texto", raiz); len(rotas) != 1 {
			t.Errorf("%s: la cita inventada %s dio %d errores; want 1 (%v)", clase, cita, len(rotas), rotas)
		}
	}
	// Y las buenas pasan, de cada clase.
	buenas := "`internal/vault/rekey.go#PrepareRekey` `internal/vault/rekey.go#Rekey.Commit` " +
		"`internal/witness/server.go#RetiredBody` `internal/vault/rekey_test.go#TestRekeySinCommitNoCambiaNada` " +
		"`sdk/ts/src/receipt.ts#verifyReceipt` `sdk/php/src/Verifier.php#Verifier::verify` " +
		"`scripts/lint.sh#falla` `deploy/witness/` ADR-030 `vault/params/v1` `ejemplo.ec/x`"
	if rotas, n := citasRotas(buenas, raiz); len(rotas) != 0 || n != 9 {
		t.Errorf("citas buenas: %d comprobadas (want 9), rotas %v", n, rotas)
	}
}

var (
	reCita    = regexp.MustCompile("`([^`\n]+)`")
	reADR     = regexp.MustCompile(`ADR-\d{3}`)
	reRuta    = regexp.MustCompile(`^[A-Za-z0-9_.\-/]+(#[A-Za-z0-9_.:]+)?$`)
	reBloques = regexp.MustCompile("(?s)```.*?```")
)

// citasRotas devuelve las citas de doc que no existen en el repositorio de raiz, y
// cuántas citas comprobables tenía.
func citasRotas(doc, raiz string) (rotas []string, comprobadas int) {
	// Los bloques de código (Mermaid incluido) no son citas: sus nombres son cortos a
	// propósito para que se importen en Excalidraw.
	texto := reBloques.ReplaceAllString(doc, "")

	adrs := map[string]bool{}
	for _, a := range reADR.FindAllString(texto, -1) {
		adrs[a] = true
	}
	for _, a := range claves(adrs) {
		comprobadas++
		if m, _ := filepath.Glob(filepath.Join(raiz, "docs", "adr", a+"-*.md")); len(m) == 0 {
			rotas = append(rotas, a+" no existe en docs/adr/")
		}
	}

	raices := entradasDeLaRaiz(raiz)
	vistas := map[string]bool{}
	for _, m := range reCita.FindAllStringSubmatch(texto, -1) {
		cita := m[1]
		if vistas[cita] || !reRuta.MatchString(cita) {
			continue
		}
		vistas[cita] = true
		ruta, nombre, _ := strings.Cut(cita, "#")
		primero, _, _ := strings.Cut(ruta, "/")
		if !raices[primero] {
			continue
		}
		comprobadas++
		completa := filepath.Join(raiz, filepath.FromSlash(strings.TrimSuffix(ruta, "/")))
		if _, err := os.Stat(completa); err != nil {
			rotas = append(rotas, "`"+cita+"`: el fichero no existe")
			continue
		}
		if nombre != "" && !declara(completa, nombre) {
			rotas = append(rotas, "`"+cita+"`: "+ruta+" no declara "+nombre)
		}
	}
	return rotas, comprobadas
}

// entradasDeLaRaiz son los nombres del primer nivel del repositorio.
func entradasDeLaRaiz(raiz string) map[string]bool {
	out := map[string]bool{}
	es, _ := os.ReadDir(raiz)
	for _, e := range es {
		out[e.Name()] = true
	}
	return out
}

// declara dice si el fichero declara ese nombre.
func declara(fichero, nombre string) bool {
	switch filepath.Ext(fichero) {
	case ".go":
		return declaraGo(fichero, nombre)
	case ".ts", ".js", ".mjs":
		return contiene(fichero, `(function\s*\*?\s+|class\s+|const\s+|let\s+|var\s+)`+regexp.QuoteMeta(nombre)+`\b`)
	case ".php":
		clase, metodo, conMetodo := strings.Cut(nombre, "::")
		if !contiene(fichero, `\bclass\s+`+regexp.QuoteMeta(clase)+`\b`) {
			return false
		}
		return !conMetodo || contiene(fichero, `function\s+`+regexp.QuoteMeta(metodo)+`\s*\(`)
	case ".sh":
		return contiene(fichero, `(?m)^\s*(function\s+)?`+regexp.QuoteMeta(nombre)+`\s*\(\)`)
	}
	return false
}

func contiene(fichero, patron string) bool {
	raw, err := os.ReadFile(fichero)
	return err == nil && regexp.MustCompile(patron).Match(raw)
}

// declaraGo busca el nombre entre las declaraciones de primer nivel del fichero:
// funciones, métodos (Tipo.Metodo), tipos, constantes y variables.
func declaraGo(fichero, nombre string) bool {
	f, err := parser.ParseFile(token.NewFileSet(), fichero, nil, 0)
	if err != nil {
		return false
	}
	for _, d := range f.Decls {
		switch x := d.(type) {
		case *ast.FuncDecl:
			n := x.Name.Name
			if x.Recv != nil && len(x.Recv.List) > 0 {
				tipo := x.Recv.List[0].Type
				if s, ok := tipo.(*ast.StarExpr); ok {
					tipo = s.X
				}
				if id, ok := tipo.(*ast.Ident); ok {
					n = id.Name + "." + n
				}
			}
			if n == nombre {
				return true
			}
		case *ast.GenDecl:
			for _, s := range x.Specs {
				switch sp := s.(type) {
				case *ast.TypeSpec:
					if sp.Name.Name == nombre {
						return true
					}
				case *ast.ValueSpec:
					for _, id := range sp.Names {
						if id.Name == nombre {
							return true
						}
					}
				}
			}
		}
	}
	return false
}

func claves(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
