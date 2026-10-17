package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// La documentación vigente deriva sola: en el Sprint 22, SECURITY.md seguía diciendo que la
// firma del bloque no va en la hoja y que el destinatario del recibo no va firmado —G4 y G15
// dicen lo contrario desde la v0.2—, y el README y TODO seguían en v0.2.0-alpha con la v0.4
// preparada. Este test convierte las dos derivas en un fallo del CI.
//
// Las reglas:
//
//   - los límites viven en un solo sitio, la tabla de límites de docs/GARANTIAS.md. Cada
//     viñeta de «Out of scope» de SECURITY.md enlaza docs/GARANTIAS.md y cita al menos un
//     Lnn, y todos los que cita existen en esa tabla. Ninguna cita un Gnn: una garantía no
//     puede ser a la vez un límite.
//   - la versión vigente es la de la entrada más reciente del CHANGELOG que no sea
//     [Unreleased]. El commit que prepara una versión añade su entrada, y desde ese commit
//     —que es el que queda dentro del tag— la versión vigente es la que se va a etiquetar;
//     tras publicarla lo sigue siendo, hasta que se prepare la siguiente. La primera línea
//     de «Status» del README empieza por esa versión, en negrita, y el párrafo «Estado:» de
//     TODO.md la nombra. Lo que el test NO puede ver es si lo que dicen alrededor es verdad:
//     eso es el paso de RELEASING «antes del tag».

var (
	reLimite      = regexp.MustCompile(`\bL(\d+)\b`)
	reGarantia    = regexp.MustCompile(`\bG(\d+)\b`)
	reFilaLimite  = regexp.MustCompile(`(?m)^\| (L\d+) \|`)
	reEntradaLog  = regexp.MustCompile(`(?m)^## \[([^\]]+)\]`)
	enlaceLimites = "docs/GARANTIAS.md"
)

// vinetasFueraDeAlcance devuelve las viñetas de «Out of scope» de SECURITY.md, cada una con
// sus líneas de continuación unidas.
func vinetasFueraDeAlcance(security string) []string {
	i := strings.Index(security, "**Out of scope**")
	if i < 0 {
		return nil
	}
	resto := security[i:]
	if j := strings.Index(resto, "\nIf you think"); j >= 0 {
		resto = resto[:j]
	}
	if j := strings.Index(resto, "\n## "); j >= 0 {
		resto = resto[:j]
	}
	var vinetas []string
	for _, linea := range strings.Split(resto, "\n") {
		switch {
		case strings.HasPrefix(linea, "- "):
			vinetas = append(vinetas, linea)
		case strings.HasPrefix(linea, "  ") && len(vinetas) > 0:
			vinetas[len(vinetas)-1] += " " + strings.TrimSpace(linea)
		}
	}
	return vinetas
}

// limitesDeGarantias devuelve los Lnn de la tabla de límites de GARANTIAS.md.
func limitesDeGarantias(garantias string) map[string]bool {
	limites := map[string]bool{}
	for _, m := range reFilaLimite.FindAllStringSubmatch(garantias, -1) {
		limites[m[1]] = true
	}
	return limites
}

// problemasDeSecurity devuelve, en prosa, lo que incumple cada viñeta.
func problemasDeSecurity(security string, limites map[string]bool) []string {
	vinetas := vinetasFueraDeAlcance(security)
	if len(vinetas) == 0 {
		return []string{"SECURITY.md no tiene viñetas en «Out of scope»: ¿se movió la sección?"}
	}
	var problemas []string
	for _, v := range vinetas {
		corta := v
		if len(corta) > 70 {
			corta = corta[:70] + "…"
		}
		citas := reLimite.FindAllString(v, -1)
		if len(citas) == 0 {
			problemas = append(problemas, "viñeta sin Lnn: "+corta)
		}
		for _, c := range citas {
			if !limites[c] {
				problemas = append(problemas, c+" no existe en la tabla de límites: "+corta)
			}
		}
		if !strings.Contains(v, enlaceLimites) {
			problemas = append(problemas, "viñeta sin enlace a "+enlaceLimites+": "+corta)
		}
		if g := reGarantia.FindString(v); g != "" {
			problemas = append(problemas, "viñeta que cita una garantía ("+g+"): "+corta)
		}
	}
	return problemas
}

// versionVigente devuelve la versión de la entrada más reciente del CHANGELOG que no sea
// [Unreleased], con su «v» delante, como la nombran los tags.
func versionVigente(changelog string) string {
	for _, m := range reEntradaLog.FindAllStringSubmatch(changelog, -1) {
		if m[1] != "Unreleased" {
			return "v" + m[1]
		}
	}
	return ""
}

// primeraLineaDeStatus devuelve la primera línea no vacía de la sección «Status» del README.
func primeraLineaDeStatus(readme string) string {
	i := strings.Index(readme, "\n## Status\n")
	if i < 0 {
		return ""
	}
	for _, linea := range strings.Split(readme[i+len("\n## Status\n"):], "\n") {
		if strings.TrimSpace(linea) != "" {
			return linea
		}
	}
	return ""
}

// parrafoDeEstado devuelve el párrafo de TODO.md que empieza por «Estado:».
func parrafoDeEstado(todo string) string {
	i := strings.Index(todo, "\nEstado:")
	if i < 0 {
		return ""
	}
	parrafo := todo[i+1:]
	if j := strings.Index(parrafo, "\n\n"); j >= 0 {
		parrafo = parrafo[:j]
	}
	return parrafo
}

// problemasDeVersion devuelve lo que no nombra la versión vigente.
func problemasDeVersion(changelog, readme, todo string) []string {
	v := versionVigente(changelog)
	if v == "" {
		return []string{"el CHANGELOG no tiene ninguna entrada con versión"}
	}
	var problemas []string
	if l := primeraLineaDeStatus(readme); !strings.HasPrefix(l, "**"+v+".**") {
		problemas = append(problemas, "README «Status» no empieza por **"+v+".**: "+l)
	}
	if p := parrafoDeEstado(todo); !strings.Contains(p, "`"+v+"`") {
		problemas = append(problemas, "el «Estado:» de TODO.md no nombra `"+v+"`")
	}
	return problemas
}

func leerDocumento(t *testing.T, ruta string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", ruta))
	if err != nil {
		t.Fatalf("no está %s: %v", ruta, err)
	}
	return string(raw)
}

// TestSecurityRemiteCadaLimiteAGarantias: cada viñeta de «Out of scope» es un límite de
// GARANTIAS, con su Lnn y su enlace, y ninguna es una garantía.
func TestSecurityRemiteCadaLimiteAGarantias(t *testing.T) {
	limites := limitesDeGarantias(leerDocumento(t, "docs/GARANTIAS.md"))
	if len(limites) < 20 {
		t.Fatalf("GARANTIAS tiene %d límites; la tabla se movió o cambió de forma", len(limites))
	}
	for _, p := range problemasDeSecurity(leerDocumento(t, "SECURITY.md"), limites) {
		t.Error(p)
	}
}

// TestReadmeYTodoNombranLaVersionVigente: el README y TODO nombran la versión de la
// entrada más reciente del CHANGELOG.
func TestReadmeYTodoNombranLaVersionVigente(t *testing.T) {
	for _, p := range problemasDeVersion(leerDocumento(t, "CHANGELOG.md"),
		leerDocumento(t, "README.md"), leerDocumento(t, "TODO.md")) {
		t.Error(p)
	}
}

// TestLaGuardiaDeLosDocumentosMuerde: con los documentos reales y un fallo reintroducido de
// cada clase, la guardia lo detecta. Sin esto, una guardia que no mirara nada pasaría los
// dos tests de arriba.
func TestLaGuardiaDeLosDocumentosMuerde(t *testing.T) {
	security := leerDocumento(t, "SECURITY.md")
	limites := limitesDeGarantias(leerDocumento(t, "docs/GARANTIAS.md"))
	changelog := leerDocumento(t, "CHANGELOG.md")
	readme := leerDocumento(t, "README.md")
	todo := leerDocumento(t, "TODO.md")
	v := versionVigente(changelog)

	vinetas := vinetasFueraDeAlcance(security)
	if len(vinetas) == 0 {
		t.Fatal("SECURITY.md sin viñetas en «Out of scope»")
	}
	quitarL := regexp.MustCompile(`\(\[L\d+\]\([^)]*\)\)`)
	if !quitarL.MatchString(security) {
		t.Fatal("SECURITY.md ya no cita los límites como ([Lnn](docs/GARANTIAS.md#…)); ajusta este test")
	}
	estropeados := map[string]string{
		"una viñeta sin Lnn":   quitarL.ReplaceAllString(security, ""),
		"un Lnn que no existe": strings.Replace(security, "[L4]", "[L999]", 1),
		"una garantía como límite": strings.Replace(security, "- **A receipt does not prove delivery**",
			"- **A block's signature is not inside its Merkle leaf** (G4)", 1),
		"la viñeta falsa de vuelta, sin Lnn": strings.Replace(security, "\n- **A receipt does not prove delivery**",
			"\n- **A receipt's recipient is not covered by any signature.**\n- **A receipt does not prove delivery**", 1),
	}
	for clase, roto := range estropeados {
		if roto == security {
			t.Errorf("%s: el reemplazo no cambió nada; ajusta este test", clase)
			continue
		}
		if p := problemasDeSecurity(roto, limites); len(p) == 0 {
			t.Errorf("%s: la guardia no lo detectó", clase)
		}
	}

	viejos := map[string][3]string{
		"README en una versión vieja": {changelog, strings.Replace(readme, "**"+v+".**", "**v0.2.0-alpha.**", 1), todo},
		"TODO en una versión vieja":   {changelog, readme, strings.ReplaceAll(todo, "`"+v+"`", "`v0.2.0-alpha`")},
		"una versión nueva sin README ni TODO": {strings.Replace(changelog, "## [Unreleased]\n",
			"## [Unreleased]\n\n## [9.9.9-alpha] — 2099-01-01\n", 1), readme, todo},
	}
	for clase, d := range viejos {
		if p := problemasDeVersion(d[0], d[1], d[2]); len(p) == 0 {
			t.Errorf("%s: la guardia no lo detectó", clase)
		}
	}
}
