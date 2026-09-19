package integration_test

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestNingunFuenteSeQuedaFueraDelRepositorio: un fichero que el producto necesita y que
// .gitignore se traga no falla en esta máquina —está en el disco— y falla en el CI, o
// peor, en el clon de quien lo use.
//
// Pasó: el patrón `bin/` sin anclar ignoraba CUALQUIER directorio llamado bin a cualquier
// profundidad, y se llevó sdk/php/bin/dictamen.php, el punto de entrada del tercer
// verificador del diferencial. La compuerta local pasaba con los tres verificadores; el
// CI decía "Could not open input file" (run 35468562784). El propio .gitignore ya
// advertía de esto para `/nucleo` y el aviso no se aplicó a la línea de al lado.
//
// Esta prueba es la que faltaba: recorre lo que git IGNORA dentro de los directorios de
// código y falla si alguno es una fuente. No mira el contenido; mira quién falta.
func TestNingunFuenteSeQuedaFueraDelRepositorio(t *testing.T) {
	raiz := filepath.Join("..", "..")
	// --others --ignored --exclude-standard: lo que está en el disco, no está en el
	// índice y git ignora. Es exactamente la categoría "existe aquí y no existe en el
	// repositorio".
	cmd := exec.Command("git", "-C", raiz, "ls-files", "--others", "--ignored", "--exclude-standard", "-z",
		"--", "cmd", "internal", "profiles", "sdk", "scripts", "testdata", "web")
	salida, err := cmd.Output()
	if err != nil {
		// Sin git —un tarball de fuentes, por ejemplo— no hay nada que comprobar y
		// tampoco nada que arreglar.
		t.Skipf("no se pudo consultar git, se omite: %v", err)
	}

	// Lo que se ignora a propósito y no es fuente: dependencias y artefactos de
	// construcción. Todo lo demás con extensión de código es un hallazgo.
	exentos := []string{"sdk/ts/node_modules/", "sdk/ts/dist/"}
	fuentes := map[string]bool{
		".go": true, ".php": true, ".ts": true, ".js": true, ".mjs": true,
		".py": true, ".sh": true, ".json": true, ".yml": true, ".yaml": true, ".md": true,
	}

	var fuera []string
	for _, f := range strings.Split(string(salida), "\x00") {
		if f == "" {
			continue
		}
		exento := false
		for _, e := range exentos {
			if strings.HasPrefix(f, e) {
				exento = true
				break
			}
		}
		if exento || !fuentes[strings.ToLower(filepath.Ext(f))] {
			continue
		}
		fuera = append(fuera, f)
	}
	if len(fuera) > 0 {
		t.Errorf("estos ficheros existen en el disco y NO en el repositorio, porque .gitignore los ignora:\n  %s\n\n"+
			"Un patrón sin anclar (`bin/`, `dist/`) alcanza cualquier profundidad. Ancla el patrón con `/` "+
			"o añade la excepción, y comprueba con `git check-ignore -v <fichero>`.",
			strings.Join(fuera, "\n  "))
	}
}
