package vault

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// slip39ImportPath es la ruta de la biblioteca aprobada en ADR-010.
const slip39ImportPath = `"github.com/shurlinet/go-slip39"`

// TestSlip39StaysBehindTheVault hace cumplir la condición con la que se aprobó
// la dependencia: solo internal/vault la conoce, y del código de producción solo
// backup.go. Si mañana hay que reemplazarla, se toca un fichero.
//
// La condición está escrita en ADR-010 y en la cabecera de backup.go, pero una
// condición que solo vive en un comentario se incumple sin que nadie se entere.
// Esta es la que avisa.
func TestSlip39StaysBehindTheVault(t *testing.T) {
	root := filepath.Join("..", "..")
	vaultDir := filepath.Join(root, "internal", "vault")

	var offenders []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if name := d.Name(); path != root && (strings.HasPrefix(name, ".") || name == "testdata") {
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(d.Name(), ".go") {
			return nil
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if !strings.Contains(string(src), slip39ImportPath) {
			return nil
		}
		inVault := filepath.Dir(path) == vaultDir
		isTest := strings.HasSuffix(d.Name(), "_test.go")
		if !inVault || (!isTest && d.Name() != "backup.go") {
			offenders = append(offenders, path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range offenders {
		t.Errorf("%s importa %s: la biblioteca solo puede aparecer en internal/vault/backup.go y en tests de ese paquete", f, slip39ImportPath)
	}

	// Control negativo: si el propio backup.go dejara de importarla, el barrido
	// de arriba pasaría en verde sin comprobar nada.
	src, err := os.ReadFile(filepath.Join(vaultDir, "backup.go"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(src), slip39ImportPath) {
		t.Fatal("backup.go no importa la biblioteca: el test de aislamiento no está mirando nada")
	}
}
