//go:build testhooks

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Los vectores del contrato `--json` (ADR-025).
//
// La salida `--json` de la CLI es un formato de cable: la consumen el SDK de PHP, los
// crons de los integradores y cualquier ERP. Tenía documento —docs/CLI-JSON.md— y no
// tenía vectores, así que el productor escribía lo que quería y el consumidor aceptaba lo
// que llegara. La auditoría del 2026-09-19 encontró el otro extremo de eso en
// SealResult::fromJSON.
//
// Estos vectores los emite la CLI DE VERDAD, con el reloj y la semilla fijos del arnés, y
// los consume la suite de PHP (sdk/php/test/contrato.php). Si la CLI cambia un campo, el
// vector cambia aquí y la suite de PHP dice si el cambio sigue siendo aceptable. Los
// INVÁLIDOS están escritos a mano, porque son justo lo que la CLI nunca produce.
//
// Se regeneran a petición:
//
//	NUCLEO_REGENERAR_VECTORES_CLIJSON=1 go test -tags testhooks ./cmd/nucleo -run TestVectoresCLIJSON
const dirVectoresCLIJSON = "cli-json"

// vectorCLIJSON es la forma de cada fichero.
type vectorCLIJSON struct {
	// Name identifica el caso.
	Name string `json:"name"`
	// Description dice qué demuestra, en español, para quien lea el JSON.
	Description string `json:"description"`
	// Command es la línea que produjo la salida, sin el binario ni --dir.
	Command []string `json:"command,omitempty"`
	// ExitCode es con el que salió la CLI.
	ExitCode int `json:"exit_code"`
	// Stdout es el stdout LITERAL, como cadena: es lo que recibe quien parsea.
	Stdout string `json:"stdout"`
	// Valid dice si el contrato de ADR-025 debe aceptarlo.
	Valid bool `json:"valid"`
	// Reason explica, en los inválidos, qué regla rompen.
	Reason string `json:"reason,omitempty"`
}

// marcaDir es lo que sustituye al directorio temporal del test.
//
// `status` publica `dir`, que es la ruta que se le pasó y cambia en cada ejecución. Es la
// ÚNICA sustitución que se hace sobre la salida literal, y se hace para que el vector se
// pueda comparar byte a byte entre ejecuciones. Para el contrato sigue siendo una cadena
// no vacía, que es lo que CLI-JSON.md exige de ese campo.
const marcaDir = "<DIR>"

// sinRutas quita el directorio del test de una salida JSON.
//
// Sustituye la ruta Y su forma escapada en JSON, y esa segunda mitad la enseñó Windows:
// allí la ruta lleva barras invertidas, dentro del JSON aparecen duplicadas —`C:\\Users`—
// y la sustitución literal no encontraba nada, así que el directorio temporal se colaba
// en el vector y la comparación fallaba solo en ese sistema (run 35815589938).
func sinRutas(texto, dir string) string {
	texto = strings.ReplaceAll(texto, dir, marcaDir)
	if escapado := strings.ReplaceAll(dir, `\`, `\\`); escapado != dir {
		texto = strings.ReplaceAll(texto, escapado, marcaDir)
	}
	return texto
}

func TestVectoresCLIJSON(t *testing.T) {
	regenerar := os.Getenv("NUCLEO_REGENERAR_VECTORES_CLIJSON") == "1"
	dir := filepath.Join("..", "..", "testdata", "vectors", dirVectoresCLIJSON)

	c := newCLI(t)
	var out []vectorCLIJSON
	añade := func(nombre, desc string, code int, args ...string) string {
		t.Helper()
		salida, _ := c.runWant(t, code, args...)
		// También en la línea de comandos: lleva rutas temporales y sin esto cada
		// regeneración produciría un diff que no dice nada.
		limpios := make([]string, len(args))
		for i, a := range args {
			limpios[i] = strings.ReplaceAll(a, c.dir, marcaDir)
		}
		out = append(out, vectorCLIJSON{
			Name:        nombre,
			Description: desc,
			Command:     limpios,
			ExitCode:    code,
			Stdout:      sinRutas(salida, c.dir),
			Valid:       true,
		})
		return salida
	}

	// 1. Un ledger recién creado: el borde de abajo. Sin bloques, signer.state es "none"
	// y la raíz es la del árbol vacío.
	c.initLedger()
	añade("valido-status-vacio", "status sobre un ledger sin bloques: signer.state none y la raíz del árbol vacío",
		exitOK, "--json", "status")

	// 2. Un sellado normal.
	// Nombres FIJOS y no os.CreateTemp: aquí los elijo yo y son distintos entre sí, así
	// que no hay colisión que evitar, y a cambio la línea de comandos del vector no
	// cambia en cada regeneración.
	doc := escribeDoc(t, c.dir, "doc-001.json", `{"factura":"contrato-001"}`)
	añade("valido-seal", "un sellado normal, sin atestación todavía",
		exitOK, "--json", "seal", "--tenant", testTenant, "--type", "sri.factura.v1", "--payload", doc)

	// 3. El mismo contenido otra vez: bloque nuevo con duplicate_of (ADR-020 §A).
	añade("valido-seal-duplicado", "re-sellar el mismo contenido: bloque nuevo y duplicate_of con el anterior",
		exitOK, "--json", "seal", "--tenant", testTenant, "--type", "sri.factura.v1", "--payload", doc)

	// 4. Con clave de idempotencia y su reintento (ADR-020 §D).
	otro := escribeDoc(t, c.dir, "doc-002.json", `{"factura":"contrato-002"}`)
	añade("valido-seal-con-clave", "un sellado con clave de idempotencia",
		exitOK, "--json", "seal", "--tenant", testTenant, "--type", "sri.factura.v1", "--payload", otro,
		"--idempotency-key", "contrato-002")
	añade("valido-seal-idempotente", "el reintento con la misma clave: idempotent true y no se escribió nada",
		exitOK, "--json", "seal", "--tenant", testTenant, "--type", "sri.factura.v1", "--payload", otro,
		"--idempotency-key", "contrato-002")

	// 5. Sincronizado con un testigo y abierto CON política: es el único estado en el que
	// la CLI afirma atestación verificada, y el que un consumidor tiene que aceptar sin
	// dudar. El testigo del arnés es determinista —nombre, semilla y reloj fijos—, así
	// que la nota y la cosignature salen iguales en cada ejecución.
	url, wname, wkey := startTestWitness(t, c.logPubKey(t))
	js, _ := c.runWant(t, exitOK, "--json", "sync", "--witness", url, "--witness-name", wname, "--witness-key", wkey)
	var sync struct {
		Policy map[string]any `json:"policy"`
	}
	if err := json.Unmarshal([]byte(js), &sync); err != nil {
		t.Fatal(err)
	}
	pol, err := json.Marshal(sync.Policy)
	if err != nil {
		t.Fatal(err)
	}
	polPath := filepath.Join(c.dir, "politica.json")
	if err := os.WriteFile(polPath, pol, 0o600); err != nil {
		t.Fatal(err)
	}
	añade("valido-status-atestiguado", "status con política y un testigo que cosignó: attestation verified y firmante verificado",
		exitOK, "--json", "status", "--policy-file", polPath)
	añade("valido-seal-con-politica", "un sellado con política: la frescura sale de la cosignature verificada",
		exitOK, "--json", "seal", "--tenant", testTenant, "--type", "sri.factura.v1",
		"--payload", escribeDoc(t, c.dir, "doc-003.json", `{"factura":"contrato-003"}`), "--policy-file", polPath)

	// 6. Y el objeto de error, que también es contrato (CLI-JSON.md §Convenciones).
	//
	// El error se provoca con una bandera que la CLI valida por su cuenta y NO con un
	// fichero que no existe: el mensaje de "no existe" lo escribe el sistema operativo
	// —"no such file or directory" en Linux, "The system cannot find the file specified."
	// en Windows— y un vector con texto del sistema dentro solo vale en un sistema. Lo
	// que este caso demuestra es la FORMA del objeto de error, no de quién es la frase.
	añade("valido-error-de-uso", "un error de uso: ok false, error y exit_code, y el proceso sale con ese código",
		exitUsage, "--json", "seal", "--tenant", testTenant, "--type", "sri.factura.v1",
		"--payload", doc, "--idempotency-key", "")

	if regenerar {
		escribeVectoresCLIJSON(t, dir, out)
		return
	}
	comparaVectoresCLIJSON(t, dir, out)
}

// escribeDoc deja un documento en el despliegue y devuelve su ruta.
func escribeDoc(t *testing.T, dir, nombre, contenido string) string {
	t.Helper()
	ruta := filepath.Join(dir, nombre)
	if err := os.WriteFile(ruta, []byte(contenido), 0o600); err != nil {
		t.Fatal(err)
	}
	return ruta
}

// escribeVectoresCLIJSON guarda los vectores válidos, uno por fichero.
func escribeVectoresCLIJSON(t *testing.T, dir string, out []vectorCLIJSON) {
	t.Helper()
	for _, v := range out {
		raw, err := json.MarshalIndent(v, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, v.Name+".json"), append(raw, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	t.Logf("%d vectores de contrato escritos en %s", len(out), dir)
}

// comparaVectoresCLIJSON exige que lo que la CLI emite HOY sea lo que dice el vector.
//
// Es la mitad que importa en el día a día: si alguien cambia un campo de la salida, esto
// falla aquí, en Go, en vez de romperle el cron a un integrador.
func comparaVectoresCLIJSON(t *testing.T, dir string, out []vectorCLIJSON) {
	t.Helper()
	for _, v := range out {
		ruta := filepath.Join(dir, v.Name+".json")
		raw, err := os.ReadFile(ruta)
		if err != nil {
			t.Errorf("falta el vector %s: %v\nRegenera con NUCLEO_REGENERAR_VECTORES_CLIJSON=1", v.Name, err)
			continue
		}
		var guardado vectorCLIJSON
		if err := json.Unmarshal(raw, &guardado); err != nil {
			t.Errorf("%s: %v", ruta, err)
			continue
		}
		if guardado.Stdout != v.Stdout {
			t.Errorf("la salida de la CLI ya no es la del vector %s.\n--- vector ---\n%s\n--- ahora ---\n%s\n"+
				"Si el cambio es intencionado, regenera con NUCLEO_REGENERAR_VECTORES_CLIJSON=1 y mira qué dice "+
				"la suite de PHP: el contrato lo consume otro programa (ADR-025).",
				v.Name, guardado.Stdout, v.Stdout)
		}
		if guardado.ExitCode != v.ExitCode {
			t.Errorf("%s: código %d, el vector dice %d", v.Name, v.ExitCode, guardado.ExitCode)
		}
	}
}
