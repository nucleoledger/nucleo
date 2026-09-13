//go:build testhooks

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// El fichero de política (ADR-017 b) y el snippet de sync (ADR-017 c), por la vía
// del usuario.

func TestPolicyFileAbreConAtestacionYFirmanteVerificados(t *testing.T) {
	c := newCLI(t)
	c.initLedger()
	c.sealFile(`{"x":1}`)
	url, name, key := startTestWitness(t, c.logPubKey(t))

	// sync con banderas imprime la política lista para guardar.
	out := c.mustRun("sync", "--witness", url, "--witness-name", name, "--witness-key", key)
	if !strings.Contains(out, "lista para guardar") || !strings.Contains(out, `"signerKey"`) {
		t.Fatalf("sync no imprimió el snippet de la política:\n%s", out)
	}
	// Y en --json la emite como objeto: se guarda tal cual y tiene que funcionar.
	js := c.mustRun("--json", "sync", "--witness", url, "--witness-name", name, "--witness-key", key)
	var v struct {
		Policy json.RawMessage `json:"policy"`
	}
	if err := json.Unmarshal([]byte(js), &v); err != nil || len(v.Policy) == 0 {
		t.Fatalf("sync --json no trae policy: %v\n%s", err, js)
	}
	path := filepath.Join(c.dir, "politica.json")
	if err := os.WriteFile(path, v.Policy, 0o600); err != nil {
		t.Fatal(err)
	}

	// La política que sync entregó abre con TODO verificado.
	st := c.mustRun("--json", "status", "--policy-file", path)
	var d map[string]any
	if err := json.Unmarshal([]byte(st), &d); err != nil {
		t.Fatal(err)
	}
	if d["attestation"] != "verified" {
		t.Errorf("attestation = %v, want verified", d["attestation"])
	}
	if sg, _ := d["signer"].(map[string]any); sg["state"] != "verified" {
		t.Errorf("signer = %v, want verified: la política trae signerKey", d["signer"])
	}
	humano := c.mustRun("status", "--policy-file", path)
	for _, want := range []string{"firmante  : ✔ verificado", "✔ historia atestiguada hasta 1 de 1"} {
		if !strings.Contains(humano, want) {
			t.Errorf("status no dice %q:\n%s", want, humano)
		}
	}

	// Sin signerKey en las banderas sueltas: atestación sí, firmante NO verificado.
	sin := c.mustRun("status", "--witness-name", name, "--witness-key", key)
	if !strings.Contains(sin, "firmante  : ◐") || !strings.Contains(sin, "NO verificada contra ninguna política") {
		t.Errorf("sin signer-key el firmante debería decir NO verificado:\n%s", sin)
	}

	// Y sync con el fichero, en vez de banderas, también funciona.
	if out := c.mustRun("sync", "--witness", url, "--policy-file", path); !strings.Contains(out, "atestación obtenida") {
		t.Errorf("sync --policy-file:\n%s", out)
	}
}

func TestPolicyFileRechazaLoAmbiguoYLoRoto(t *testing.T) {
	c := newCLI(t)
	c.initLedger()
	path := filepath.Join(c.dir, "p.json")
	escribe := func(s string) {
		if err := os.WriteFile(path, []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	hex32 := strings.Repeat("ab", 32)
	buena := `{"origin":"` + testOrigin + `","logKey":"` + hex32 + `","witnesses":{"w/1":"` + hex32 + `"},"quorum":1}`

	for _, cs := range []struct {
		nombre, contenido string
		args              []string
		quiero            string
	}{
		{"fichero y banderas a la vez", buena, []string{"--policy-file", path, "--witness-name", "w", "--witness-key", hex32}, "no se combina"},
		{"JSON roto", `{"origin":`, []string{"--policy-file", path}, "no es válida"},
		{"clave desconocida (typo)", `{"origin":"x","logKey":"` + hex32 + `","witnessess":{},"quorum":1}`, []string{"--policy-file", path}, "no es válida"},
		{"sin testigos", `{"origin":"x","logKey":"` + hex32 + `","witnesses":{},"quorum":1}`, []string{"--policy-file", path}, "ningún testigo"},
		{"quorum 0", `{"origin":"x","logKey":"` + hex32 + `","witnesses":{"w":"` + hex32 + `"},"quorum":0}`, []string{"--policy-file", path}, "quorum 0"},
		{"logKey corta", `{"origin":"x","logKey":"abcd","witnesses":{"w":"` + hex32 + `"},"quorum":1}`, []string{"--policy-file", path}, "logKey"},
		{"fichero inexistente", "", []string{"--policy-file", filepath.Join(c.dir, "no-existe.json")}, "no-existe"},
	} {
		t.Run(cs.nombre, func(t *testing.T) {
			if cs.contenido != "" {
				escribe(cs.contenido)
			}
			_, errOut := c.runWant(t, exitUsage, append([]string{"status"}, cs.args...)...)
			if !strings.Contains(errOut, cs.quiero) {
				t.Errorf("stderr no contiene %q:\n%s", cs.quiero, errOut)
			}
		})
	}

	// Una política con la clave del log de OTRO ledger: integridad, no uso.
	escribe(buena)
	c.sealFile(`{"x":1}`)
	_, errOut, code := c.run("status", "--policy-file", path)
	if code != exitVerify || !strings.Contains(errOut, "clave del log de la política no coincide") {
		t.Errorf("otra clave del log: esperado código %d\n%s", exitVerify, c.ultima())
	}
}

// TestPolicyFileEsFormatoDeCable: los hallazgos #4 y #8 de la tercera auditoría a
// través de la CLI (ADR-018 A y D). La gramática entera la cubren los vectores de
// testdata/vectors/policy/; aquí se comprueba que la CLI usa ese parser y no otro.
func TestPolicyFileEsFormatoDeCable(t *testing.T) {
	c := newCLI(t)
	c.initLedger()
	c.sealFile(`{"x":1}`)
	url, name, key := startTestWitness(t, c.logPubKey(t))
	js := c.mustRun("--json", "sync", "--witness", url, "--witness-name", name, "--witness-key", key)
	var v struct {
		Policy map[string]any `json:"policy"`
	}
	if err := json.Unmarshal([]byte(js), &v); err != nil {
		t.Fatal(err)
	}
	buena, _ := json.Marshal(v.Policy)
	signer := v.Policy["signerKey"].(string)
	path := filepath.Join(c.dir, "p.json")
	escribe := func(s string, perm os.FileMode) {
		if err := os.WriteFile(path, []byte(s), perm); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, perm); err != nil {
			t.Fatal(err)
		}
	}
	otra := strings.Repeat("ab", 32)
	inyecta := func(extra string) string { return strings.TrimSuffix(string(buena), "}") + "," + extra + "}" }

	for _, cs := range []struct {
		nombre, texto string
		codigo        int
		quiero        string
	}{
		{"el ataque #4: signerKey y signerkey", strings.Replace(inyecta(`"signerkey":"`+signer+`"`), signer, otra, 1),
			exitUsage, "variante de mayúsculas"},
		{"basura detrás del objeto", string(buena) + `{"signerKey":"` + otra + `"} esto no es JSON`, exitUsage, "después del objeto"},
		{"clave en mayúsculas", strings.Replace(string(buena), signer, strings.ToUpper(signer), 1), exitUsage, "minúsculas"},
		{"sin quorum", strings.Replace(string(buena), `,"quorum":1`, "", 1), exitUsage, `falta el miembro "quorum"`},
		{"la misma clave bajo dos nombres",
			strings.Replace(string(buena), `"witnesses":{`, `"witnesses":{"alias.example/w":"`+key+`",`, 1), exitUsage, "dos nombres"},
		{"origin de otro log", strings.Replace(string(buena), testOrigin, "otro.example/log", 1), exitVerify, "origin de la política no es el del ledger"},
	} {
		t.Run(cs.nombre, func(t *testing.T) {
			escribe(cs.texto, 0o600)
			_, errOut, code := c.run("status", "--policy-file", path)
			if code != cs.codigo || !strings.Contains(errOut, cs.quiero) {
				t.Errorf("esperado código %d y stderr con %q\n%s", cs.codigo, cs.quiero, c.ultima())
			}
		})
	}

	t.Run("--policy-file vacío es error de uso, no 'sin política'", func(t *testing.T) {
		_, errOut, code := c.run("status", "--policy-file", "")
		if code != exitUsage || !strings.Contains(errOut, "--policy-file vacío") {
			t.Errorf("esperado código %d y stderr con \"--policy-file vacío\"\n%s", exitUsage, c.ultima())
		}
	})

	t.Run("permisos distintos de 0600 y 0644 avisan", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("los bits de permiso no significan lo mismo en Windows")
		}
		escribe(string(buena), 0o666)
		_, errOut, code := c.run("status", "--policy-file", path)
		if code != exitOK || !strings.Contains(errOut, "tiene permisos 0666") {
			t.Errorf("esperado código %d y el aviso de permisos\n%s", exitOK, c.ultima())
		}
		escribe(string(buena), 0o644)
		if _, errOut, _ := c.run("status", "--policy-file", path); strings.Contains(errOut, "permisos") {
			t.Errorf("0644 no debería avisar:\n%s", errOut)
		}
	})
}
