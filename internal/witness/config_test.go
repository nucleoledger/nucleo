package witness

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

func hexDe(k ed25519.PublicKey) string { return hex.EncodeToString(k) }

const (
	claveA = "1111111111111111111111111111111111111111111111111111111111111111"
	claveB = "2222222222222222222222222222222222222222222222222222222222222222"
)

// TestConfigValida: lo que el ADR-030 documenta se lee tal cual.
func TestConfigValida(t *testing.T) {
	c, err := ParseConfig([]byte(`{
  "name": "testigo.ejemplo.ec/w1",
  "logs": {"ejemplo.ec/a": "` + claveA + `", "ejemplo.ec/b": "` + claveB + `"},
  "retired": {"ejemplo.ec/c": "` + claveA + `"}
}`))
	if err != nil {
		t.Fatal(err)
	}
	if c.Name != "testigo.ejemplo.ec/w1" || len(c.Logs) != 2 || len(c.Retired) != 1 {
		t.Fatalf("leído: %+v", c)
	}
	// retired es opcional.
	if _, err := ParseConfig([]byte(`{"name": "w", "logs": {"o": "` + claveA + `"}}`)); err != nil {
		t.Errorf("sin retired: %v", err)
	}
}

// TestConfigRechaza: el formato es tan estricto como la política, y además tiene sus
// propias reglas.
func TestConfigRechaza(t *testing.T) {
	logs := `"logs": {"ejemplo.ec/a": "` + claveA + `"}`
	for _, c := range []struct{ nombre, doc, dice string }{
		{"miembro repetido", `{"name": "w", "name": "x", ` + logs + `}`, "repetido"},
		{"variante de mayúsculas", `{"Name": "w", ` + logs + `}`, "variante de mayúsculas"},
		{"miembro desconocido", `{"name": "w", ` + logs + `, "quorum": 1}`, "desconocido"},
		{"sin name", `{` + logs + `}`, `falta el miembro "name"`},
		{"sin logs", `{"name": "w"}`, `falta el miembro "logs"`},
		{"logs vacío", `{"name": "w", "logs": {}}`, "no trae ningún log"},
		{"clave en mayúsculas", `{"name": "w", "logs": {"o": "` + strings.ToUpper(strings.Repeat("ab", 32)) + `"}}`, "minúsculas"},
		{"clave corta", `{"name": "w", "logs": {"o": "abcd"}}`, "64 caracteres"},
		{"activo y retirado", `{"name": "w", ` + logs + `, "retired": {"ejemplo.ec/a": "` + claveA + `"}}`, "en logs y en retired"},
		{"booleano", `{"name": true, ` + logs + `}`, "valor no admitido en la configuración del testigo"},
		{"anidado de más", `{"name": "w", "logs": {"o": {"k": "v"}}}`, "objeto anidado"},
		{"origin con espacio", `{"name": "w", "logs": {"con espacio": "` + claveA + `"}}`, "origin"},
		{"name con espacio", `{"name": "con espacio", ` + logs + `}`, "name"},
		{"comentario", `{"name": "w", ` + logs + ` /* x */}`, ""},
		{"BOM", "\xef\xbb\xbf{\"name\": \"w\", " + logs + "}", "BOM"},
	} {
		t.Run(c.nombre, func(t *testing.T) {
			_, err := ParseConfig([]byte(c.doc))
			if !errors.Is(err, ErrConfig) {
				t.Fatalf("error %v; tiene que ser ErrConfig", err)
			}
			if c.dice != "" && !strings.Contains(err.Error(), c.dice) {
				t.Errorf("no dice %q: %v", c.dice, err)
			}
		})
	}
}

// TestConfigApply: los activos se cosignan y los retirados no.
func TestConfigApply(t *testing.T) {
	a := nuevoLog(t, "ejemplo.ec/a", 1)
	c := nuevoLog(t, "ejemplo.ec/c", 3)
	conf, err := ParseConfig([]byte(`{"name": "` + witnessName + `",
		"logs": {"` + a.origin + `": "` + hexDe(a.pub()) + `"},
		"retired": {"` + c.origin + `": "` + hexDe(c.pub()) + `"}}`))
	if err != nil {
		t.Fatal(err)
	}
	w := testigoSobre(t, NewMemState())
	if err := conf.Apply(w); err != nil {
		t.Fatal(err)
	}
	if _, err := w.CosignAt(0, a.firma(2), nil); err != nil {
		t.Errorf("el activo no se cosigna: %v", err)
	}
	if _, err := w.CosignAt(0, c.firma(2), nil); !errors.Is(err, ErrRetiredLog) {
		t.Errorf("el retirado = %v; want ErrRetiredLog", err)
	}
}
