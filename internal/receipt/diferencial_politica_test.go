package receipt

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nucleoledger/nucleo/internal/policy"
)

// TERCER CATÁLOGO DEL DIFERENCIAL: mutaciones de la POLÍTICA (ADR-018 E).
//
// La política es un formato de cable: la CLI (internal/policy) y la página
// (parsePolicyText del bundle) tienen que aceptar y rechazar exactamente los mismos
// textos. Los vectores escritos a mano cubren las reglas; esto cubre lo que a nadie
// se le ocurrió escribir, mutando cada política válida carácter a carácter.

// mutacionPolitica es una entrada del catálogo de políticas.
type mutacionPolitica struct {
	Nombre  string `json:"nombre"`
	Texto   string `json:"texto"`
	GoValid bool   `json:"go_valid"`
	GoErr   string `json:"go_err,omitempty"`
}

func catalogoDePoliticas(t *testing.T) []mutacionPolitica {
	t.Helper()
	files, err := filepath.Glob(filepath.Join("..", "..", "testdata", "vectors", "policy", "valida-*.json"))
	if err != nil || len(files) == 0 {
		t.Fatalf("sin vectores de política válidos: %v", err)
	}
	var out []mutacionPolitica
	add := func(n, texto string) {
		m := mutacionPolitica{Nombre: n, Texto: texto}
		if _, err := policy.Parse([]byte(texto)); err != nil {
			m.GoErr = err.Error()
		} else {
			m.GoValid = true
		}
		out = append(out, m)
	}
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var v struct {
			Name string `json:"name"`
			Text string `json:"text"`
		}
		if err := json.Unmarshal(raw, &v); err != nil {
			t.Fatal(err)
		}
		if len(v.Text) > 4096 {
			continue // el vector del límite de tamaño: mutarlo carácter a carácter no aporta
		}
		// Se muta por RUNAS y no por bytes: un byte suelto de una secuencia UTF-8 no
		// sobrevive al JSON del catálogo (se convierte en U+FFFD) y produciría
		// divergencias que no existen.
		rs := []rune(v.Text)
		for i := range rs {
			et := fmt.Sprintf("%s: %d %q", v.Name, i, string(rs[i]))
			add("borra "+et, string(rs[:i])+string(rs[i+1:]))
			add("duplica "+et, string(rs[:i+1])+string(rs[i:]))
			add("espacio antes de "+et, string(rs[:i])+" "+string(rs[i:]))
			if rs[i] < 0x80 && rs[i] >= 0x40 {
				c := append([]rune{}, rs...)
				c[i] ^= 0x20
				add("mayúsculas/minúsculas en "+et, string(c))
			}
		}
		for _, extra := range []string{"\n", " x", "{}", "\ufeff", " ", "\x00"} {
			add(fmt.Sprintf("%s: añade %q al final", v.Name, extra), v.Text+extra)
			add(fmt.Sprintf("%s: antepone %q", v.Name, extra), extra+v.Text)
		}
		// Estructurales sobre cada miembro de primer nivel.
		for _, k := range []string{"origin", "logKey", "signerKey", "witnesses", "quorum"} {
			clave := `"` + k + `"`
			if !strings.Contains(v.Text, clave) {
				continue
			}
			add(v.Name+": "+k+" en mayúsculas", strings.Replace(v.Text, clave, `"`+strings.ToUpper(k)+`"`, 1))
			add(v.Name+": "+k+" con escape", strings.Replace(v.Text, clave, `"\u00`+fmt.Sprintf("%02x", k[0])+k[1:]+`"`, 1))
			for _, val := range []string{"null", "true", "[]", "{}", `""`, "0", "1", "-1", "1.5", `"x"`} {
				add(fmt.Sprintf("%s: %s duplicado con %s", v.Name, k, val),
					strings.Replace(v.Text, "{", "{"+clave+":"+val+",", 1))
			}
		}
	}
	return out
}

// escribirCatalogoDePoliticas deja el catálogo junto al de recibos.
func escribirCatalogoDePoliticas(t *testing.T, catalogo map[string]any) {
	t.Helper()
	catalogo["politicas"] = catalogoDePoliticas(t)
}
