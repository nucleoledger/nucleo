package reconcile

import (
	"encoding/json"
	"slices"
	"testing"
)

// TestCompatibilidadConPolitica07 (ADR-033 §C y su enmienda): con una política sin los
// miembros de 0.8-draft, el informe es exactamente el de v0.4.0-alpha salvo la
// regularización. Lo esperado está escrito a mano a partir de lo que v0.4.0-alpha decía de
// esta misma cadena —los motivos, copiados de su código en el tag—, no calculado con el
// código de ahora.
//
// La cadena tiene de todo: una supresión autorizada, una no autorizada que nadie arregla y
// otra no autorizada que una autorizada posterior regulariza.
func TestCompatibilidadConPolitica07(t *testing.T) {
	x := []byte(`{"factura":"001"}`)
	y := []byte(`{"factura":"002"}`)
	z := []byte(`{"factura":"003"}`)
	r := []byte(`{"factura":"004"}`)
	hx, hy, hz := hashOf(string(x)), hashOf(string(y)), hashOf(string(z))
	s, err := openLedger(t)
	if err != nil {
		t.Fatal(err)
	}
	apila(t, s,
		factura(x), // 0: suprimido por el 4
		factura(y), // 1: falta (su evento no está autorizado)
		factura(z), // 2: suprimido por el 7
		factura(r), // 3: vivo
		evento(t, hx, autoriza(t, claveSupresion, testOrigin, hx, 0)), // 4: autorizado
		evento(t, hy, autoriza(t, claveAjena, testOrigin, hy, 1)),     // 5: no autorizado
		evento(t, hz, autoriza(t, claveAjena, testOrigin, hz, 2)),     // 6: no autorizado, regularizable
		evento(t, hz, autoriza(t, claveSupresion, testOrigin, hz, 2)), // 7: autorizado
	)
	rep, err := Reconcile(s, FromSlice([]Record{{Index: 3, Payload: r}}), Options{Erasure: autoridad})
	if err != nil {
		t.Fatal(err)
	}

	// Lo que daba v0.4.0-alpha: hallazgos 1 (faltante), 5 y 6 (no autorizadas); suprimidos
	// 0 por el 4 y 2 por el 7. Los motivos, literales de su código.
	const otraClave = "supresión no autorizada: la autorización no verifica con la erasureKey de la política " +
		"(otra clave, otro contenido, otro log u otro through)"
	type h struct {
		status Status
		index  uint64
		reason string
	}
	v04 := []h{{StatusMissing, 1, ""}, {StatusUnauthorizedErasure, 5, otraClave}, {StatusUnauthorizedErasure, 6, otraClave}}
	// Ahora: lo mismo, menos el 6, que pasa a regularized.
	var got []h
	for _, f := range rep.Findings {
		got = append(got, h{f.Status, f.Index, f.Reason})
	}
	if want := slices.DeleteFunc(slices.Clone(v04), func(x h) bool { return x.index == 6 }); !slices.Equal(got, want) {
		t.Errorf("hallazgos = %+v, want %+v", got, want)
	}
	if len(rep.Erased) != 2 || rep.Erased[0].Index != 0 || rep.Erased[0].ErasedBy != 4 || rep.Erased[1].Index != 2 || rep.Erased[1].ErasedBy != 7 {
		t.Errorf("suprimidos = %+v", rep.Erased)
	}
	if len(rep.Regularized) != 1 || rep.Regularized[0].Index != 6 || rep.Regularized[0].RegularizedBy != 7 || rep.Regularized[0].Reason != otraClave {
		t.Errorf("regularizados = %+v", rep.Regularized)
	}

	// El JSON solo GANA campos: cada nombre de v0.4.0-alpha sigue, con el mismo tipo.
	raw, err := rep.JSON()
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	tipos := func(obj map[string]any, campos map[string]string, nuevos ...string) {
		t.Helper()
		for k, v := range obj {
			want, viejo := campos[k]
			if !viejo {
				if !slices.Contains(nuevos, k) {
					t.Errorf("campo %q que ni v0.4.0-alpha ni este sprint tienen", k)
				}
				continue
			}
			var tipo string
			switch v.(type) {
			case float64:
				tipo = "número"
			case string:
				tipo = "cadena"
			case []any:
				tipo = "array"
			case map[string]any:
				tipo = "objeto"
			}
			if tipo != want {
				t.Errorf("campo %q: %s, y en v0.4.0-alpha era %s", k, tipo, want)
			}
		}
	}
	tipos(m, map[string]string{"tree_size": "número", "checked": "número", "verified": "número",
		"findings": "array", "erased": "array"}, "regularized")
	for _, e := range m["erased"].([]any) {
		tipos(e.(map[string]any), map[string]string{"index": "número", "sealed_hash": "cadena", "sealed_at": "cadena",
			"erased_by": "número", "erased_at": "cadena"}, "authorized_by", "erasure_key", "cutoff")
	}
	for _, f := range m["findings"].([]any) {
		tipos(f.(map[string]any), map[string]string{"status": "cadena", "index": "número", "sealed_hash": "cadena",
			"current_hash": "cadena", "sealed_at": "cadena", "tenant": "cadena", "type": "cadena", "reason": "cadena"})
	}
	if _, ok := m["regularized"].([]any); !ok {
		t.Errorf("regularized no es un array: %#v", m["regularized"])
	}
}
