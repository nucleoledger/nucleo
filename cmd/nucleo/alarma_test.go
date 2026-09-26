//go:build testhooks

package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

// La alarma de frescura durable (ADR-028).
//
// Todas las comprobaciones de este fichero leen stdout —el JSON— y el código de salida,
// y NINGUNA lee stderr. Es el punto del ADR: en el hosting real el cron termina en
// `> /dev/null 2>&1` y el ERP tira stderr, así que una alarma que solo vive ahí no la
// ve nadie.

// jsonDeSalida parsea stdout, sea un resultado o un objeto de error.
func jsonDeSalida(t *testing.T, out string) map[string]any {
	t.Helper()
	var v map[string]any
	if err := json.Unmarshal([]byte(out), &v); err != nil {
		t.Fatalf("stdout no es JSON: %v\n%s", err, out)
	}
	return v
}

// alertaDe devuelve el objeto "alert" de una salida, o falla.
func alertaDe(t *testing.T, v map[string]any) map[string]any {
	t.Helper()
	a, ok := v["alert"].(map[string]any)
	if !ok {
		t.Fatalf("la salida no trae el objeto alert: %v", v)
	}
	return a
}

// urlMuerta es la de un testigo apagado: un servidor que se cierra antes de usarlo.
func urlMuerta() string {
	srv := httptest.NewServer(http.NotFoundHandler())
	u := srv.URL
	srv.Close()
	return u
}

// TestConElTestigoApagadoSeSellaYLaAlarmaQuedaRegistrada es el test que pide ADR-028:
// con el testigo caído, `seal` sigue sellando y la alarma queda en el ledger, visible
// para el siguiente comando sin haber leído una sola línea de stderr.
func TestConElTestigoApagadoSeSellaYLaAlarmaQuedaRegistrada(t *testing.T) {
	c := newCLI(t)
	c.initLedger()
	c.sealFile(`{"factura":"000001"}`)
	url, name, key := startTestWitness(t, c.logPubKey(t))
	pol := []string{"--witness-name", name, "--witness-key", key}
	c.runWant(t, exitOK, append([]string{"sync", "--witness", url}, pol...)...)

	// El golden de stale_since se calcula aquí, fuera del código: la atestación es del
	// reloj base del test y el umbral por omisión son 72 horas.
	base, err := time.Parse(time.RFC3339, testClockRFC)
	if err != nil {
		t.Fatal(err)
	}
	quiereDesde := base.Add(72 * time.Hour).UTC().Format(time.RFC3339)

	// Cuatro días después, el testigo ya no contesta.
	avanzaReloj(t, 100*time.Hour)
	muerta := urlMuerta()

	t.Run("sync con el testigo caído abre la alarma, y viaja en el objeto de error", func(t *testing.T) {
		out, _, code := c.run(append([]string{"--json", "sync", "--witness", muerta}, pol...)...)
		if code != exitSyncFail {
			t.Fatalf("código %d, want %d", code, exitSyncFail)
		}
		a := alertaDe(t, jsonDeSalida(t, out))
		if a["state"] != "open" || a["new"] != true || a["persisted"] != true {
			t.Errorf("alert = %v, want state:open new:true persisted:true", a)
		}
		if a["stale_since"] != quiereDesde {
			t.Errorf("stale_since = %v, want %s (la atestación más el umbral)", a["stale_since"], quiereDesde)
		}
		if a["reason"] != "age" {
			t.Errorf("reason = %v, want age", a["reason"])
		}
	})

	t.Run("seal SIGUE sellando, y ve la alarma que abrió el sync", func(t *testing.T) {
		f := ficheroUnico(t, c.dir, "payload-*.json", `{"factura":"000002"}`)
		out, _, code := c.run(append([]string{"--json", "seal", "--tenant", testTenant,
			"--type", "sri.factura.v1", "--payload", f}, pol...)...)
		if code != exitOK {
			t.Fatalf("seal con la atestación vieja salió con %d: un registro no sellado se pierde (ADR-028 §A)", code)
		}
		v := jsonDeSalida(t, out)
		if v["index"] != float64(1) {
			t.Errorf("index = %v, want 1", v["index"])
		}
		a := alertaDe(t, v)
		if a["state"] != "open" || a["new"] != false {
			t.Errorf("alert = %v, want state:open new:false (la abrió el sync, no este seal)", a)
		}
	})

	t.Run("alert status la enseña, y --exit-code da 3 mientras nadie la reconozca", func(t *testing.T) {
		out, _, code := c.run(append([]string{"--json", "alert", "status"}, pol...)...)
		if code != exitOK {
			t.Fatalf("alert status salió con %d sin --exit-code", code)
		}
		if a := alertaDe(t, jsonDeSalida(t, out)); a["state"] != "open" {
			t.Errorf("alert = %v", a)
		}
		if _, _, code := c.run(append([]string{"alert", "status", "--exit-code"}, pol...)...); code != exitSyncFail {
			t.Errorf("alert status --exit-code salió con %d, want %d", code, exitSyncFail)
		}
	})

	t.Run("seal --fail-on-stale no escribe y sale con 3, transitorio", func(t *testing.T) {
		f := ficheroUnico(t, c.dir, "payload-*.json", `{"factura":"000003"}`)
		out, _, code := c.run(append([]string{"--json", "seal", "--fail-on-stale", "--tenant", testTenant,
			"--type", "sri.factura.v1", "--payload", f, "--idempotency-key", "factura-000003"}, pol...)...)
		if code != exitSyncFail {
			t.Fatalf("código %d, want %d", code, exitSyncFail)
		}
		v := jsonDeSalida(t, out)
		if v["ok"] != false || v["error_class"] != "transient" {
			t.Errorf("error = %v, want ok:false error_class:transient", v)
		}
		if a := alertaDe(t, v); a["state"] != "open" {
			t.Errorf("el objeto de error no trae la alarma abierta: %v", a)
		}
		st := jsonDeSalida(t, c.mustRun(append([]string{"--json", "status"}, pol...)...))
		if st["tree_size"] != float64(2) {
			t.Errorf("tree_size = %v tras --fail-on-stale, want 2: no se tenía que escribir nada", st["tree_size"])
		}
	})

	t.Run("ack la reconoce, no la cierra, y --exit-code deja de dar 3", func(t *testing.T) {
		v := jsonDeSalida(t, c.mustRun("--json", "alert", "ack", "--by", "operador@ejemplo"))
		if v["acked"] != true {
			t.Errorf("acked = %v", v["acked"])
		}
		a := alertaDe(t, v)
		if a["state"] != "acked" || a["acked_by"] != "operador@ejemplo" || a["alert_acked_at"] == nil {
			t.Errorf("alert = %v, want state:acked con quién y cuándo", a)
		}
		if _, _, code := c.run(append([]string{"alert", "status", "--exit-code"}, pol...)...); code != exitOK {
			t.Errorf("alert status --exit-code salió con %d con la alarma reconocida, want 0", code)
		}
		// Reconocer otra vez no reescribe el primer reconocimiento.
		v2 := jsonDeSalida(t, c.mustRun("--json", "alert", "ack", "--by", "otra-persona"))
		if v2["acked"] != false || alertaDe(t, v2)["acked_by"] != "operador@ejemplo" {
			t.Errorf("el segundo ack reescribió el primero: %v", v2)
		}
	})

	t.Run("un sync que sale bien la cierra sola", func(t *testing.T) {
		v := jsonDeSalida(t, c.mustRun(append([]string{"--json", "sync", "--witness", url}, pol...)...))
		if a := alertaDe(t, v); a["state"] != "none" {
			t.Errorf("tras un sync bueno, alert = %v, want none", a)
		}
		st := jsonDeSalida(t, c.mustRun(append([]string{"--json", "status"}, pol...)...))
		if a := alertaDe(t, st); a["state"] != "none" {
			t.Errorf("status tras el sync bueno: alert = %v", a)
		}
	})

	t.Run("el siguiente episodio es una alarma NUEVA, sin reconocer", func(t *testing.T) {
		avanzaReloj(t, 200*time.Hour)
		st := jsonDeSalida(t, c.mustRun(append([]string{"--json", "status"}, pol...)...))
		a := alertaDe(t, st)
		if a["state"] != "open" || a["new"] != true {
			t.Errorf("alert = %v, want una alarma nueva y abierta", a)
		}
		if _, hay := a["alert_acked_at"]; hay {
			t.Errorf("el reconocimiento del episodio anterior se arrastró al nuevo: %v", a)
		}
	})
}

// TestAckSinAlarmaNoEsUnError: un script que reconoce por si acaso no tiene que
// distinguir el caso.
func TestAckSinAlarmaNoEsUnError(t *testing.T) {
	c := newCLI(t)
	c.initLedger()
	v := jsonDeSalida(t, c.mustRun("--json", "alert", "ack"))
	if v["acked"] != false || alertaDe(t, v)["state"] != "none" {
		t.Errorf("ack sin alarma = %v", v)
	}
}

// TestLaAlarmaQueNoSePuedeGuardarLoDice: si el ledger no se deja leer ni escribir, la
// alarma se publica igual con persisted:false, se dice por stderr, y el comando que la
// juzgó no falla por ello.
func TestLaAlarmaQueNoSePuedeGuardarLoDice(t *testing.T) {
	c := newCLI(t)
	c.initLedger()
	c.sealFile(`{"x":1}`)

	stderr, err := os.CreateTemp(t.TempDir(), "stderr-*")
	if err != nil {
		t.Fatal(err)
	}
	defer stderr.Close()
	e := &env{dir: c.dir, stdout: stderr, stderr: stderr}
	s, res, err := e.openStoreWith(nil)
	if err != nil {
		t.Fatal(err)
	}
	st, err := checkStaleness(s, res, false, now(), DefaultStaleAfter, res.TreeSize)
	if err != nil {
		t.Fatal(err)
	}
	if !st.Stale {
		t.Fatal("premisa: un ledger con bloques y sin atestación está viejo")
	}
	s.Close() // a partir de aquí, cualquier lectura o escritura falla

	a := registraAlarma(e, s, st)
	if a.Guardada {
		t.Error("persisted:true con un ledger cerrado")
	}
	if got := a.json()["persisted"]; got != false {
		t.Errorf("json persisted = %v", got)
	}
	raw, err := os.ReadFile(stderr.Name())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "no se pudo leer la alarma de frescura") {
		t.Errorf("no lo dijo por stderr:\n%s", raw)
	}
}
