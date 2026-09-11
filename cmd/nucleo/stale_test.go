//go:build testhooks

package main

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// La política fail-stale existe por una frase de la revisión externa que vale
// citar entera: "sin sync con alarma, el sistema abre bonito y no atestado… si
// alguien mira status. Nadie mira status".
//
// Todo lo que se prueba aquí gira alrededor de eso: el aviso tiene que salir sin
// que nadie lo pida, por el canal que un cron manda al correo, y tiene que
// basarse en el reloj del TESTIGO y no en el de la máquina que podría querer que
// no suene.

// avanzaReloj mueve el reloj de la CLI. El del testigo se queda donde estaba, que
// es justo la situación real: pasa el tiempo y nadie sincroniza.
func avanzaReloj(t *testing.T, d time.Duration) {
	t.Helper()
	base, err := time.Parse(time.RFC3339, testClockRFC)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv(envClock, base.Add(d).UTC().Format(time.RFC3339))
}

// avisoDeFrescura dice si stderr trae el aviso de ESTA política.
//
// No vale buscar "AVISO" a secas: el binario compilado con -tags testhooks
// imprime su propio aviso en cada ejecución, y una aserción sobre la palabra
// suelta pasaría siempre. Lo aprendí fallando: el primer test daba por bueno el
// aviso del gancho y no habría detectado que la política no avisa nunca.
func avisoDeFrescura(errOut string) bool {
	for _, marca := range []string{
		"atestación verificada es de hace",
		"NUNCA ha obtenido una atestación verificada",
		"dice ser del futuro",
	} {
		if strings.Contains(errOut, marca) {
			return true
		}
	}
	return false
}

// freshness saca el objeto de frescura de una salida --json.
func freshness(t *testing.T, out string) map[string]any {
	t.Helper()
	var v map[string]any
	if err := json.Unmarshal([]byte(out), &v); err != nil {
		t.Fatalf("salida no es JSON: %v\n%s", err, out)
	}
	f, ok := v["freshness"].(map[string]any)
	if !ok {
		t.Fatalf("la salida no trae el objeto freshness:\n%s", out)
	}
	return f
}

func TestStaleSinAtestacionNunca(t *testing.T) {
	c := newCLI(t)
	c.initLedger()
	c.sealFile(`{"x":1}`)

	out, errOut, code := c.run("status")
	if code != exitOK {
		t.Fatalf("status salió con %d", code)
	}
	// El código de salida NO cambia: "la historia está íntegra" y "alguien de
	// fuera la vio hace poco" son preguntas distintas, y mezclarlas en un solo
	// código dejaría sin forma de distinguirlas a quien automatiza.
	for _, want := range []string{"NUNCA ha obtenido una atestación verificada", "nucleo sync"} {
		if !strings.Contains(errOut, want) {
			t.Errorf("stderr no contiene %q:\n%s", want, errOut)
		}
	}
	if !strings.Contains(out, "frescura  : ⚠ nunca se obtuvo") {
		t.Errorf("stdout no dice nada de frescura:\n%s", out)
	}
}

func TestStaleTrasElUmbral(t *testing.T) {
	c := newCLI(t)
	c.initLedger()
	c.sealFile(`{"x":1}`)
	url, name, key := startTestWitness(t, c.logPubKey(t))
	c.mustRun("sync", "--witness", url, "--witness-name", name, "--witness-key", key)

	// Recién sincronizado: ni un aviso.
	out, errOut, _ := c.run("status")
	if avisoDeFrescura(errOut) {
		t.Errorf("avisó con una atestación de hace un instante:\n%s", errOut)
	}
	if !strings.Contains(out, "frescura  : ✔") {
		t.Errorf("no dice que la frescura está bien:\n%s", out)
	}

	// Pasan cuatro días sin que nadie sincronice.
	avanzaReloj(t, 100*time.Hour)
	out, errOut, code := c.run("status")
	if code != exitOK {
		t.Fatalf("status salió con %d; la frescura no debe cambiar el código", code)
	}
	for _, want := range []string{"4 días", "umbral: 3 días", name, "lleva 4 días roto"} {
		if !strings.Contains(errOut, want) {
			t.Errorf("stderr no contiene %q:\n%s", want, errOut)
		}
	}
	if !strings.Contains(out, "frescura  : ⚠ la última atestación es de hace 4 días") {
		t.Errorf("stdout:\n%s", out)
	}

	// Con un umbral mayor que la edad, el mismo estado no es incidente. Prueba
	// que el umbral se usa de verdad y no es un adorno.
	_, errOut, _ = c.run("--stale-after", "200h", "status")
	if avisoDeFrescura(errOut) {
		t.Errorf("avisó con --stale-after 200h y una edad de 100h:\n%s", errOut)
	}
}

func TestStaleEnJSONYPorStderrALaVez(t *testing.T) {
	c := newCLI(t)
	c.initLedger()
	c.sealFile(`{"x":1}`)
	url, name, key := startTestWitness(t, c.logPubKey(t))
	c.mustRun("sync", "--witness", url, "--witness-name", name, "--witness-key", key)
	avanzaReloj(t, 100*time.Hour)

	out, errOut, code := c.run("--json", "status")
	if code != exitOK {
		t.Fatalf("código %d", code)
	}
	// En modo --json el aviso SIGUE saliendo, porque va por stderr: es lo que
	// hace que un cron avise solo sin que nadie programe nada.
	if !avisoDeFrescura(errOut) {
		t.Errorf("en --json no avisó por stderr:\n%s", errOut)
	}
	f := freshness(t, out)
	if f["stale"] != true {
		t.Errorf("freshness.stale = %v, want true", f["stale"])
	}
	if f["attested_ever"] != true {
		t.Errorf("freshness.attested_ever = %v, want true", f["attested_ever"])
	}
	if f["witness"] != name {
		t.Errorf("freshness.witness = %v, want %q", f["witness"], name)
	}
	// La fecha guardada es la que afirmó el TESTIGO, no el reloj de esta máquina
	// —que ya está 100 horas más adelante—. Si fuera el local, la atestación
	// parecería recién hecha para siempre.
	if f["attested_at"] != testClockRFC {
		t.Errorf("freshness.attested_at = %v, want %q (el instante del testigo)", f["attested_at"], testClockRFC)
	}
	if edad, ok := f["age_hours"].(float64); !ok || edad < 99 || edad > 101 {
		t.Errorf("freshness.age_hours = %v, want ~100", f["age_hours"])
	}
}

func TestStaleSealAvisaAlSellar(t *testing.T) {
	c := newCLI(t)
	c.initLedger()
	c.sealFile(`{"x":1}`)
	url, name, key := startTestWitness(t, c.logPubKey(t))
	c.mustRun("sync", "--witness", url, "--witness-name", name, "--witness-key", key)
	avanzaReloj(t, 100*time.Hour)

	// Sellar es cuando alguien CONFÍA: acaba de meter un registro que da por
	// protegido. Es el momento de enterarse, no la próxima vez que alguien se
	// acuerde de mirar status.
	out := c.sealFile(`{"x":2}`)
	if !strings.Contains(out, "registro sellado") {
		t.Fatalf("el sellado debe seguir funcionando:\n%s", out)
	}
	_, errOut, code := c.run("seal", "--tenant", testTenant, "--type", "sri.factura.v1",
		"--payload", c.writeTemp(t, `{"x":3}`))
	if code != exitOK {
		t.Errorf("seal salió con %d; la frescura no debe impedir sellar", code)
	}
	if !avisoDeFrescura(errOut) {
		t.Errorf("seal no avisó de la atestación vieja:\n%s", errOut)
	}
}

func TestStaleVerifyLoReporta(t *testing.T) {
	c := newCLI(t)
	c.initLedger()
	c.sealFile(`{"x":1}`)
	url, name, key := startTestWitness(t, c.logPubKey(t))
	c.mustRun("sync", "--witness", url, "--witness-name", name, "--witness-key", key)
	avanzaReloj(t, 100*time.Hour)

	out, errOut, code := c.run("--json", "verify")
	if code != exitOK {
		t.Fatalf("verify salió con %d: la verificación pasó, la frescura es otra cosa", code)
	}
	if !avisoDeFrescura(errOut) {
		t.Errorf("verify no avisó:\n%s", errOut)
	}
	if f := freshness(t, out); f["stale"] != true {
		t.Errorf("verify --json no reporta stale:\n%s", out)
	}
}

func TestStaleRelojDescuadrado(t *testing.T) {
	c := newCLI(t)
	c.initLedger()
	c.sealFile(`{"x":1}`)
	url, name, key := startTestWitness(t, c.logPubKey(t))
	c.mustRun("sync", "--witness", url, "--witness-name", name, "--witness-key", key)

	// El reloj local se va ATRÁS: la atestación queda en el futuro. No es un
	// ataque, es un reloj mal puesto, y callarlo convertiría un reloj roto en
	// una atestación eternamente fresca.
	avanzaReloj(t, -48*time.Hour)
	out, errOut, code := c.run("--json", "status")
	if code != exitOK {
		t.Fatalf("código %d", code)
	}
	if !strings.Contains(errOut, "del futuro") {
		t.Errorf("no avisó del desfase de reloj:\n%s", errOut)
	}
	f := freshness(t, out)
	if f["clock_skew"] != true {
		t.Errorf("freshness.clock_skew = %v, want true", f["clock_skew"])
	}
	// Y no se da por vieja: la edad no se calcula en negativo.
	if f["stale"] != false {
		t.Errorf("freshness.stale = %v; un reloj atrasado no hace vieja la atestación", f["stale"])
	}
}

func TestStaleAfterRechazaValoresAbsurdos(t *testing.T) {
	c := newCLI(t)
	c.initLedger()
	for _, v := range []string{"0", "-1h", "ayer", ""} {
		_, _, code := c.run("--stale-after", v, "status")
		if code != exitUsage {
			t.Errorf("--stale-after %q salió con %d, want %d", v, code, exitUsage)
		}
	}
}

// TestKDFProfileEnInit cubre el perfil de derivación desde la vía del usuario.
//
// Está aquí y no en internal/vault porque lo que puede romperse es la ruta
// completa: que la bandera llegue, que los parámetros se guarden y que lo que
// init IMPRIME sea lo que quedó en la base. Un init que dijera "constrained"
// mientras guarda los valores por omisión sería peor que no tener la opción.
func TestKDFProfileEnInit(t *testing.T) {
	t.Run("constrained se guarda y se informa", func(t *testing.T) {
		c := newCLI(t)
		out := c.mustRun("--json", "init", "--origin", testOrigin,
			"--assume-confirmed", "--kdf-profile", "constrained")
		var v map[string]any
		if err := json.Unmarshal([]byte(out), &v); err != nil {
			t.Fatal(err)
		}
		kdf, ok := v["kdf"].(map[string]any)
		if !ok {
			t.Fatalf("init --json no informa del perfil de KDF:\n%s", out)
		}
		// Los números son los de la guía de OWASP, escritos literales.
		for campo, quiero := range map[string]any{
			"profile": "constrained", "memory_mib": 19.0, "iterations": 2.0, "parallelism": 1.0,
		} {
			if kdf[campo] != quiero {
				t.Errorf("kdf.%s = %v, want %v", campo, kdf[campo], quiero)
			}
		}

		// Y el vault se abre después: si los parámetros guardados no fueran los
		// usados para derivar, cualquier operación que toque el vault fallaría.
		c.sealFile(`{"x":1}`)
	})

	t.Run("el perfil por omisión sigue siendo el fuerte", func(t *testing.T) {
		c := newCLI(t)
		out := c.mustRun("--json", "init", "--origin", testOrigin, "--assume-confirmed")
		var v map[string]any
		if err := json.Unmarshal([]byte(out), &v); err != nil {
			t.Fatal(err)
		}
		kdf := v["kdf"].(map[string]any)
		if kdf["profile"] != "default" || kdf["memory_mib"] != 64.0 {
			t.Errorf("sin bandera, el perfil debería ser default/64 MiB: %v", kdf)
		}
	})

	t.Run("la salida humana avisa de que es más débil", func(t *testing.T) {
		c := newCLI(t)
		out := c.mustRun("init", "--origin", testOrigin, "--assume-confirmed",
			"--kdf-profile", "constrained")
		for _, want := range []string{
			"perfil KDF    : constrained (19 MiB, 2 iteraciones, 1 hilo(s))",
			"Más débil que el perfil por omisión",
			"passphrase más larga",
		} {
			if !strings.Contains(out, want) {
				t.Errorf("init no contiene %q:\n%s", want, out)
			}
		}
	})

	t.Run("un perfil inventado es error de uso, no un vault sorpresa", func(t *testing.T) {
		c := newCLI(t)
		_, errOut, code := c.run("init", "--origin", testOrigin,
			"--assume-confirmed", "--kdf-profile", "barato")
		if code != exitUsage {
			t.Errorf("código = %d, want %d", code, exitUsage)
		}
		if !strings.Contains(errOut, "kdf-profile") {
			t.Errorf("stderr = %q", errOut)
		}
	})
}

// TestStaleLedgerVacioNoGrita: recién instalado, sin un solo bloque, no hay nada
// que atestiguar y por tanto no hay nada que avisar.
//
// Parece un detalle de cortesía y no lo es. El primer `status` de quien acaba de
// instalar esto saldría con una alarma, aprendería ahí mismo que las alarmas de
// este programa se pueden ignorar, y para cuando una importe de verdad ya estará
// entrenado para no leerla. Una alarma que se ignora es peor que no tenerla.
func TestStaleLedgerVacioNoGrita(t *testing.T) {
	c := newCLI(t)
	c.initLedger()

	out, errOut, code := c.run("--json", "status")
	if code != exitOK {
		t.Fatalf("código %d", code)
	}
	if avisoDeFrescura(errOut) {
		t.Errorf("avisó sobre un ledger sin un solo bloque:\n%s", errOut)
	}
	if f := freshness(t, out); f["stale"] != false {
		t.Errorf("freshness.stale = %v en un ledger vacío, want false", f["stale"])
	}

	humano, _, _ := c.run("status")
	if strings.Contains(humano, "frescura") {
		t.Errorf("la salida humana habla de frescura sin historia:\n%s", humano)
	}

	// Y en cuanto hay UN bloque, el aviso sí sale: lo que se silencia es el
	// ledger vacío, no el ledger sin atestiguar.
	c.sealFile(`{"x":1}`)
	_, errOut, _ = c.run("status")
	if !avisoDeFrescura(errOut) {
		t.Errorf("con un bloque sin atestiguar debería avisar:\n%s", errOut)
	}
}
