//go:build testhooks

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nucleoledger/nucleo/internal/policy"
)

// conRetiradas escribe, junto a la política del despliegue, otra con el miembro
// retiredErasureKeys dado, y devuelve su ruta.
func conRetiradas(t *testing.T, c *cli, sp *conSupresion, nombre string, retiradas map[string]uint64, sinActual bool) string {
	t.Helper()
	raw, err := os.ReadFile(sp.politica)
	if err != nil {
		t.Fatal(err)
	}
	var p map[string]any
	if err := json.Unmarshal(raw, &p); err != nil {
		t.Fatal(err)
	}
	p["retiredErasureKeys"] = retiradas
	if sinActual {
		delete(p, "erasureKey")
	}
	raw, _ = json.Marshal(p)
	ruta := filepath.Join(c.dir, nombre)
	if err := os.WriteFile(ruta, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return ruta
}

// claveC es una clave que ningún test de este paquete usa en otro papel: la C de
// testdata/vectors/erasure/rotacion.json.
const claveC = "2543b92ff1095511476adc8369db6ddc933665a11978dda1404ee1066ca9559d"

// TestAvisoDeCorteAbierto (ADR-033 §C): un corte por encima del último índice de la cadena
// deja una ventana —la clave retirada autorizaría lo que se selle hasta él— y reconcile lo
// avisa por stderr, sin cambiar la salida. Un corte igual al último índice no deja ventana
// y no se avisa.
func TestAvisoDeCorteAbierto(t *testing.T) {
	c := newCLI(t)
	sp := c.initConSupresion(t)
	c.sealFile(`{"x":1}`)
	c.sealFile(`{"x":2}`)
	vivos := ficheroUnico(t, c.dir, "vivo-*.jsonl",
		`{"index":0,"payload_b64":"eyJ4IjoxfQ=="}`+"\n"+`{"index":1,"payload_b64":"eyJ4IjoyfQ=="}`+"\n")

	abierto := conRetiradas(t, c, sp, "abierta.json", map[string]uint64{claveC: 2}, false)
	_, errOut := c.runWant(t, exitOK, "reconcile", "--source", vivos, "--policy-file", abierto)
	if !strings.Contains(errOut, "la clave retirada "+claveC+" todavía autoriza eventos hasta el índice 2, y la cadena va\n  por el 1") {
		t.Errorf("no avisa del corte abierto:\n%s", errOut)
	}
	cerrado := conRetiradas(t, c, sp, "cerrada.json", map[string]uint64{claveC: 1}, false)
	if _, errOut := c.runWant(t, exitOK, "reconcile", "--source", vivos, "--policy-file", cerrado); strings.Contains(errOut, "todavía autoriza") {
		t.Errorf("avisa con el corte en el último índice:\n%s", errOut)
	}
}

// nuevaClaveDeSupresion genera con la CLI otra clave de supresión y devuelve su pública y
// sus tarjetas.
func nuevaClaveDeSupresion(t *testing.T, c *cli) (string, []string) {
	t.Helper()
	out := c.mustRun("--json", "erasure-key", "init", "--assume-confirmed")
	var v struct {
		ErasureKey string   `json:"erasure_key"`
		Shares     []string `json:"shares"`
	}
	if err := json.Unmarshal([]byte(out), &v); err != nil || len(v.Shares) < 2 {
		t.Fatalf("erasure-key init --json (%v):\n%s", err, out)
	}
	return v.ErasureKey, v.Shares
}

// TestAutorizarConUnaClaveRetiradaSeNiega (ADR-033 §D): unas tarjetas que reconstruyen una
// clave de retiredErasureKeys no firman nada —lo que firmaran iría después del corte— y el
// mensaje dice que la clave está retirada, desde qué índice, y qué hacer.
func TestAutorizarConUnaClaveRetiradaSeNiega(t *testing.T) {
	c := newCLI(t)
	sp := c.initConSupresion(t) // las tarjetas del entorno son las de sp.erasureKey
	c.sealFile(`{"x":1}`)
	h, _ := contenidoDe(t, c.dir, 0)
	nueva, _ := nuevaClaveDeSupresion(t, c)
	raw, _ := os.ReadFile(sp.politica)
	var p map[string]any
	if err := json.Unmarshal(raw, &p); err != nil {
		t.Fatal(err)
	}
	p["erasureKey"] = nueva
	p["retiredErasureKeys"] = map[string]uint64{sp.erasureKey: 41}
	raw, _ = json.Marshal(p)
	rotada := filepath.Join(c.dir, "rotada.json")
	if err := os.WriteFile(rotada, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	_, errOut := c.runWant(t, exitUsage, "erasure-key", "authorize", "--policy-file", rotada,
		"--payload-hash", h, "--through", "0")
	for _, dice := range []string{"RETIRADA", "retirada desde el índice 41", "tarjetas de la clave actual"} {
		if !strings.Contains(errOut, dice) {
			t.Errorf("el mensaje no dice %q:\n%s", dice, errOut)
		}
	}
	if strings.Contains(errOut, "supresión autorizada") {
		t.Error("firmó")
	}
}

// fragmentoImpreso devuelve la línea «"retiredErasureKeys": {…}» que sync imprime, tal cual.
func fragmentoImpreso(t *testing.T, out string) string {
	t.Helper()
	for _, l := range strings.Split(out, "\n") {
		if l = strings.TrimSpace(l); strings.HasPrefix(l, `"retiredErasureKeys": `) {
			return l
		}
	}
	t.Fatalf("sync no imprimió el fragmento:\n%s", out)
	return ""
}

// TestRotarLaClaveDeSupresionDePuntaAPunta (ADR-033, decisiones 3 y 4; la regla de los
// mensajes): lo que sync imprime se pega TAL CUAL en la política nueva, y esa política hace
// lo que promete.
//
//  1. Con la clave A se suprime el bloque 0 (evento en el 2) y sync atestigua 3 bloques:
//     el fragmento es {A: 2}, en texto y en JSON.
//  2. Política nueva: erasureKey B y la línea del fragmento, pegada en el texto del JSON.
//     Parsea con el parser 0.8.
//  3. reconcile con ella: lo suprimido antes del corte sigue contando, autorizado por la
//     clave retirada.
//  4. Una supresión autorizada con A y sellada después del corte (sin pasar por erase,
//     que la rechazaría) es un hallazgo, y el registro falta: salida 2.
//  5. La misma supresión con B cuenta: erase la sella, el registro queda suprimido, y el
//     evento de A queda regularizado por el de B. Salida 0.
func TestRotarLaClaveDeSupresionDePuntaAPunta(t *testing.T) {
	c := newCLI(t)
	sp := c.initConSupresion(t)
	c.sealFile(`{"venta":"001","cliente":"Ana"}`)
	c.sealFile(`{"venta":"002","cliente":"Luis"}`)
	h0, _ := contenidoDe(t, c.dir, 0)
	c.mustRun("--json", "erase", "--block", "0", "--policy-file", sp.politica,
		"--authorization", c.autoriza(t, sp, h0, 0), "--assume-confirmed")

	// 1. El fragmento, en texto y en JSON.
	texto := c.mustRun("sync", "--witness", sp.url, "--policy-file", sp.politica)
	linea := fragmentoImpreso(t, texto)
	if want := `"retiredErasureKeys": {"` + sp.erasureKey + `":2}`; linea != want {
		t.Fatalf("fragmento %q, want %q\n%s", linea, want, texto)
	}
	js := c.mustRun("--json", "sync", "--witness", sp.url, "--policy-file", sp.politica)
	var sinc struct {
		Rotacion *struct {
			Retired      map[string]uint64 `json:"retiredErasureKeys"`
			AttestedSize uint64            `json:"attested_size"`
		} `json:"erasure_rotation"`
	}
	if err := json.Unmarshal([]byte(js), &sinc); err != nil {
		t.Fatal(err)
	}
	if sinc.Rotacion == nil || sinc.Rotacion.AttestedSize != 3 || len(sinc.Rotacion.Retired) != 1 || sinc.Rotacion.Retired[sp.erasureKey] != 2 {
		t.Fatalf("erasure_rotation:\n%s", js)
	}

	// 2. La política nueva, con la línea pegada tal cual.
	claveB, tarjetasB := nuevaClaveDeSupresion(t, c)
	raw, err := os.ReadFile(sp.politica)
	if err != nil {
		t.Fatal(err)
	}
	vieja := string(raw)
	if !strings.Contains(vieja, sp.erasureKey) || !strings.HasPrefix(vieja, "{") {
		t.Fatalf("política inesperada: %s", vieja)
	}
	nueva := "{" + linea + "," + strings.Replace(vieja[1:], sp.erasureKey, claveB, 1)
	rotada := filepath.Join(c.dir, "rotada.json")
	if err := os.WriteFile(rotada, []byte(nueva), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := policy.Parse([]byte(nueva))
	if err != nil {
		t.Fatalf("la política con el fragmento pegado no parsea: %v\n%s", err, nueva)
	}
	if f.ErasureKey != claveB || f.RetiredErasureKeys[sp.erasureKey] != 2 {
		t.Fatalf("política leída: %+v", f)
	}

	// 3. Lo de antes del corte sigue contando.
	vivos := ficheroVivo(t, c.dir, 1, `{"venta":"002","cliente":"Luis"}`)
	out := c.mustRun("--json", "reconcile", "--source", vivos, "--policy-file", rotada)
	var rep struct {
		OK       bool `json:"ok"`
		Findings []struct {
			Status string `json:"status"`
			Index  uint64 `json:"index"`
			Reason string `json:"reason"`
		} `json:"findings"`
		Erased []struct {
			Index        uint64  `json:"index"`
			ErasedBy     uint64  `json:"erased_by"`
			AuthorizedBy string  `json:"authorized_by"`
			ErasureKey   string  `json:"erasure_key"`
			Cutoff       *uint64 `json:"cutoff"`
		} `json:"erased"`
		Regularized []struct {
			Index         uint64 `json:"index"`
			RegularizedBy uint64 `json:"regularized_by"`
			ErasureKey    string `json:"erasure_key"`
		} `json:"regularized"`
	}
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatal(err)
	}
	if !rep.OK || len(rep.Erased) != 1 || rep.Erased[0].Index != 0 || rep.Erased[0].AuthorizedBy != "retiredErasureKeys" ||
		rep.Erased[0].ErasureKey != sp.erasureKey || rep.Erased[0].Cutoff == nil || *rep.Erased[0].Cutoff != 2 {
		t.Fatalf("con la política rotada, lo suprimido antes del corte:\n%s", out)
	}

	// 4. Con la clave vieja, después del corte: hallazgo.
	c.sealFile(`{"venta":"003","cliente":"María Pérez"}`) // bloque 3
	h3, _ := contenidoDe(t, c.dir, 3)
	conA := c.autoriza(t, sp, h3, 3)     // la política vieja: la custodia de A aún tiene sus tarjetas
	sellaSupresionConCID(t, c, h3, conA) // bloque 4, después del corte 2
	out, _ = c.runWant(t, exitVerify, "--json", "reconcile", "--source", vivos, "--policy-file", rotada)
	rep.Findings, rep.Erased, rep.Regularized = nil, nil, nil
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatal(err)
	}
	if rep.OK || len(rep.Findings) != 2 || rep.Findings[0].Index != 3 || rep.Findings[0].Status != "faltante" ||
		rep.Findings[1].Index != 4 || !strings.Contains(rep.Findings[1].Reason, "después de su corte 2") {
		t.Fatalf("la clave retirada después del corte:\n%s", out)
	}

	// 5. La misma supresión con B: cuenta, y regulariza el evento de A.
	t.Setenv(envCards, tarjetasB[0]+"|"+tarjetasB[1])
	spB := *sp
	spB.politica = rotada
	conB := c.autoriza(t, &spB, h3, 3)
	c.mustRun("--json", "erase", "--block", "3", "--policy-file", rotada, "--authorization", conB, "--assume-confirmed")
	out = c.mustRun("--json", "reconcile", "--source", vivos, "--policy-file", rotada)
	rep.Findings, rep.Erased, rep.Regularized = nil, nil, nil
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatal(err)
	}
	if !rep.OK || len(rep.Findings) != 0 || len(rep.Erased) != 2 || rep.Erased[1].Index != 3 || rep.Erased[1].ErasedBy != 5 ||
		rep.Erased[1].AuthorizedBy != "erasureKey" || rep.Erased[1].ErasureKey != claveB ||
		len(rep.Regularized) != 1 || rep.Regularized[0].Index != 4 || rep.Regularized[0].RegularizedBy != 5 {
		t.Fatalf("con la clave nueva:\n%s", out)
	}
}

// TestSinErasureKeyNoHayFragmento (ADR-033, decisión 3): sin erasureKey en la política, o
// con banderas sueltas, sync no conoce ninguna clave de supresión: erasure_rotation es
// null y el texto no habla de rotar.
func TestSinErasureKeyNoHayFragmento(t *testing.T) {
	c := newCLI(t)
	c.initLedger()
	c.sealFile(`{"x":1}`)
	url, name, key := startTestWitness(t, c.logPubKey(t))
	js := c.mustRun("--json", "sync", "--witness", url, "--witness-name", name, "--witness-key", key)
	var v map[string]any
	if err := json.Unmarshal([]byte(js), &v); err != nil {
		t.Fatal(err)
	}
	if r, ok := v["erasure_rotation"]; !ok || r != nil {
		t.Errorf("erasure_rotation = %#v (presente %v), want null", r, ok)
	}
	if out := c.mustRun("sync", "--witness", url, "--witness-name", name, "--witness-key", key); strings.Contains(out, "retiredErasureKeys") {
		t.Errorf("habla de rotar sin erasureKey:\n%s", out)
	}
}

// conSupresionNoAutorizada prepara un ledger cuyo bloque 0 tiene ya una supresión NO
// autorizada (evento en el bloque 2, con la firma de la autorización alterada) y devuelve
// los argumentos de un erase autorizado del bloque 0, que la regulariza.
func conSupresionNoAutorizada(t *testing.T) (*cli, []string, string) {
	t.Helper()
	c := newCLI(t)
	sp := c.initConSupresion(t)
	c.sealFile(`{"venta":"001","cliente":"Ana"}`)
	c.sealFile(`{"venta":"002","cliente":"Luis"}`)
	h0, _ := contenidoDe(t, c.dir, 0)
	buena := c.autoriza(t, sp, h0, 0)
	i := len(buena) - 10
	repl := byte('A')
	if buena[i] == 'A' {
		repl = 'B'
	}
	mala := buena[:i] + string(repl) + buena[i+1:]
	sellaSupresionConCID(t, c, h0, mala) // bloque 2: la supresión que nadie autorizó
	return c, []string{"erase", "--block", "0", "--policy-file", sp.politica, "--authorization", buena}, h0
}

// TestRegularizarEsRatificar (Sprint 31, cierre del C1; ADR-033, decisión 4): cuando erase
// va a sellar un evento autorizado sobre un contenido que ya tiene una supresión no
// autorizada, lo dice ANTES de sellar —en la confirmación tecleada, o por stderr con
// --assume-confirmed— y lo deja en la salida: en el texto y en regularizes de --json.
// Sin supresión previa no hay aviso ni regularizes: la salida es la de siempre.
func TestRegularizarEsRatificar(t *testing.T) {
	const aviso = "esto REGULARIZA la supresión no autorizada del evento 2 ("
	const ratificar = "regularizar es ratificar ese borrado: hazlo solo si la supresión estaba pedida de verdad."

	t.Run("la confirmación lo muestra y --json lo deja", func(t *testing.T) {
		c, args, _ := conSupresionNoAutorizada(t)
		var errOut string
		conEntrada(t, "00000000\n", func() {
			_, errOut = c.runWant(t, exitUsage, args...)
		})
		if !strings.Contains(errOut, aviso) || !strings.Contains(errOut, ratificar) {
			t.Fatalf("la confirmación no dice que regulariza:\n%s", errOut)
		}
		if strings.Index(errOut, "REGULARIZA") > strings.Index(errOut, "Para confirmar") {
			t.Errorf("el aviso va después de pedir la confirmación:\n%s", errOut)
		}
		if bloques(t, c.dir) != 3 {
			t.Fatal("una confirmación equivocada selló algo")
		}

		out, errOut := c.runWant(t, exitOK, append([]string{"--json"}, append(args, "--assume-confirmed")...)...)
		if !strings.Contains(errOut, aviso) {
			t.Errorf("con --json --assume-confirmed no avisa por stderr:\n%s", errOut)
		}
		var v struct {
			Index       uint64 `json:"index"`
			Regularizes []struct {
				Index  uint64 `json:"index"`
				Reason string `json:"reason"`
			} `json:"regularizes"`
		}
		if err := json.Unmarshal([]byte(out), &v); err != nil {
			t.Fatal(err)
		}
		if v.Index != 3 || len(v.Regularizes) != 1 || v.Regularizes[0].Index != 2 || v.Regularizes[0].Reason == "" {
			t.Fatalf("regularizes:\n%s", out)
		}
	})

	t.Run("con --assume-confirmed queda en el texto", func(t *testing.T) {
		c, args, _ := conSupresionNoAutorizada(t)
		out, errOut := c.runWant(t, exitOK, append(args, "--assume-confirmed")...)
		if !strings.Contains(errOut, aviso) || !strings.Contains(out, aviso) || !strings.Contains(out, ratificar) {
			t.Fatalf("el aviso no queda en la salida:\nstdout:\n%s\nstderr:\n%s", out, errOut)
		}
	})

	t.Run("sin supresión previa no hay aviso", func(t *testing.T) {
		c := newCLI(t)
		sp := c.initConSupresion(t)
		c.sealFile(`{"venta":"001","cliente":"Ana"}`)
		h0, _ := contenidoDe(t, c.dir, 0)
		out, errOut := c.runWant(t, exitOK, "--json", "erase", "--block", "0", "--policy-file", sp.politica,
			"--authorization", c.autoriza(t, sp, h0, 0), "--assume-confirmed")
		var v map[string]any
		if err := json.Unmarshal([]byte(out), &v); err != nil {
			t.Fatal(err)
		}
		if r, ok := v["regularizes"]; ok {
			t.Errorf("regularizes = %#v sin nada que regularizar; no tenía que salir", r)
		}
		if strings.Contains(out+errOut, "REGULARIZA") {
			t.Errorf("avisa sin nada que regularizar:\n%s\n%s", out, errOut)
		}
	})
}

// regularizadasDe ejecuta reconcile --json con la política dada y devuelve, de cada
// supresión regularizada, su índice y el del evento que la regulariza.
func regularizadasDe(t *testing.T, c *cli, vivos, pol string) map[uint64]uint64 {
	t.Helper()
	out := c.mustRun("--json", "reconcile", "--source", vivos, "--policy-file", pol)
	var r struct {
		Regularized []struct {
			Index         uint64 `json:"index"`
			RegularizedBy uint64 `json:"regularized_by"`
		} `json:"regularized"`
	}
	if err := json.Unmarshal([]byte(out), &r); err != nil {
		t.Fatal(err)
	}
	if r.Regularized == nil {
		t.Fatalf("regularized no sale (tiene que ir siempre, vacío si no hay ninguna):\n%s", out)
	}
	m := map[uint64]uint64{}
	for _, x := range r.Regularized {
		m[x.Index] = x.RegularizedBy
	}
	return m
}

// TestEraseYReconcileDicenLoMismo (Sprint 32, 0a): lo que erase --json anuncia en
// regularizes es EXACTAMENTE lo que reconcile, con la misma política, lista después en
// regularized, y con regularized_by igual al índice del evento que selló erase. Sin
// regularizes, regularized sale vacío. Si las dos condiciones —la de erase al avisar y la
// 4 de reconcile al contar— se separan, erase anunciaría una ratificación que reconcile no
// ve, o al revés.
func TestEraseYReconcileDicenLoMismo(t *testing.T) {
	t.Run("con regularizes", func(t *testing.T) {
		c, args, _ := conSupresionNoAutorizada(t)
		pol := args[4]
		vivos := ficheroVivo(t, c.dir, 1, `{"venta":"002","cliente":"Luis"}`)
		out := c.mustRun(append([]string{"--json"}, append(args, "--assume-confirmed")...)...)
		var v struct {
			Index       uint64 `json:"index"`
			Regularizes []struct {
				Index uint64 `json:"index"`
			} `json:"regularizes"`
		}
		if err := json.Unmarshal([]byte(out), &v); err != nil {
			t.Fatal(err)
		}
		if len(v.Regularizes) == 0 {
			t.Fatalf("erase no anuncia nada que regularizar; el test no compararía nada:\n%s", out)
		}
		anunciadas := map[uint64]uint64{}
		for _, r := range v.Regularizes {
			anunciadas[r.Index] = v.Index
		}
		got := regularizadasDe(t, c, vivos, pol)
		if len(got) != len(anunciadas) {
			t.Fatalf("erase anuncia %v y reconcile lista %v", anunciadas, got)
		}
		for i, por := range anunciadas {
			if got[i] != por {
				t.Errorf("la supresión del evento %d: erase dice que la regulariza el %d, reconcile %v", i, por, got)
			}
		}
	})

	t.Run("sin regularizes", func(t *testing.T) {
		c := newCLI(t)
		sp := c.initConSupresion(t)
		c.sealFile(`{"venta":"001","cliente":"Ana"}`)
		c.sealFile(`{"venta":"002","cliente":"Luis"}`)
		h0, _ := contenidoDe(t, c.dir, 0)
		out := c.mustRun("--json", "erase", "--block", "0", "--policy-file", sp.politica,
			"--authorization", c.autoriza(t, sp, h0, 0), "--assume-confirmed")
		if strings.Contains(out, "regularizes") {
			t.Fatalf("regularizes sin nada que regularizar:\n%s", out)
		}
		vivos := ficheroVivo(t, c.dir, 1, `{"venta":"002","cliente":"Luis"}`)
		if got := regularizadasDe(t, c, vivos, sp.politica); len(got) != 0 {
			t.Errorf("regularized %v sin regularizes en erase", got)
		}
	})
}
