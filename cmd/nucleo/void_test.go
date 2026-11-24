//go:build testhooks

package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// Los tests de `nucleo void` (ADR-035): cada camino de la orden, con el binario de verdad.

const (
	facturaA = `{"factura":"001","importe":"10000.00"}`
	facturaB = `{"factura":"002","importe":"75.00"}`
)

// vivosDe escribe el JSONL de un sistema vivo con los registros dados (índice → contenido).
func vivosDe(t *testing.T, dir string, regs map[uint64]string) string {
	t.Helper()
	var b strings.Builder
	for i := uint64(0); i < 64; i++ {
		if p, ok := regs[i]; ok {
			fmt.Fprintf(&b, `{"index":%d,"payload_b64":%q}`+"\n", i, base64.StdEncoding.EncodeToString([]byte(p)))
		}
	}
	return ficheroUnico(t, dir, "vivos-*.jsonl", b.String())
}

func hashOf(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

type salidaVoid struct {
	Index             uint64 `json:"index"`
	Hash              string `json:"hash"`
	VoidedIndex       uint64 `json:"voided_index"`
	VoidedPayloadHash string `json:"voided_payload_hash"`
	AlreadyVoided     *bool  `json:"already_voided"`
}

func leeSalidaVoid(t *testing.T, out string) salidaVoid {
	t.Helper()
	var r salidaVoid
	if err := json.Unmarshal([]byte(out), &r); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if r.AlreadyVoided == nil {
		t.Fatalf("la salida no trae already_voided:\n%s", out)
	}
	return r
}

type informeVoided struct {
	OK       bool `json:"ok"`
	Findings []struct {
		Status string `json:"status"`
		Index  uint64 `json:"index"`
	} `json:"findings"`
	Voided []struct {
		Index    uint64 `json:"index"`
		VoidedBy uint64 `json:"voided_by"`
	} `json:"voided"`
}

// TestVoidSellaUnaVezYReconcileLaEnsena: void --block sella el evento con el tipo, el
// payload_cid y el contenido de PROTOCOL §5.2; reconcile lo enseña en voided sin cambiar el
// código de salida; una segunda anulación no sella nada (already_voided); y si el ERP borra
// la factura anulada, sigue faltando.
func TestVoidSellaUnaVezYReconcileLaEnsena(t *testing.T) {
	c := newCLI(t)
	c.initLedger()
	c.sealFile(facturaA)
	c.sealFile(facturaB)

	r := leeSalidaVoid(t, c.mustRun("--json", "void", "--block", "1"))
	b1 := bloqueDeCLI(t, c.dir, 1)
	if r.Index != 2 || r.VoidedIndex != 1 || r.VoidedPayloadHash != b1.Header.PayloadHash || *r.AlreadyVoided {
		t.Errorf("salida de void: %+v", r)
	}
	ev := bloqueDeCLI(t, c.dir, 2)
	if ev.Hash != r.Hash || ev.Header.Type != "nucleo.void.v1" || ev.Header.PayloadCID != "nucleo-void@v1:1" ||
		ev.Header.Tenant != b1.Header.Tenant {
		t.Errorf("el evento no es el de PROTOCOL §5.2: %+v", ev.Header)
	}
	// El payload_hash del evento, contra el texto de §5.2 escrito aquí a mano.
	if want := hashOf(fmt.Sprintf(`{"voided_index":"1","voided_payload_hash":"%s"}`, b1.Header.PayloadHash)); ev.Header.PayloadHash != want {
		t.Errorf("payload_hash del evento = %s, want %s", ev.Header.PayloadHash, want)
	}

	// reconcile: la factura sigue en el sistema vivo → 0, y voided la nombra.
	out, _ := c.runWant(t, 0, "--json", "reconcile", "--source", vivosDe(t, c.dir, map[uint64]string{0: facturaA, 1: facturaB}))
	var inf informeVoided
	if err := json.Unmarshal([]byte(out), &inf); err != nil {
		t.Fatal(err)
	}
	if !inf.OK || len(inf.Findings) != 0 || len(inf.Voided) != 1 || inf.Voided[0].Index != 1 || inf.Voided[0].VoidedBy != 2 {
		t.Errorf("reconcile tras anular: %+v", inf)
	}
	// En texto, lo dice.
	txt, _ := c.runWant(t, 0, "reconcile", "--source", vivosDe(t, c.dir, map[uint64]string{0: facturaA, 1: facturaB}))
	if !strings.Contains(txt, "bloque ANULADO por el emisor") || !strings.Contains(txt, "anulado en     : el bloque 2") {
		t.Errorf("el texto de reconcile no enseña la anulación:\n%s", txt)
	}

	// Segunda anulación: código 0, already_voided y el índice de la primera, sin sellar.
	r2 := leeSalidaVoid(t, c.mustRun("--json", "void", "--block", "1"))
	if !*r2.AlreadyVoided || r2.Index != 2 || r2.Hash != ev.Hash || r2.VoidedIndex != 1 {
		t.Errorf("segunda anulación: %+v", r2)
	}
	if n := bloques(t, c.dir); n != 3 {
		t.Errorf("la segunda anulación selló algo: %d bloques, want 3", n)
	}
	txt2, _ := c.runWant(t, 0, "void", "--block", "1")
	if !strings.Contains(txt2, "ya estaba anulado (evento en el bloque 2)") {
		t.Errorf("texto de la segunda anulación:\n%s", txt2)
	}

	// El ERP borró la factura anulada: faltante, código 2, y voided la sigue nombrando.
	out, _ = c.runWant(t, exitVerify, "--json", "reconcile", "--source", vivosDe(t, c.dir, map[uint64]string{0: facturaA}))
	inf = informeVoided{}
	if err := json.Unmarshal([]byte(out), &inf); err != nil {
		t.Fatal(err)
	}
	if inf.OK || len(inf.Findings) != 1 || inf.Findings[0].Status != "faltante" || inf.Findings[0].Index != 1 || len(inf.Voided) != 1 {
		t.Errorf("reconcile con la factura anulada borrada: %+v", inf)
	}
}

// TestVoidPorPayload: --payload busca por el SHA-256 de los bytes. Un contenido que nadie
// selló es un error; uno sellado dos veces, de uso, con los candidatos y --block.
func TestVoidPorPayload(t *testing.T) {
	c := newCLI(t)
	c.initLedger()
	c.sealFile(facturaA)
	c.mustRun("seal", "--tenant", testTenant, "--type", "sri.factura.v1", "--no-encrypt", "--payload", c.writeTemp(t, facturaB))
	c.mustRun("seal", "--tenant", testTenant, "--type", "sri.factura.v1", "--no-encrypt", "--payload", c.writeTemp(t, facturaB))

	r := leeSalidaVoid(t, c.mustRun("--json", "void", "--payload", c.writeTemp(t, facturaA)))
	if r.VoidedIndex != 0 || r.Index != 3 || *r.AlreadyVoided {
		t.Errorf("void --payload: %+v", r)
	}

	_, errOut := c.runWant(t, exitUsage, "void", "--payload", c.writeTemp(t, `{"factura":"999"}`))
	if !strings.Contains(errOut, "ningún bloque selló ese contenido") {
		t.Errorf("cero coincidencias:\n%s", errOut)
	}
	_, errOut = c.runWant(t, exitUsage, "void", "--payload", c.writeTemp(t, facturaB))
	if !strings.Contains(errOut, "los bloques 1 y 2") || !strings.Contains(errOut, "--block N") {
		t.Errorf("dos coincidencias:\n%s", errOut)
	}
	if n := bloques(t, c.dir); n != 4 {
		t.Errorf("%d bloques, want 4: los errores sellaron algo", n)
	}
}

// TestVoidRechaza: un evento de Núcleo, un índice que no existe, un tenant que no casa y
// las banderas mal puestas son errores de uso, y no sellan nada.
func TestVoidRechaza(t *testing.T) {
	c := newCLI(t)
	c.initLedger()
	c.sealFile(facturaA)
	c.mustRun("void", "--block", "0") // bloque 1: el evento

	for _, caso := range []struct {
		nombre, dice string
		args         []string
	}{
		{"un evento de Núcleo", "es un evento de Núcleo (nucleo.void.v1)", []string{"void", "--block", "1"}},
		{"un índice que no existe", "el ledger no tiene el bloque 7", []string{"void", "--block", "7"}},
		{"un tenant que no casa", "--tenant dice \"0999999999001\"", []string{"void", "--block", "0", "--tenant", "0999999999001"}},
		{"las dos banderas", "no los dos", []string{"void", "--block", "0", "--payload", "x"}},
		{"ninguna bandera", "void necesita --block N", []string{"void"}},
	} {
		t.Run(caso.nombre, func(t *testing.T) {
			_, errOut := c.runWant(t, exitUsage, caso.args...)
			if !strings.Contains(errOut, caso.dice) {
				t.Errorf("stderr no dice %q:\n%s", caso.dice, errOut)
			}
		})
	}
	if n := bloques(t, c.dir); n != 2 {
		t.Errorf("%d bloques, want 2: un rechazo selló algo", n)
	}
}
