//go:build testhooks

package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/nucleoledger/nucleo/internal/receipt"
)

// La autoridad de supresión por la vía del usuario (ADR-032).

// TestUnTerceroCompruebaLaAutorizacionConLosRecibos (ADR-032 §E): con el recibo del
// evento, el del bloque suprimido y la política, un tercero comprueba la autorización
// sin Núcleo. Los recibos se verifican como siempre; la autorización, con la biblioteca
// estándar y nada de internal/erasure: el texto se escribe aquí, desde PROTOCOL §5.1.
func TestUnTerceroCompruebaLaAutorizacionConLosRecibos(t *testing.T) {
	c := newCLI(t)
	sp := c.initConSupresion(t)
	c.sealFile(`{"venta":"001","cliente":"María Pérez"}`)
	c.sealFile(`{"venta":"002","cliente":"Luis"}`)
	h0, _ := contenidoDe(t, c.dir, 0)
	c.mustRun("erase", "--block", "0", "--policy-file", sp.politica,
		"--authorization", c.autoriza(t, sp, h0, 0), "--assume-confirmed")
	testigo := []string{"--witness-name", sp.name, "--witness-key", sp.key}
	c.mustRun(append([]string{"sync", "--witness", sp.url}, testigo...)...)

	recibo := func(bloque string) []byte {
		t.Helper()
		ruta := filepath.Join(c.dir, "recibo-"+bloque+".txt")
		c.mustRun(append([]string{"receipt", "--block", bloque, "--recipient", "Auditoría", "--out", ruta}, testigo...)...)
		raw, err := os.ReadFile(ruta)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	recBloque, recEvento := recibo("0"), recibo("2")

	// 1. Los dos recibos verifican, como cualquier recibo.
	pol := politicaDe(t, c, sp.name, sp.key)
	for _, raw := range [][]byte{recBloque, recEvento} {
		r, err := receipt.Parse(raw, pol)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := r.Verify(pol); err != nil {
			t.Fatal(err)
		}
	}

	// 2-4. Lo demás, a mano: el header es la primera línea de la sección de máquina.
	type header struct {
		Index       uint64 `json:"index"`
		PayloadHash string `json:"payload_hash"`
		PayloadCID  string `json:"payload_cid"`
		Type        string `json:"type"`
	}
	leeHeader := func(raw []byte) header {
		t.Helper()
		_, maquina, ok := strings.Cut(string(raw), "--- prueba verificable ---\n")
		if !ok {
			t.Fatal("el recibo no tiene sección de máquina")
		}
		linea, _, _ := strings.Cut(maquina, "\n")
		var h header
		if err := json.Unmarshal([]byte(linea), &h); err != nil {
			t.Fatal(err)
		}
		return h
	}
	bloque, ev := leeHeader(recBloque), leeHeader(recEvento)
	if ev.Type != "nucleo.erasure.v1" {
		t.Fatalf("el bloque 2 no es un evento de supresión: %+v", ev)
	}
	partes := strings.Split(ev.PayloadCID, ":")
	if len(partes) != 3 || partes[0] != "nucleo-erasure-auth@v1" {
		t.Fatalf("payload_cid del evento: %q", ev.PayloadCID)
	}
	through, err := strconv.ParseUint(partes[1], 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	if bloque.Index > through || through >= ev.Index {
		t.Errorf("la autorización no cubre el bloque: %d ≤ %d < %d", bloque.Index, through, ev.Index)
	}
	contenido := sha256.Sum256([]byte(`{"erased_payload_hash":"` + bloque.PayloadHash + `"}`))
	if hex.EncodeToString(contenido[:]) != ev.PayloadHash {
		t.Error("el evento no suprime el contenido del bloque")
	}
	texto := "nucleo.org/erasure-authorization@v1\n" +
		"origin " + testOrigin + "\n" +
		"erased_payload_hash " + bloque.PayloadHash + "\n" +
		"through " + partes[1] + "\n"
	digest := sha256.Sum256([]byte(texto))
	firma, err := hex.DecodeString(partes[2])
	if err != nil {
		t.Fatal(err)
	}
	clave, err := hex.DecodeString(sp.erasureKey) // la erasureKey de la política
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(ed25519.PublicKey(clave), digest[:], firma) {
		t.Error("la autorización no verifica con la erasureKey de la política")
	}
	// Y con la clave del firmante —la que está en el servidor— no verifica.
	if ed25519.Verify(pol.SignerKey, digest[:], firma) {
		t.Error("la autorización verifica con la clave del firmante")
	}
}

// TestEraseDiceQueOrdenPedirYEsaOrdenFunciona: sin --authorization, erase no borra nada y
// dice la orden exacta que tiene que ejecutar la custodia. La regla de los mensajes: esa
// orden, copiada tal cual, funciona (con las tarjetas, que en el test da el gancho).
func TestEraseDiceQueOrdenPedirYEsaOrdenFunciona(t *testing.T) {
	c := newCLI(t)
	sp := c.initConSupresion(t)
	c.sealFile(`{"venta":"001","cliente":"María Pérez"}`)
	_, errOut := c.runWant(t, exitUsage, "erase", "--block", "0", "--policy-file", sp.politica, "--assume-confirmed")
	if _, ct := contenidoDe(t, c.dir, 0); ct == nil || bloques(t, c.dir) != 1 {
		t.Fatal("sin autorización, erase borró o selló algo")
	}
	orden := regexp.MustCompile(`nucleo erasure-key authorize .*`).FindString(errOut)
	if orden == "" {
		t.Fatalf("erase no dice qué orden pedir:\n%s", errOut)
	}
	args := strings.Fields(strings.TrimPrefix(orden, "nucleo "))
	out := c.mustRun(append([]string{"--json"}, args...)...)
	var v struct {
		Authorization string `json:"authorization"`
	}
	if err := json.Unmarshal([]byte(out), &v); err != nil {
		t.Fatal(err)
	}
	c.mustRun("erase", "--block", "0", "--policy-file", sp.politica, "--authorization", v.Authorization, "--assume-confirmed")
	if _, ct := contenidoDe(t, c.dir, 0); ct != nil {
		t.Error("con la autorización de la orden impresa, erase no suprimió")
	}
}

// TestAuthorizeRechazaLasTarjetasDelVault: las tarjetas del vault reconstruyen la clave
// que también abre la passphrase; no autorizan supresiones, y authorize lo dice.
func TestAuthorizeRechazaLasTarjetasDelVault(t *testing.T) {
	c := newCLI(t)
	sp := c.initConSupresion(t)
	out := c.mustRun("--json", "backup")
	var v struct {
		Shares []string `json:"shares"`
	}
	if err := json.Unmarshal([]byte(out), &v); err != nil || len(v.Shares) < 2 {
		t.Fatalf("backup --json (%v):\n%s", err, out)
	}
	t.Setenv(envCards, v.Shares[0]+"|"+v.Shares[1])
	_, errOut := c.runWant(t, exitUsage, "erasure-key", "authorize", "--policy-file", sp.politica,
		"--payload-hash", strings.Repeat("ab", 32), "--through", "0")
	if !strings.Contains(errOut, "tarjetas del vault") {
		t.Errorf("no dice que son las del vault:\n%s", errOut)
	}
}

// TestLaAutorizacionNoCubreUnaCopiaPosterior: si el contenido se volvió a sellar después
// de autorizar su supresión, la autorización no cubre la copia nueva (through). erase lo
// dice y no borra nada; con una autorización hasta la copia nueva, sí.
func TestLaAutorizacionNoCubreUnaCopiaPosterior(t *testing.T) {
	c := newCLI(t)
	sp := c.initConSupresion(t)
	c.sealFile(`{"venta":"001","cliente":"María Pérez"}`)
	h0, _ := contenidoDe(t, c.dir, 0)
	vieja := c.autoriza(t, sp, h0, 0)
	c.sealFile(`{"venta":"001","cliente":"María Pérez"}`) // la misma, otra vez: bloque 1
	_, errOut := c.runWant(t, exitUsage, "erase", "--block", "0", "--policy-file", sp.politica,
		"--authorization", vieja, "--assume-confirmed")
	if !strings.Contains(errOut, "llega hasta el bloque 0") || !strings.Contains(errOut, "--through 1") {
		t.Errorf("no explica la copia posterior:\n%s", errOut)
	}
	if bloques(t, c.dir) != 2 {
		t.Fatal("se selló algo")
	}
	c.mustRun("erase", "--block", "0", "--policy-file", sp.politica,
		"--authorization", c.autoriza(t, sp, h0, 1), "--assume-confirmed")
}

// TestErasureKeyInitNoAbreNingunLedger: la clave de supresión se genera en el equipo de
// la custodia, donde no hay ledger. Y en --json la confirmación hay que saltarla
// explícitamente, como en init.
func TestErasureKeyInitNoAbreNingunLedger(t *testing.T) {
	c := newCLI(t) // sin init: el directorio está vacío
	out := c.mustRun("--json", "erasure-key", "init", "--assume-confirmed")
	var v struct {
		ErasureKey string   `json:"erasure_key"`
		Shares     []string `json:"shares"`
		Threshold  int      `json:"threshold"`
	}
	if err := json.Unmarshal([]byte(out), &v); err != nil || len(v.ErasureKey) != 64 || len(v.Shares) != 3 || v.Threshold != 2 {
		t.Errorf("erasure-key init --json (%v):\n%s", err, out)
	}
	if _, err := os.Stat(filepath.Join(c.dir, "nucleo.db")); err == nil {
		t.Error("erasure-key init creó un ledger")
	}
	c.runWant(t, exitUsage, "--json", "erasure-key", "init")
}
