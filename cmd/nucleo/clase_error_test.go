//go:build testhooks

package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nucleoledger/nucleo/internal/store"
)

// La clase del error (ADR-027), comprobada en las situaciones que la hicieron falta.
//
// El valor de la clase está en que NO se deduce del código de salida: si cada código
// tuviera una sola clase, el campo sería decorativo. Así que estas comprobaciones miran
// justo los pares que se cruzan —un código 1 que es transitorio, dos códigos 3 que piden
// cosas opuestas— y no la correspondencia trivial.

// claseDe ejecuta la CLI con --json y devuelve el código y la clase del error.
func claseDe(t *testing.T, c *cli, args ...string) (int, string, string) {
	t.Helper()
	out, _, code := c.run(append([]string{"--json"}, args...)...)
	if code == exitOK {
		t.Fatalf("se esperaba un error y salió 0: %s", out)
	}
	var obj map[string]any
	if err := json.Unmarshal([]byte(out), &obj); err != nil {
		t.Fatalf("la salida de error no es JSON: %v\n%s", err, out)
	}
	clase, ok := obj["error_class"].(string)
	if !ok {
		t.Fatalf("el objeto de error no trae error_class: %s", out)
	}
	mensaje, _ := obj["error"].(string)
	return code, clase, mensaje
}

func TestClaseDelErrorEnLosCasosQueLaPiden(t *testing.T) {
	c := newCLI(t)
	c.initLedger()
	c.sealFile(`{"factura":"000001","importe":"100.00"}`)

	t.Run("una bandera mal dada es uso", func(t *testing.T) {
		code, clase, _ := claseDe(t, c, "seal", "--tenant", testTenant, "--type", "t.v1")
		if code != exitUsage || clase != claseUso {
			t.Errorf("código %d, clase %q; want %d y %q", code, clase, exitUsage, claseUso)
		}
	})

	t.Run("un fichero que no existe es uso", func(t *testing.T) {
		code, clase, _ := claseDe(t, c, "seal", "--tenant", testTenant, "--type", "t.v1",
			"--payload", filepath.Join(c.dir, "no-existe.json"))
		if code != exitUsage || clase != claseUso {
			t.Errorf("código %d, clase %q; want %d y %q", code, clase, exitUsage, claseUso)
		}
	})

	// EL CASO QUE ORIGINÓ EL ADR: código 1, y no hay nada mal en la llamada. Un ERP
	// tiene que sincronizar y reintentar, no revisar su código.
	t.Run("el recibo de un bloque que ningún testigo cubrió es transitorio", func(t *testing.T) {
		pol := politicaDeTest(t, c, "w1", strings.Repeat("ab", 32))
		code, clase, mensaje := claseDe(t, c, "receipt", "--policy-file", pol,
			"--block", "0", "--recipient", "Cliente")
		if code != exitUsage {
			t.Errorf("código %d, want %d", code, exitUsage)
		}
		if clase != claseTransitoria {
			t.Errorf("clase %q, want %q. Mensaje: %s", clase, claseTransitoria, mensaje)
		}
		if !strings.Contains(mensaje, "sync") {
			t.Errorf("el mensaje no dice qué hacer: %s", mensaje)
		}
	})

	// Dos códigos 3 que piden cosas opuestas.
	t.Run("un testigo que no contesta es transitorio", func(t *testing.T) {
		pol := politicaDeTest(t, c, "w1", strings.Repeat("ab", 32))
		// Un servidor que se cierra antes de usarse: el puerto queda sin nadie
		// escuchando, que es un testigo caído sin depender de elegir un puerto a dedo.
		srv := httptest.NewServer(http.NotFoundHandler())
		u := srv.URL
		srv.Close()
		code, clase, _ := claseDe(t, c, "sync", "--policy-file", pol, "--witness", u)
		if code != exitSyncFail || clase != claseTransitoria {
			t.Errorf("código %d, clase %q; want %d y %q", code, clase, exitSyncFail, claseTransitoria)
		}
	})

	t.Run("un testigo que contesta basura es entorno", func(t *testing.T) {
		pol := politicaDeTest(t, c, "w1", strings.Repeat("ab", 32))
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("esto no es una nota firmada"))
		}))
		defer srv.Close()
		code, clase, mensaje := claseDe(t, c, "sync", "--policy-file", pol, "--witness", srv.URL)
		if code != exitSyncFail {
			t.Errorf("código %d, want %d", code, exitSyncFail)
		}
		if clase != claseEntorno {
			t.Errorf("clase %q, want %q. Mensaje: %s", clase, claseEntorno, mensaje)
		}
		// Y el mensaje ya decía que reintentar no sirve: la clase dice lo mismo para
		// un programa, que es de lo que se trata.
		if !strings.Contains(mensaje, "NO se arregla reintentando") {
			t.Errorf("el mensaje perdió el aviso de que no se reintenta: %s", mensaje)
		}
	})

	// Un ledger de otra versión del protocolo no es un error de la llamada. Se fabrica
	// el de v0.1.0-alpha como lo reconoce la apertura: bloques sin regla de hoja
	// declarada, que es lo que hace a un log "leaf/v1".
	t.Run("un ledger de otra regla de hoja es entorno", func(t *testing.T) {
		if claseDelError(fmt.Errorf("abrir: %w", store.ErrLeafRule), exitUsage) != claseEntorno {
			t.Errorf("ErrLeafRule no se clasifica como %q", claseEntorno)
		}
	})

	t.Run("un fichero que no es un ledger es integridad", func(t *testing.T) {
		otro := t.TempDir()
		if err := os.WriteFile(filepath.Join(otro, "nucleo.db"), []byte("no soy una base de datos"), 0o600); err != nil {
			t.Fatal(err)
		}
		code, clase, _ := claseDe(t, c, "--dir", otro, "status")
		if clase != claseIntegridad {
			t.Errorf("clase %q, want %q (código %d)", clase, claseIntegridad, code)
		}
	})
}

// TestLaClaseNoSaleEnLaSalidaParaPersonas: el campo es para programas.
//
// Meter "[transient]" en el mensaje sería jerga del motor llegando al usuario, que es lo
// que prohíbe ADR-020 §E. A una persona se le dice qué hacer, y ya se le dice.
func TestLaClaseNoSaleEnLaSalidaParaPersonas(t *testing.T) {
	c := newCLI(t)
	c.initLedger()
	_, errOut, code := c.run("seal", "--tenant", testTenant, "--type", "t.v1")
	if code != exitUsage {
		t.Fatalf("código %d, want %d", code, exitUsage)
	}
	for _, jerga := range []string{"usage", "transient", "environment", "integrity", "error_class"} {
		if strings.Contains(errOut, jerga) {
			t.Errorf("la salida para personas trae %q:\n%s", jerga, errOut)
		}
	}
}

// TestTodoObjetoDeErrorTraeSuClase: el campo no es opcional en el productor.
//
// Lo es en el CONSUMIDOR —un binario anterior no lo trae, y por eso se lee con el código
// de salida como respaldo (ADR-027 §C)—, pero un objeto de error emitido por esta versión
// sin clase sería un contrato a medias.
func TestTodoObjetoDeErrorTraeSuClase(t *testing.T) {
	c := newCLI(t)
	casos := [][]string{
		{"--json", "subcomando-que-no-existe"},
		{"--json", "status"}, // sin ledger: no hay nada que abrir
		{"--json", "seal"},
		{"--json", "receipt", "--block", "0"},
		{"--json", "sync"},
		{"--json", "reconcile"},
	}
	for _, args := range casos {
		out, _, code := c.run(args...)
		if code == exitOK {
			continue
		}
		var obj map[string]any
		if err := json.Unmarshal([]byte(out), &obj); err != nil {
			t.Errorf("%v: la salida no es JSON: %v", args, err)
			continue
		}
		clase, _ := obj["error_class"].(string)
		switch clase {
		case claseUso, claseTransitoria, claseEntorno, claseIntegridad:
		default:
			t.Errorf("%v: error_class = %q, y tiene que ser una de las cuatro", args, clase)
		}
	}
}
