//go:build testhooks

package main

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/nucleoledger/nucleo/internal/vault"
)

const passNueva = "otra passphrase que esta vez se apunta"

// initConTarjetas crea el ledger con --json y devuelve las tarjetas que entrega.
func initConTarjetas(t *testing.T, c *cli) []string {
	t.Helper()
	out := c.mustRun("--json", "init", "--origin", testOrigin, "--assume-confirmed")
	var r struct {
		Shares []string `json:"shares"`
	}
	if err := json.Unmarshal([]byte(out), &r); err != nil || len(r.Shares) != 3 {
		t.Fatalf("init --json no devolvió tres tarjetas (%v):\n%s", err, out)
	}
	return r.Shares
}

// ficheroDeTarjetas escribe unas tarjetas, una por línea.
func ficheroDeTarjetas(t *testing.T, c *cli, tarjetas ...string) string {
	t.Helper()
	return ficheroUnico(t, c.dir, "tarjetas-*.txt", strings.Join(tarjetas, "\n")+"\n")
}

// TestRestoreFijaPassphraseNueva es ADR-029 de punta a punta, con la CLI: se pierde la
// passphrase, dos tarjetas fijan una nueva, se sella con ella, y ni la vieja ni las
// tarjetas viejas sirven ya.
func TestRestoreFijaPassphraseNueva(t *testing.T) {
	c := newCLI(t)
	viejas := initConTarjetas(t, c)
	c.sealFile(`{"factura":"antes del cambio"}`)

	// La passphrase se perdió. Quedan dos tarjetas.
	nueva := ficheroUnico(t, c.dir, "nueva-*.txt", passNueva+"\n")
	out := c.mustRun("--json", "restore", "--shares-file", ficheroDeTarjetas(t, c, viejas[0], viejas[2]),
		"--new-passphrase-file", nueva, "--assume-confirmed")
	var r struct {
		Changed   bool     `json:"passphrase_changed"`
		NewShares []string `json:"new_shares"`
		Threshold int      `json:"threshold"`
	}
	if err := json.Unmarshal([]byte(out), &r); err != nil {
		t.Fatalf("restore --json: %v\n%s", err, out)
	}
	if !r.Changed || len(r.NewShares) != 3 || r.Threshold != 2 {
		t.Fatalf("restore --json no dice lo que hizo: %+v\n%s", r, out)
	}

	t.Run("se sella con la passphrase nueva", func(t *testing.T) {
		doc := ficheroUnico(t, c.dir, "doc-*.json", `{"factura":"despues del cambio"}`)
		c.runWant(t, exitOK, "seal", "--tenant", testTenant, "--type", "sri.factura.v1",
			"--payload", doc, "--passphrase-file", nueva)
	})
	t.Run("la passphrase vieja ya no abre", func(t *testing.T) {
		vieja := ficheroUnico(t, c.dir, "vieja-*.txt", testPassphrase+"\n")
		doc := ficheroUnico(t, c.dir, "doc-*.json", `{"factura":"con la vieja"}`)
		_, errOut := c.runWant(t, exitUsage, "seal", "--tenant", testTenant, "--type", "sri.factura.v1",
			"--payload", doc, "--passphrase-file", vieja)
		if !strings.Contains(errOut, "la passphrase no es la de este vault") {
			t.Errorf("no dice por qué:\n%s", c.ultima())
		}
	})
	t.Run("las tarjetas viejas ya no sirven, y lo dice", func(t *testing.T) {
		_, _ = c.runWant(t, exitVerify, "restore", "--shares-file", ficheroDeTarjetas(t, c, viejas[0], viejas[1]))
		if !strings.Contains(c.ultima(), "quedaron sin valor") {
			t.Errorf("no dice que pueden ser tarjetas de antes del cambio:\n%s", c.ultima())
		}
	})
	t.Run("las tarjetas nuevas sí", func(t *testing.T) {
		out := c.mustRun("restore", "--shares-file", ficheroDeTarjetas(t, c, r.NewShares[1], r.NewShares[2]))
		if !strings.Contains(out, "comprobada contra este vault") {
			t.Errorf("salida inesperada:\n%s", out)
		}
	})
	t.Run("la cadena no se tocó", func(t *testing.T) {
		c.mustRun("verify", "--full")
	})
}

// TestRestoreEnTextoLoDiceSinAmbiguedad: la salida para personas enseña las tarjetas
// nuevas ANTES de escribir, avisa de que no valen todavía, y al terminar dice que las
// viejas ya no sirven.
func TestRestoreEnTextoLoDiceSinAmbiguedad(t *testing.T) {
	c := newCLI(t)
	viejas := initConTarjetas(t, c)
	nueva := ficheroUnico(t, c.dir, "nueva-*.txt", passNueva+"\n")
	out := c.mustRun("restore", "--shares-file", ficheroDeTarjetas(t, c, viejas[:2]...),
		"--new-passphrase-file", nueva, "--assume-confirmed")
	orden := []string{
		"Valen desde que veas «✔ passphrase nueva",
		"TARJETA 1 de 3",
		"✔ passphrase nueva fijada",
		"Las tarjetas ANTERIORES ya no sirven para este vault: destrúyelas",
		"Una copia del fichero del ledger hecha ANTES",
	}
	desde := 0
	for _, q := range orden {
		i := strings.Index(out[desde:], q)
		if i < 0 {
			t.Fatalf("falta %q (o no va en su sitio):\n%s", q, out)
		}
		desde += i + len(q)
	}
}

// TestRestoreSinCambiarNadaDiceComoSeguir: sin --new-passphrase, restore comprueba y no
// cambia nada, y a quien perdió la passphrase le da la orden que sí la fija.
func TestRestoreSinCambiarNadaDiceComoSeguir(t *testing.T) {
	c := newCLI(t)
	viejas := initConTarjetas(t, c)
	out := c.mustRun("restore", "--shares-file", ficheroDeTarjetas(t, c, viejas[1:]...))
	for _, q := range []string{"No se ha cambiado nada", "restore --new-passphrase"} {
		if !strings.Contains(out, q) {
			t.Errorf("falta %q:\n%s", q, out)
		}
	}
	// Y de verdad no cambió: la passphrase de siempre sigue abriendo.
	c.sealFile(`{"factura":"sigue igual"}`)
}

// TestRestoreUsoIncorrecto: las combinaciones que no tienen sentido se rechazan antes de
// tocar nada.
func TestRestoreUsoIncorrecto(t *testing.T) {
	c := newCLI(t)
	viejas := initConTarjetas(t, c)
	tarjetas := ficheroDeTarjetas(t, c, viejas[:2]...)
	nueva := ficheroUnico(t, c.dir, "nueva-*.txt", passNueva+"\n")

	_, errOut := c.runWant(t, exitUsage, "--json", "restore", "--shares-file", tarjetas, "--new-passphrase-file", nueva)
	if !strings.Contains(c.ultima(), "--assume-confirmed") {
		t.Errorf("--json sin --assume-confirmed no lo explica:\n%s%s", errOut, c.ultima())
	}
	c.runWant(t, exitUsage, "restore", "--shares-file", tarjetas, "--new-passphrase-file", nueva, "--new-passphrase")
	// Nada cambió.
	c.sealFile(`{"factura":"sin cambios"}`)
}

// envSubprocesoCLI lleva, en JSON, los argumentos con los que TestSubprocesoCLI ejecuta
// la CLI en un proceso aparte.
const envSubprocesoCLI = "NUCLEO_TEST_SUBPROCESO_ARGS"

// TestSubprocesoCLI no prueba nada por sí mismo: es el proceso que los tests de
// interrupción lanzan y matan. Sin la variable, no hace nada.
func TestSubprocesoCLI(t *testing.T) {
	raw := os.Getenv(envSubprocesoCLI)
	if raw == "" {
		t.Skip("solo se ejecuta como subproceso")
	}
	var args []string
	if err := json.Unmarshal([]byte(raw), &args); err != nil {
		os.Exit(99)
	}
	os.Exit(run(args, os.Stdout, os.Stderr))
}

// TestRestoreInterrumpidoNuncaDejaElVaultSinAbrir mata el proceso de restore —os.Exit,
// sin defer ni rollback— en cada frontera del cambio de passphrase, y comprueba que el
// vault queda en uno de sus dos estados completos, nunca en uno mixto (ADR-029 §C):
//
//   - antes del COMMIT, el VIEJO: abren la passphrase y las tarjetas de antes, y la
//     nueva no;
//   - después, el NUEVO: abre la passphrase nueva, y ni la vieja ni sus tarjetas.
//
// En el estado viejo, además, repetir restore termina bien: la interrupción no deja
// nada que estorbe al reintento.
func TestRestoreInterrumpidoNuncaDejaElVaultSinAbrir(t *testing.T) {
	fronteras := []struct {
		nombre string
		nuevo  bool
	}{
		{"restore:tarjetas-comprobadas", false},
		{"restore:tarjetas-nuevas-emitidas", false},
		{"restore:confirmado", false},
		// Dentro de la transacción: tras escribir la primera fila, y tras la segunda
		// pero antes del COMMIT. Las claves se escriben en orden.
		{"meta-tx:" + vault.MetaDEKKey, false},
		{"meta-tx:" + vault.MetaParamsKey, false},
		{"restore:fijada", true},
	}
	for _, f := range fronteras {
		t.Run(f.nombre, func(t *testing.T) {
			c := newCLI(t)
			viejas := initConTarjetas(t, c)
			tarjetas := ficheroDeTarjetas(t, c, viejas[0], viejas[1])
			nueva := ficheroUnico(t, c.dir, "nueva-*.txt", passNueva+"\n")

			args, _ := json.Marshal([]string{"--dir", c.dir, "--json", "restore",
				"--shares-file", tarjetas, "--new-passphrase-file", nueva, "--assume-confirmed"})
			cmd := exec.Command(os.Args[0], "-test.run=^TestSubprocesoCLI$")
			cmd.Env = append(os.Environ(), envSubprocesoCLI+"="+string(args), envDieAt+"="+f.nombre)
			out, err := cmd.CombinedOutput()
			var ee *exec.ExitError
			if !errors.As(err, &ee) || ee.ExitCode() != codigoMuerte {
				t.Fatalf("el restore tenía que morir en %s (código %d) y salió con %v:\n%s",
					f.nombre, codigoMuerte, err, out)
			}

			abre := estadoDelVault(t, c.dir, viejas)
			want := estadoVault{vieja: !f.nuevo, tarjetasViejas: !f.nuevo, nueva: f.nuevo}
			if abre != want {
				t.Fatalf("muerto en %s, el vault se abre con %+v; want %+v", f.nombre, abre, want)
			}
			if !f.nuevo {
				c.mustRun("--json", "restore", "--shares-file", tarjetas,
					"--new-passphrase-file", nueva, "--assume-confirmed")
				if abre := estadoDelVault(t, c.dir, viejas); abre != (estadoVault{nueva: true}) {
					t.Fatalf("el reintento tras morir en %s deja %+v", f.nombre, abre)
				}
			}
		})
	}
}

// estadoVault dice con qué se abre un vault.
type estadoVault struct{ vieja, tarjetasViejas, nueva bool }

// estadoDelVault lo comprueba contra la base, sin pasar por la CLI: con Unlock para las
// passphrases y RestoreKEK + UnwrapDEK para las tarjetas.
func estadoDelVault(t *testing.T, dir string, viejas []string) estadoVault {
	t.Helper()
	s, _, err := openStoreAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	abre := func(pass string) bool {
		v, err := vault.Unlock(s, []byte(pass))
		if err != nil {
			return false
		}
		v.Close()
		return true
	}
	kek, err := vault.RestoreKEK(viejas[1:])
	if err != nil {
		t.Fatal(err)
	}
	wrapped, err := s.GetMeta(vault.MetaDEKKey)
	if err != nil {
		t.Fatal(err)
	}
	id, err := s.GetMeta(vault.MetaIDKey)
	if err != nil {
		t.Fatal(err)
	}
	_, errTarjetas := vault.UnwrapDEK(kek, wrapped, string(id))
	return estadoVault{
		vieja:          abre(testPassphrase),
		tarjetasViejas: errTarjetas == nil,
		nueva:          abre(passNueva),
	}
}
