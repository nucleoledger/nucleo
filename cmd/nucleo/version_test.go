package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"testing"
)

// Los valores de las -X de los tests. El commit es de 40 hex como el de verdad, para que
// el corte a 7 se vea; ninguno sale del código bajo prueba.
const (
	xVersion = "9.9.9-prueba"
	xCommit  = "0123456789abcdef0123456789abcdef01234567"
	xDate    = "2099-12-31T23:59:59Z"
)

func buildInfoDePrueba(main string, ajustes ...string) *debug.BuildInfo {
	bi := &debug.BuildInfo{GoVersion: "go1.99.9"}
	bi.Main.Version = main
	for i := 0; i+1 < len(ajustes); i += 2 {
		bi.Settings = append(bi.Settings, debug.BuildSetting{Key: ajustes[i], Value: ajustes[i+1]})
	}
	return bi
}

// TestLeerVersion: las -X mandan campo a campo; sin ellas, BuildInfo; sin nada,
// «(devel)».
func TestLeerVersion(t *testing.T) {
	conVCS := buildInfoDePrueba("v0.4.1-0.20261017193751-dae1f1e1ef8d+dirty",
		"vcs.revision", "dae1f1e1ef8d27f25dceba9622ff59ca20de1738",
		"vcs.time", "2026-10-17T19:37:51Z",
		"vcs.modified", "true")
	casos := []struct {
		nombre  string
		v, c, d string
		bi      *debug.BuildInfo
		quiero  infoVersion
	}{
		{"con -X, que mandan sobre BuildInfo", xVersion, xCommit, xDate, conVCS,
			infoVersion{xVersion, xCommit, xDate, "go1.99.9", true}},
		{"sin -X: BuildInfo", "", "", "", conVCS,
			infoVersion{"v0.4.1-0.20261017193751-dae1f1e1ef8d+dirty", "dae1f1e1ef8d27f25dceba9622ff59ca20de1738",
				"2026-10-17T19:37:51Z", "go1.99.9", true}},
		{"una -X sola: el resto de BuildInfo", xVersion, "", "", conVCS,
			infoVersion{xVersion, "dae1f1e1ef8d27f25dceba9622ff59ca20de1738", "2026-10-17T19:37:51Z", "go1.99.9", true}},
		{"sin -X ni VCS: (devel)", "", "", "", buildInfoDePrueba("(devel)"),
			infoVersion{"(devel)", "", "", "go1.99.9", false}},
		{"árbol limpio", "", "", "", buildInfoDePrueba("(devel)", "vcs.modified", "false"),
			infoVersion{"(devel)", "", "", "go1.99.9", false}},
		{"sin BuildInfo: (devel) y el Go del runtime", "", "", "", nil,
			infoVersion{"(devel)", "", "", runtime.Version(), false}},
	}
	for _, c := range casos {
		t.Run(c.nombre, func(t *testing.T) {
			if got := leerVersion(c.v, c.c, c.d, c.bi); got != c.quiero {
				t.Errorf("leerVersion = %+v\n         quiero %+v", got, c.quiero)
			}
		})
	}
}

func TestLineaDeVersion(t *testing.T) {
	casos := map[string]struct {
		info   infoVersion
		quiero string
	}{
		"release": {infoVersion{"0.4.0-alpha", xCommit, xDate, "go1.27.2", false},
			"nucleo 0.4.0-alpha · commit 0123456 · 2099-12-31T23:59:59Z · go1.27.2"},
		"con cambios": {infoVersion{"(devel)", xCommit, xDate, "go1.27.2", true},
			"nucleo (devel) · commit 0123456 · 2099-12-31T23:59:59Z · go1.27.2 · con cambios sin commitear"},
		"sin nada": {infoVersion{"(devel)", "", "", "go1.27.2", false},
			"nucleo (devel) · commit desconocido · fecha desconocida · go1.27.2"},
	}
	for nombre, c := range casos {
		if got := c.info.lineaDeVersion(); got != c.quiero {
			t.Errorf("%s:\n got   %q\n quiero %q", nombre, got, c.quiero)
		}
	}
}

// compilaNucleo compila la CLI sin el tag testhooks, como goreleaser, con las ldflags
// dadas. Se salta donde no hay `go`, salvo en el CI (ver TestProductionBinaryRefusesHooks).
func compilaNucleo(t *testing.T, ldflags string) string {
	t.Helper()
	if testing.Short() {
		t.Skip("compila un binario; se salta en -short")
	}
	if _, err := exec.LookPath("go"); err != nil {
		if os.Getenv("GITHUB_ACTIONS") == "true" {
			t.Fatalf("no hay `go` en el PATH del CI: %v", err)
		}
		t.Skipf("no hay `go` en el PATH (%v); en el CI corre siempre", err)
	}
	bin := filepath.Join(t.TempDir(), "nucleo"+exeSuffix())
	build := exec.Command("go", "build", "-trimpath", "-ldflags", ldflags, "-o", bin, ".")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("no se pudo compilar: %v\n%s", err, out)
	}
	return bin
}

// ejecutaVersion corre el binario y exige el código 0.
func ejecutaVersion(t *testing.T, bin string, args ...string) string {
	t.Helper()
	cmd := exec.Command(bin, args...)
	cmd.Env = filterHookVars(os.Environ())
	var out, errOut bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errOut
	if err := cmd.Run(); err != nil {
		t.Fatalf("`nucleo %s`: %v\n--- stdout ---\n%s\n--- stderr ---\n%s", strings.Join(args, " "), err, out.String(), errOut.String())
	}
	return out.String()
}

type versionJSON struct {
	OK       *bool   `json:"ok"`
	Version  *string `json:"version"`
	Commit   *string `json:"commit"`
	Date     *string `json:"date"`
	Go       *string `json:"go"`
	Modified *bool   `json:"modified"`
}

// leeVersionJSON exige UN objeto JSON con los seis campos, de su tipo.
func leeVersionJSON(t *testing.T, salida string) versionJSON {
	t.Helper()
	dec := json.NewDecoder(strings.NewReader(salida))
	var v versionJSON
	if err := dec.Decode(&v); err != nil {
		t.Fatalf("--json version no es JSON: %v\n%s", err, salida)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		t.Fatalf("--json version da más de un valor JSON:\n%s", salida)
	}
	if v.OK == nil || v.Version == nil || v.Commit == nil || v.Date == nil || v.Go == nil || v.Modified == nil {
		t.Fatalf("faltan campos en --json version:\n%s", salida)
	}
	if !*v.OK {
		t.Fatalf("ok false en --json version:\n%s", salida)
	}
	return v
}

// TestVersionConLdflags: el binario compilado con las tres -X de .goreleaser.yaml dice
// lo que se le pasó, en texto y en --json.
func TestVersionConLdflags(t *testing.T) {
	bin := compilaNucleo(t, "-s -w -X main.version="+xVersion+" -X main.commit="+xCommit+" -X main.date="+xDate)

	linea := ejecutaVersion(t, bin, "version")
	if !strings.HasPrefix(linea, "nucleo "+xVersion+" · commit 0123456 · "+xDate+" · go") {
		t.Errorf("la línea no lleva lo pasado con -X: %q", linea)
	}
	if strings.Count(linea, "\n") != 1 {
		t.Errorf("la salida para personas es UNA línea: %q", linea)
	}

	v := leeVersionJSON(t, ejecutaVersion(t, bin, "--json", "version"))
	if *v.Version != xVersion || *v.Commit != xCommit || *v.Date != xDate {
		t.Errorf("--json no lleva lo pasado con -X: %+v", v)
	}
	if !strings.HasPrefix(*v.Go, "go") {
		t.Errorf("go = %q", *v.Go)
	}
}

// TestVersionSinLdflags: un `go build` a secas no inventa una versión: dice la del
// módulo que Go sacó del VCS, o «(devel)», y el commit, si lo hay, es el completo.
func TestVersionSinLdflags(t *testing.T) {
	bin := compilaNucleo(t, "-s -w")
	v := leeVersionJSON(t, ejecutaVersion(t, bin, "--json", "version"))
	if *v.Version == "" || *v.Version == xVersion {
		t.Errorf("version = %q sin -X", *v.Version)
	}
	if *v.Commit != "" && len(*v.Commit) != 40 {
		t.Errorf("commit = %q: de BuildInfo sale completo", *v.Commit)
	}
	if !strings.HasPrefix(ejecutaVersion(t, bin, "version"), "nucleo "+*v.Version+" · ") {
		t.Error("el texto y --json no dicen la misma versión")
	}
}
