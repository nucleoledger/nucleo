package main

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/nucleoledger/nucleo/internal/checkpoint"
	"github.com/nucleoledger/nucleo/internal/reconcile"
)

// liveRecord es una línea del fichero JSONL que describe el sistema vivo.
type liveRecord struct {
	Index      uint64 `json:"index"`
	PayloadB64 string `json:"payload_b64"`
	Extra      bool   `json:"extra,omitempty"`
}

func cmdReconcile(e *env, args []string) error {
	fs := flag.NewFlagSet("reconcile", flag.ContinueOnError)
	fs.SetOutput(e.stderr)
	source := fs.String("source", "", "fichero JSONL con los registros vivos")
	pf := registerPolicyFlags(fs)
	full := fs.Bool("full", true, "ejecuta también la verificación exhaustiva del ledger")
	if err := fs.Parse(args); err != nil {
		return usageErr("%v", err)
	}
	if *source == "" {
		return usageErr("reconcile necesita --source <archivo JSONL>\n\n" +
			"  Cada línea: {\"index\":N,\"payload_b64\":\"...\"}\n" +
			"  Con \"extra\":true se marca un registro que el sistema vivo tiene\n" +
			"  y el ledger nunca selló.")
	}

	wp, _, err := pf.resolve()
	if err != nil {
		return err
	}
	s, res, err := e.openStoreWith(wp)
	if err != nil {
		return err
	}
	defer s.Close()

	rep, err := reconcile.Reconcile(s, jsonlSource(*source), reconcile.Options{IncludeFullVerify: *full})
	if err != nil {
		return usageErr("%v", err)
	}

	// Un cotejo que coincide sobre una historia SIN atestiguar dice menos de lo
	// que parece: el sistema vivo coincide con un ledger que podría estar
	// truncado. Por eso la atestación, el firmante y la frescura salen aquí con
	// la misma semántica y los mismos campos que en status.
	st, err := checkStaleness(s, res, now(), e.staleAfter, res.TreeSize)
	if err != nil {
		return err
	}
	st.warn(e)
	if e.json {
		raw, err := rep.JSON()
		if err != nil {
			return err
		}
		var data map[string]any
		if err := json.Unmarshal(raw, &data); err != nil {
			return err
		}
		data["attestation"] = res.Attestation.String()
		data["attested"] = res.Attested()
		data["attested_size"] = res.AttestedSize
		data["signer"] = signerJSON(res)
		data["freshness"] = st.json()
		data["ok"] = len(rep.Findings) == 0 && (rep.FullVerify == nil || rep.FullVerify.OK)
		e.printJSON(data)
	} else {
		printReport(e, rep)
		e.printf("\n")
		printAttestation(e, res)
		printFreshness(e, st)
	}

	// Una discrepancia NO es un error del programa: el cotejo hizo su trabajo.
	// Pero tampoco es un éxito, y el código de salida tiene que distinguirlo para
	// que un cron lo note sin leer la prosa.
	if len(rep.Findings) > 0 {
		return &exitError{
			code:     exitVerify,
			err:      fmt.Errorf("%d hallazgos en la reconciliación", len(rep.Findings)),
			reported: true,
		}
	}
	if rep.FullVerify != nil && !rep.FullVerify.OK {
		return verifyErr("la verificación exhaustiva falló: %s", rep.FullVerify.Err)
	}
	return nil
}

// jsonlSource lee el fichero línea a línea, sin cargarlo entero: un sistema
// real puede tener millones de registros.
func jsonlSource(path string) reconcile.Source {
	return func(yield func(reconcile.Record) error) error {
		f, err := os.Open(path)
		if err != nil {
			return usageErr("no se pudo leer %q: %v", path, err)
		}
		defer f.Close()

		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 0, 1<<20), 16<<20)
		line := 0
		for sc.Scan() {
			line++
			raw := sc.Bytes()
			if len(raw) == 0 {
				continue
			}
			var rec liveRecord
			if err := json.Unmarshal(raw, &rec); err != nil {
				return usageErr("línea %d de %q: %v", line, path, err)
			}
			payload, err := base64.StdEncoding.DecodeString(rec.PayloadB64)
			if err != nil {
				return usageErr("línea %d de %q: payload_b64 inválido: %v", line, path, err)
			}
			if err := yield(reconcile.Record{Index: rec.Index, Payload: payload, Extra: rec.Extra}); err != nil {
				return err
			}
		}
		return sc.Err()
	}
}

// printReport enseña el reporte en español.
func printReport(e *env, rep *reconcile.Report) {
	e.printf("comparados : %d\n", rep.Checked)
	e.printf("coinciden  : %d\n", rep.Verified)
	e.printf("hallazgos  : %d\n", len(rep.Findings))
	if rep.FullVerify != nil {
		if rep.FullVerify.OK {
			e.printf("ledger     : ✔ verificación exhaustiva superada\n")
		} else {
			e.printf("ledger     : ✘ %s\n", rep.FullVerify.Err)
		}
	}
	if len(rep.Findings) == 0 {
		e.printf("\n✔ el sistema vivo coincide con lo sellado en los %d registros comparados\n", rep.Checked)
		return
	}
	for _, f := range rep.Findings {
		e.printf("\n")
		switch f.Status {
		case reconcile.StatusAltered:
			e.printf("  ✘ REGISTRO ALTERADO DESPUÉS DE SELLARSE\n")
			e.printf("      bloque         : %d\n", f.Index)
			e.printf("      emisor         : %s\n", f.Tenant)
			e.printf("      tipo           : %s\n", f.Type)
			e.printf("      sellado el     : %s  (tiempo declarado)\n", f.SealedAt)
			e.printf("      hash sellado   : %s\n", f.SealedHash)
			e.printf("      hash actual    : %s\n", f.CurrentHash)
		case reconcile.StatusMissing:
			e.printf("  ✘ REGISTRO QUE EL SISTEMA VIVO YA NO TIENE\n")
			e.printf("      bloque         : %d\n", f.Index)
			e.printf("      hash sellado   : %s\n", f.SealedHash)
			e.printf("      sellado el     : %s  (tiempo declarado)\n", f.SealedAt)
		case reconcile.StatusExtra:
			e.printf("  ⚠ REGISTRO VIVO QUE NUNCA SE SELLÓ\n")
			e.printf("      índice         : %d\n", f.Index)
			e.printf("      hash actual    : %s\n", f.CurrentHash)
		}
	}
	e.printf("\n  Núcleo no impidió estos cambios: la base operativa no es suya. Lo que\n")
	e.printf("  hace es recordar qué decía cada registro cuando se selló, y desde\n")
	e.printf("  cuándo. La alteración deja de ser invisible.\n")
}

// checkpointOf parsea la nota de un checkpoint guardado.
func checkpointOf(note []byte) (checkpoint.Checkpoint, error) {
	return checkpoint.ParseNote(note)
}
