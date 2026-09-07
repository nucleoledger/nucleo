package main

import (
	"encoding/hex"
	"flag"

	"github.com/nucleoledger/nucleo/internal/ledger"
	"github.com/nucleoledger/nucleo/internal/store"
)

func cmdStatus(e *env, args []string) error {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	fs.SetOutput(e.stderr)
	if err := fs.Parse(args); err != nil {
		return usageErr("%v", err)
	}
	s, res, err := e.openStore()
	if err != nil {
		return err
	}
	defer s.Close()

	root, err := s.Root()
	if err != nil {
		return err
	}
	data := map[string]any{
		"dir":           e.dir,
		"tree_size":     res.TreeSize,
		"attested":      res.Attested,
		"attested_size": res.AttestedSize,
		"root":          hex.EncodeToString(root),
	}
	e.out(data, func() {
		e.printf("ledger    : %s\n", e.dbPath())
		e.printf("bloques   : %d\n", res.TreeSize)
		e.printf("raíz      : %s\n", hex.EncodeToString(root))
		printAttestation(e, res)
	})
	return nil
}

func cmdVerify(e *env, args []string) error {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	fs.SetOutput(e.stderr)
	full := fs.Bool("full", false, "recomputa TODAS las firmas, sin apoyarse en ningún checkpoint")
	if err := fs.Parse(args); err != nil {
		return usageErr("%v", err)
	}
	s, res, err := e.openStore()
	if err != nil {
		return err
	}
	defer s.Close()

	mode := "apertura"
	if *full {
		res, err = s.VerifyFull()
		if err != nil {
			return verifyErr("%v", err)
		}
		mode = "exhaustiva"
	}

	e.out(map[string]any{
		"mode":          mode,
		"tree_size":     res.TreeSize,
		"attested":      res.Attested,
		"attested_size": res.AttestedSize,
	}, func() {
		if *full {
			e.printf("✔ verificación EXHAUSTIVA superada: %d bloques, todas las firmas recomputadas\n", res.TreeSize)
		} else {
			e.printf("✔ verificación superada: %d bloques\n", res.TreeSize)
			if res.Attested {
				e.printf("  (las firmas anteriores al bloque %d están amparadas por un\n", res.AttestedSize)
				e.printf("   checkpoint cosignado; `verify --full` las recomprueba todas)\n")
			}
		}
		printAttestation(e, res)
	})
	return nil
}

// printAttestation dice en voz alta qué respalda la historia, con el mismo
// lenguaje del PoC: la distinción entre "íntegra" y "completa" es la que cuesta
// entender y la que más importa.
func printAttestation(e *env, r store.OpenResult) {
	switch {
	case r.TreeSize == 0:
		e.printf("estado    : base nueva, todavía sin historia que atestiguar\n")
	case r.Attested:
		e.printf("estado    : ✔ historia atestiguada hasta %d de %d bloques\n", r.AttestedSize, r.TreeSize)
	default:
		e.printf("estado    : ⚠ SIN ATESTIGUAR (%d bloques)\n", r.TreeSize)
		e.printf("            La cadena es localmente válida, pero que esté COMPLETA no\n")
		e.printf("            está garantizado: sin un checkpoint cosignado por un testigo,\n")
		e.printf("            un prefijo truncado es indistinguible de la historia entera.\n")
		e.printf("            Ejecuta `nucleo sync` contra un testigo.\n")
	}
}

// leafHashOf devuelve la hoja de Merkle de un bloque.
func leafHashOf(b *ledger.Block) ([]byte, error) { return b.HashBytes() }
