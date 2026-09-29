package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/nucleoledger/nucleo/internal/store"
	"github.com/nucleoledger/nucleo/internal/vault"
	"golang.org/x/term"
)

func cmdBackup(e *env, args []string) error {
	fs := flag.NewFlagSet("backup", flag.ContinueOnError)
	fs.SetOutput(e.stderr)
	passFile := fs.String("passphrase-file", "", "fichero con la passphrase")
	shares := fs.Int("shares", defaultShares, "número de tarjetas")
	threshold := fs.Int("threshold", defaultThreshold, "tarjetas necesarias para restaurar")
	if err := fs.Parse(args); err != nil {
		return usageErr("%v", err)
	}
	s, _, err := e.openStore()
	if err != nil {
		return err
	}
	defer s.Close()

	pass, err := readPassphrase(e, *passFile, "Passphrase del vault: ", false)
	if err != nil {
		return err
	}
	// Se abre el vault aunque solo hagan falta la KEK y los parámetros: es la
	// forma de comprobar que la passphrase es la correcta ANTES de imprimir unas
	// tarjetas que no abrirían nada.
	v, err := vault.Unlock(s, pass)
	if err != nil {
		return usageErr("no se pudo abrir el vault: %v", err)
	}
	v.Close()

	kek, err := deriveKEKFor(s, pass)
	if err != nil {
		return err
	}
	cards, err := vault.BackupKEK(kek, *shares, *threshold)
	if err != nil {
		return err
	}

	e.out(map[string]any{"shares": cards, "threshold": *threshold}, func() {
		e.printf("✔ tarjetas nuevas emitidas para el vault de %s\n", e.dir)
		e.printf("\n  Las tarjetas ANTERIORES siguen funcionando: respaldan la misma\n")
		e.printf("  clave. Emitir tarjetas nuevas no invalida las viejas, así que si\n")
		e.printf("  las emites porque unas se perdieron, destruye las que encuentres.\n")
		printCards(e, cards, *threshold)
	})
	return nil
}

func cmdRestore(e *env, args []string) error {
	fs := flag.NewFlagSet("restore", flag.ContinueOnError)
	fs.SetOutput(e.stderr)
	file := fs.String("shares-file", "", "fichero con un mnemónico por línea (si no, se piden por terminal)")
	newPassFile := fs.String("new-passphrase-file", "", "fija esta passphrase nueva, leída de un fichero (ADR-029)")
	newPassPrompt := fs.Bool("new-passphrase", false, "fija una passphrase nueva, pedida por terminal (ADR-029)")
	shares := fs.Int("shares", defaultShares, "número de tarjetas nuevas, si se fija una passphrase nueva")
	threshold := fs.Int("threshold", defaultThreshold, "tarjetas nuevas necesarias para restaurar")
	yes := fs.Bool("assume-confirmed", false, "salta la confirmación tecleada de las tarjetas nuevas (solo automatización)")
	if err := fs.Parse(args); err != nil {
		return usageErr("%v", err)
	}
	fijar := *newPassFile != "" || *newPassPrompt
	if *newPassFile != "" && *newPassPrompt {
		return usageErr("--new-passphrase-file y --new-passphrase son dos fuentes de la misma passphrase: usa una")
	}
	// Lo mismo que init (ADR-004): con --json no hay a quién pedirle la palabra, y se
	// comprueba ANTES de tocar nada.
	if fijar && e.json && !*yes {
		return usageErr("restore --json no puede pedir que se teclee la confirmación de las tarjetas nuevas: " +
			"pasa --assume-confirmed explícitamente (y guarda las tarjetas que salen en el JSON)")
	}
	// --new-passphrase la pide por terminal. Sin terminal, readPassphrase diría "usa
	// --passphrase-file", que aquí es la bandera equivocada: se dice la buena, y antes de
	// leer tarjetas.
	if *newPassPrompt {
		if _, ok := hookPassphrase(); !ok && !term.IsTerminal(int(os.Stdin.Fd())) {
			return usageErr("--new-passphrase pide la passphrase por terminal y aquí no hay: " +
				"usa --new-passphrase-file FICHERO")
		}
	}
	s, _, err := e.openStore()
	if err != nil {
		return err
	}
	defer s.Close()

	cards, err := readShares(e, *file)
	if err != nil {
		return err
	}

	kek, err := vault.RestoreKEK(cards)
	if err != nil {
		return usageErr("no se pudo reconstruir la clave: %v", err)
	}

	// Reconstruir NO es demostrar identidad. Un conjunto válido de tarjetas de
	// OTRO vault también reconstruye una clave, y sin este segundo paso el
	// usuario se llevaría un "listo" que no significa nada. La identidad la
	// prueba desenvolver la DEK de ESTE vault, que falla ruidosamente si la
	// clave no es la suya.
	wrapped, err := s.GetMeta(vault.MetaDEKKey)
	if err != nil {
		return err
	}
	rawID, err := s.GetMeta(vault.MetaIDKey)
	if err != nil {
		return err
	}
	// El detalle del AEAD no se imprime: "message authentication failed" no le dice nada
	// a quien tiene las tarjetas en la mano, y las dos causas posibles sí.
	if _, err := vault.UnwrapDEK(kek, wrapped, string(rawID)); err != nil {
		return verifyErr("las tarjetas reconstruyen una clave, pero NO es la de este vault, o son tarjetas\n" +
			"  de antes de un cambio de passphrase: esas quedaron sin valor (ADR-029)")
	}
	hookDieAt("restore:tarjetas-comprobadas")

	if !fijar {
		e.out(map[string]any{
			"restored": true,
			"vault_id": string(rawID),
			"shares":   len(cards),
		}, func() {
			e.printf("✔ clave reconstruida con %d tarjetas y comprobada contra este vault\n", len(cards))
			e.printf("  vault: %s\n", rawID)
			e.printf("\n  Reconstruir la clave no es lo mismo que demostrar que es la de\n")
			e.printf("  este vault: unas tarjetas de otro respaldo también reconstruyen\n")
			e.printf("  algo. Lo que acaba de demostrarlo es que con ella se ha podido\n")
			e.printf("  desenvolver la clave de datos de ESTE vault.\n")
			// Quien llega aquí suele venir de haber perdido la passphrase: se le dice cómo
			// seguir, con la orden que de verdad lo hace.
			e.printf("\n  No se ha cambiado nada. Si perdiste la passphrase, fija una nueva con estas\n")
			e.printf("  mismas tarjetas, desde un terminal (recibirás tarjetas nuevas que copiar):\n\n")
			e.printf("      nucleo --dir %s restore --new-passphrase\n", e.dir)
		})
		return nil
	}

	newPass, err := readPassphrase(e, *newPassFile, "Passphrase NUEVA del vault (no se verá lo que escribes): ", true)
	if err != nil {
		return err
	}
	rk, err := vault.PrepareRekey(s, kek, newPass)
	if err != nil {
		return err
	}
	defer rk.Close()
	nuevas, err := vault.BackupKEK(rk.NewKEK(), *shares, *threshold)
	if err != nil {
		return err
	}

	// Las tarjetas nuevas se enseñan y se confirman ANTES de escribir nada (ADR-029 §B):
	// si nadie confirma, el vault queda como estaba y valen las viejas.
	if !e.json {
		e.printf("✔ las tarjetas son de este vault (%s)\n", rawID)
		e.printf("\n  Estas son las tarjetas NUEVAS. Valen desde que veas «✔ passphrase nueva\n")
		e.printf("  fijada»; hasta entonces no ha cambiado nada y siguen valiendo las viejas.\n")
		printCards(e, nuevas, *threshold)
	}
	hookDieAt("restore:tarjetas-nuevas-emitidas")
	if !*yes {
		ok, err := tecleaLaPalabra(e, nuevas)
		if err != nil {
			return err
		}
		if !ok {
			return usageErr("la palabra no coincide. NO se ha cambiado nada.\n\n" +
				"  La passphrase y las tarjetas de antes siguen siendo las de este vault; las de\n" +
				"  esta pantalla NO sirven para nada, destrúyelas. Vuelve a ejecutar restore\n" +
				"  cuando puedas copiar las tarjetas nuevas.")
		}
	}
	hookDieAt("restore:confirmado")

	if err := rk.Commit(s); err != nil {
		if errors.Is(err, store.ErrMetaChanged) {
			return usageErr("la passphrase de este vault cambió mientras restore trabajaba (¿otro restore a la\n" +
				"  vez?). No se ha escrito nada: las tarjetas de esta pantalla NO sirven. Vuelve a\n" +
				"  ejecutar restore con las tarjetas que valgan ahora.")
		}
		return err
	}
	hookDieAt("restore:fijada")

	// Se comprueba lo que quedó ESCRITO, no lo que se quiso escribir: la passphrase nueva
	// abre el vault desde la base.
	v, err := vault.Unlock(s, newPass)
	if err != nil {
		return fmt.Errorf("la passphrase nueva se escribió pero no abre el vault: %w", err)
	}
	v.Close()

	e.out(map[string]any{
		"restored":           true,
		"vault_id":           string(rawID),
		"shares":             len(cards),
		"passphrase_changed": true,
		"new_shares":         nuevas,
		"threshold":          *threshold,
	}, func() {
		e.printf("✔ passphrase nueva fijada. El vault %s se abre con ella.\n", rawID)
		e.printf("\n  Las tarjetas ANTERIORES ya no sirven para este vault: destrúyelas. Valen las\n")
		e.printf("  de esta pantalla.\n")
		e.printf("\n  Una copia del fichero del ledger hecha ANTES de este cambio se sigue abriendo\n")
		e.printf("  con las tarjetas viejas: guarda esas copias como guardarías las tarjetas, o\n")
		e.printf("  destruye las tarjetas viejas y esa puerta queda cerrada.\n")
		e.printf("\n  Pon la passphrase nueva donde la lee quien sella (docs/OPERACION.md §3).\n")
	})
	return nil
}

// readShares lee los mnemónicos de un fichero o del terminal.
func readShares(e *env, file string) ([]string, error) {
	var src *os.File
	if file != "" {
		// Las tarjetas son mnemónicos: unas pocas líneas de palabras. El mismo
		// tope que para una clave sobra por tres órdenes de magnitud.
		if _, err := readLimited(file, maxKeyFile, "el fichero de tarjetas"); err != nil {
			return nil, err
		}
		f, err := os.Open(file)
		if err != nil {
			return nil, usageErr("no se pudo leer %q: %v", file, err)
		}
		defer f.Close()
		src = f
	} else {
		fmt.Fprintln(e.stderr, "Escribe un mnemónico por línea y termina con una línea vacía:")
		src = os.Stdin
	}

	var cards []string
	sc := bufio.NewScanner(src)
	sc.Buffer(make([]byte, 0, 64*1024), 64*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			if file == "" {
				break
			}
			continue
		}
		cards = append(cards, line)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(cards) == 0 {
		return nil, usageErr("no se dio ningún mnemónico")
	}
	return cards, nil
}
