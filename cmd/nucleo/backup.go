package main

import (
	"bufio"
	"flag"
	"os"
	"strings"

	"github.com/nucleoledger/nucleo/internal/vault"
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
	if err := fs.Parse(args); err != nil {
		return usageErr("%v", err)
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
	if _, err := vault.UnwrapDEK(kek, wrapped, string(rawID)); err != nil {
		return verifyErr("las tarjetas reconstruyen una clave, pero NO es la de este vault: %v", err)
	}

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
	})
	return nil
}

// readShares lee los mnemónicos de un fichero o del terminal.
func readShares(e *env, file string) ([]string, error) {
	var src *os.File
	if file != "" {
		f, err := os.Open(file)
		if err != nil {
			return nil, usageErr("no se pudo leer %q: %v", file, err)
		}
		defer f.Close()
		src = f
	} else {
		e.stderr.WriteString("Escribe un mnemónico por línea y termina con una línea vacía:\n")
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
