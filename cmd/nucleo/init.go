package main

import (
	"bufio"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/nucleoledger/nucleo/internal/identity"
	"github.com/nucleoledger/nucleo/internal/store"
	"github.com/nucleoledger/nucleo/internal/vault"
)

// Reparto por defecto de las tarjetas: 2 de 3, como fija ADR-004.
const (
	defaultShares    = 3
	defaultThreshold = 2
)

func cmdInit(e *env, args []string) error {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	fs.SetOutput(e.stderr)
	origin := fs.String("origin", "", "identificador del log, p. ej. nucleoledger.com/mi-empresa")
	passFile := fs.String("passphrase-file", "", "fichero con la passphrase (para automatización)")
	shares := fs.Int("shares", defaultShares, "número de tarjetas de respaldo")
	threshold := fs.Int("threshold", defaultThreshold, "tarjetas necesarias para restaurar")
	yes := fs.Bool("assume-confirmed", false, "salta la confirmación tecleada de la tarjeta (solo automatización)")
	kdf := fs.String("kdf-profile", string(vault.ProfileDefault),
		"perfil de derivación de la passphrase: default (64 MiB) o constrained (19 MiB, hosting compartido)")
	if err := fs.Parse(args); err != nil {
		return usageErr("%v", err)
	}
	if *origin == "" {
		return usageErr("init necesita --origin")
	}
	if err := os.MkdirAll(e.dir, 0o700); err != nil {
		return usageErr("no se pudo crear %q: %v", e.dir, err)
	}
	if _, err := os.Stat(e.dbPath()); err == nil {
		return usageErr("ya hay un ledger en %q; init no sobrescribe nada", e.dir)
	}

	pass, err := readPassphrase(e, *passFile,
		"Passphrase del vault (no se verá lo que escribes): ", true)
	if err != nil {
		return err
	}

	s, _, err := store.Open(e.dbPath())
	if err != nil {
		return err
	}
	defer s.Close()

	vaultID := *origin
	// El perfil se valida ANTES de derivar, para que un nombre mal escrito dé un
	// error de uso en vez de un vault creado con los parámetros por omisión
	// mientras quien lo creó cree que eligió otra cosa.
	profile := vault.KDFProfile(*kdf)
	if _, err := vault.ParamsFor(profile, make([]byte, vault.SaltLen)); err != nil {
		return usageErr("--kdf-profile: %v; los válidos son %q y %q",
			err, vault.ProfileDefault, vault.ProfileConstrained)
	}
	v, err := vault.CreateWithProfile(s, vaultID, pass, profile)
	if err != nil {
		return err
	}
	defer v.Close()

	id, err := newIdentity(*origin)
	if err != nil {
		return err
	}
	if err := id.Save(v, s); err != nil {
		return err
	}
	// La pública del log se guarda además EN CLARO. Es pública —no hay nada que
	// proteger— y así verificar un recibo o consultar el estado no exige abrir
	// el vault. Obligar a teclear la passphrase para leer una clave pública
	// empujaría a la gente a dejarla escrita en algún sitio.
	if err := s.PutMeta(metaLogPubKey, id.LogPublic()); err != nil {
		return err
	}
	if err := s.PutMeta(metaOriginKey, []byte(id.Origin)); err != nil {
		return err
	}
	// Y la del firmante de bloques, también en claro: status la publica para que
	// una política se pueda escribir sin abrir el vault. Es fuente de comparación,
	// no raíz de confianza —la raíz es la política que viene de fuera (ADR-017)—.
	if err := s.PutMeta(store.MetaSignerPubKey, id.TenantPublic()); err != nil {
		return err
	}

	kek, err := deriveKEKFor(s, pass)
	if err != nil {
		return err
	}
	cards, err := vault.BackupKEK(kek, *shares, *threshold)
	if err != nil {
		return err
	}

	// Los parámetros se leen de vault_meta, no de la variable local: así lo que se
	// informa es lo que quedó GUARDADO, que es lo que Unlock usará.
	storedParams, err := storedKDFParams(s)
	if err != nil {
		return err
	}

	e.out(map[string]any{
		"origin":        id.Origin,
		"dir":           e.dir,
		"tenant_pubkey": hexOf(id.TenantPublic()),
		"log_pubkey":    hexOf(id.LogPublic()),
		"shares":        cards,
		"threshold":     *threshold,
		"kdf": map[string]any{
			"profile":     storedParams.Profile(),
			"memory_mib":  storedParams.Memory / 1024,
			"iterations":  storedParams.Time,
			"parallelism": storedParams.Threads,
		},
	}, func() {
		e.printf("✔ vault y ledger creados en %s\n", e.dir)
		e.printf("  origin        : %s\n", id.Origin)
		e.printf("  clave tenant  : %s\n", hexOf(id.TenantPublic()))
		e.printf("  clave del log : %s\n", hexOf(id.LogPublic()))
		e.printf("  perfil KDF    : %s (%d MiB, %d iteraciones, %d hilo(s))\n",
			storedParams.Profile(), storedParams.Memory/1024, storedParams.Time, storedParams.Threads)
		if storedParams.Profile() == string(vault.ProfileConstrained) {
			e.printf("                  Más débil que el perfil por omisión, a cambio de caber\n")
			e.printf("                  en un plan compartido. Usa una passphrase más larga.\n")
		}
		printCards(e, cards, *threshold)
	})

	if e.json || *yes {
		return nil
	}
	return confirmCard(e, cards, *threshold)
}

// printCards enseña las tarjetas con las instrucciones de custodia.
//
// El texto es largo a propósito. Estas palabras son la única forma de recuperar
// el vault si se pierde la passphrase, y quien las lee por primera vez no sabe
// todavía lo que tiene delante. Ahorrar aquí seis líneas de explicación se paga
// años después, cuando ya no hay a quién preguntar.
func printCards(e *env, cards []string, threshold int) {
	e.printf("\n")
	e.printf("═══════════════════════════════════════════════════════════════\n")
	e.printf("  TARJETAS DE RESPALDO DE LA CLAVE — SLIP-0039\n")
	e.printf("═══════════════════════════════════════════════════════════════\n")
	e.printf("\n")
	e.printf("  Son %d tarjetas y hacen falta %d para recuperar el vault.\n", len(cards), threshold)
	e.printf("  Con %d no se recupera nada: no son copias, son fragmentos.\n\n", threshold-1)
	for i, c := range cards {
		e.printf("  ── TARJETA %d de %d ──\n", i+1, len(cards))
		for _, line := range wrapWords(c, 6) {
			e.printf("     %s\n", line)
		}
		e.printf("\n")
	}
	e.printf("  CÓMO GUARDARLAS\n")
	e.printf("  · Escríbelas EN PAPEL. No en el ordenador, no en el móvil, no\n")
	e.printf("    en una foto: cualquiera de esas cosas se sincroniza sola con\n")
	e.printf("    algún sitio que no controlas.\n")
	e.printf("  · Guárdalas en %d lugares DISTINTOS y con dueños distintos. Dos\n", len(cards))
	e.printf("    tarjetas en el mismo cajón son una sola tarjeta.\n")
	e.printf("  · Quien reúna %d tarjetas abre el vault. Repártelas pensando en\n", threshold)
	e.printf("    eso, no solo en no perderlas.\n")
	e.printf("  · Esta pantalla NO se puede volver a ver. Se pueden emitir\n")
	e.printf("    tarjetas nuevas con `nucleo backup`, pero solo si aún tienes\n")
	e.printf("    la passphrase.\n")
	e.printf("\n")
}

// confirmCard exige teclear una palabra concreta de una tarjeta.
//
// Es la UX guiada que pide ADR-004, y no es un trámite: obliga a que las
// tarjetas se hayan copiado ANTES de que la pantalla desaparezca. Sin esto, el
// error más común —seguir adelante pensando en apuntarlas luego— no se detecta
// hasta el día en que hacen falta.
func confirmCard(e *env, cards []string, threshold int) error {
	const cardIdx, wordIdx = 0, 3
	words := strings.Fields(cards[cardIdx])
	if len(words) <= wordIdx {
		return fmt.Errorf("la tarjeta 1 tiene %d palabras", len(words))
	}

	fmt.Fprintf(e.stderr, "Para confirmar que has copiado las tarjetas, escribe la palabra número %d de la TARJETA 1: ", wordIdx+1)
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		return usageErr("no se pudo leer la confirmación: %v", err)
	}
	if strings.TrimSpace(line) != words[wordIdx] {
		return usageErr("la palabra no coincide.\n\n"+
			"  El vault y el ledger quedan creados en %s, pero las tarjetas de\n"+
			"  esta pantalla son las ÚNICAS que existen. Cópialas ahora, o vuelve\n"+
			"  a emitirlas con `nucleo backup --dir %s` mientras tengas la passphrase.",
			e.dir, e.dir)
	}
	e.printf("✔ confirmado. Guarda las tarjetas como se ha explicado.\n")
	return nil
}

// newIdentity genera las identidades, o las deriva de la semilla de pruebas.
func newIdentity(origin string) (*identity.Identity, error) {
	seed, ok := hookSeed()
	if !ok {
		return identity.Generate(origin)
	}
	derive := func(label string) []byte {
		sum := sha256.Sum256(append(append([]byte{}, seed...), label...))
		return sum[:]
	}
	return identity.FromSeeds(origin, derive("tenant"), derive("log"), derive("pq"))
}

// deriveKEKFor rederiva la KEK con los parámetros guardados en el vault. Se
// necesita para respaldarla: el vault en memoria guarda la DEK, no la KEK.
func deriveKEKFor(ms vault.MetaStore, pass []byte) ([]byte, error) {
	raw, err := ms.GetMeta(vault.MetaParamsKey)
	if err != nil {
		return nil, err
	}
	var p vault.Params
	if err := unmarshalJSON(raw, &p); err != nil {
		return nil, err
	}
	return vault.DeriveKEK(pass, p)
}

// wrapWords parte un mnemónico en líneas de n palabras, para que se pueda
// copiar a mano sin perder el sitio.
func wrapWords(s string, n int) []string {
	words := strings.Fields(s)
	var out []string
	for i := 0; i < len(words); i += n {
		j := min(i+n, len(words))
		out = append(out, strings.Join(words[i:j], " "))
	}
	return out
}

func hexOf(b ed25519.PublicKey) string { return fmt.Sprintf("%x", b) }

// storedKDFParams lee de vault_meta los parámetros de Argon2id con los que se
// derivó la KEK.
//
// Se leen de la base y no de la constante del código porque son dos cosas que
// pueden divergir: el código tiene los parámetros de ESTA versión, la base los
// del día en que se creó el vault. Lo que importa —y lo que Unlock usará— es lo
// que está guardado.
func storedKDFParams(s *store.Store) (vault.Params, error) {
	raw, err := s.GetMeta(vault.MetaParamsKey)
	if err != nil {
		return vault.Params{}, err
	}
	var p vault.Params
	if err := json.Unmarshal(raw, &p); err != nil {
		return vault.Params{}, fmt.Errorf("parámetros de KDF ilegibles: %w", err)
	}
	return p, nil
}
