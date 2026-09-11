package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/nucleoledger/nucleo/internal/identity"
	"github.com/nucleoledger/nucleo/internal/store"
	"github.com/nucleoledger/nucleo/internal/vault"
	"golang.org/x/term"
)

// env lleva lo común a todos los subcomandos.
type env struct {
	stdout *os.File
	stderr *os.File
	// json activa la salida para máquinas.
	json bool
	// dir es el directorio del despliegue.
	dir string
	// staleAfter es el umbral de la política fail-stale.
	staleAfter time.Duration
}

// dbPath devuelve la ruta del ledger.
func (e *env) dbPath() string { return filepath.Join(e.dir, "nucleo.db") }

// printf escribe en la salida humana. En modo --json no escribe nada: mezclar
// prosa con JSON en el mismo flujo rompe a quien lo parsea.
func (e *env) printf(format string, args ...any) {
	if e.json {
		return
	}
	fmt.Fprintf(e.stdout, format, args...)
}

// printJSON emite un objeto en la salida máquina.
func (e *env) printJSON(v any) {
	enc := json.NewEncoder(e.stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		fmt.Fprintln(e.stderr, "error serializando la salida:", err)
	}
}

// out emite el resultado: JSON si se pidió, y si no ejecuta la función humana.
func (e *env) out(data map[string]any, human func()) {
	if e.json {
		if _, ok := data["ok"]; !ok {
			data["ok"] = true
		}
		e.printJSON(data)
		return
	}
	human()
}

// dispatch reparte a los subcomandos tras leer las banderas globales.
func dispatch(e *env, args []string) error {
	rest, err := parseGlobals(e, args)
	if err != nil {
		return err
	}
	if len(rest) == 0 {
		return usageErr("falta el subcomando\n\n%s", usageText())
	}
	name := rest[0]
	if name == "help" || name == "-h" || name == "--help" {
		fmt.Fprint(e.stdout, usageText())
		return nil
	}
	cmd, ok := commands[name]
	if !ok {
		return usageErr("subcomando desconocido %q\n\n%s", name, usageText())
	}
	// La comprobación va aquí y no en cada subcomando: si depende de que alguien
	// se acuerde de llamarla, tarde o temprano habrá un subcomando que no la
	// haga, y será justo el que alguien ejecute con la semilla puesta.
	//
	// En un binario de producción esto ABORTA si hay algún gancho definido; en
	// uno compilado con -tags testhooks solo avisa de que sí los honra.
	if err := checkHooks(e); err != nil {
		return err
	}
	return cmd(e, rest[1:])
}

// parseGlobals extrae --json y --dir de cualquier posición previa al
// subcomando, para que `nucleo --json status` y `nucleo status --json` sean lo
// mismo. Un usuario no debería tener que recordar el orden.
func parseGlobals(e *env, args []string) ([]string, error) {
	e.dir = "."
	e.staleAfter = DefaultStaleAfter
	var rest []string
	for i := 0; i < len(args); i++ {
		switch a := args[i]; {
		case a == "--json":
			e.json = true
		case a == "--stale-after" || strings.HasPrefix(a, "--stale-after="):
			v := strings.TrimPrefix(a, "--stale-after=")
			if v == a {
				if i+1 >= len(args) {
					return nil, usageErr("--stale-after necesita un valor, p.ej. 72h")
				}
				i++
				v = args[i]
			}
			d, err := time.ParseDuration(v)
			if err != nil {
				return nil, usageErr("--stale-after: %v", err)
			}
			if d <= 0 {
				return nil, usageErr("--stale-after tiene que ser positivo; 0 desactivaría el aviso, y para eso mejor no ponerlo")
			}
			e.staleAfter = d
		case a == "--dir":
			if i+1 >= len(args) {
				return nil, usageErr("--dir necesita un valor")
			}
			i++
			e.dir = args[i]
		case strings.HasPrefix(a, "--dir="):
			e.dir = strings.TrimPrefix(a, "--dir=")
		default:
			rest = append(rest, a)
		}
	}
	return rest, nil
}

// openStore abre el ledger del directorio.
func (e *env) openStore() (*store.Store, store.OpenResult, error) {
	if _, err := os.Stat(e.dbPath()); err != nil {
		return nil, store.OpenResult{}, usageErr("no hay ledger en %q; ejecuta `nucleo init --dir %s`", e.dir, e.dir)
	}
	s, res, err := store.Open(e.dbPath())
	if err != nil {
		// Abrir falla cuando la integridad no cuadra: eso es verificación, no uso.
		if errors.Is(err, store.ErrIntegrity) {
			return nil, store.OpenResult{}, verifyErr("%v", err)
		}
		return nil, store.OpenResult{}, err
	}
	return s, res, nil
}

// unlock abre el vault y carga las identidades.
func (e *env) unlock(s *store.Store, passphraseFile string, prompt string) (*vault.Vault, *identity.Identity, error) {
	pass, err := readPassphrase(e, passphraseFile, prompt, false)
	if err != nil {
		return nil, nil, err
	}
	v, err := vault.Unlock(s, pass)
	if err != nil {
		return nil, nil, usageErr("no se pudo abrir el vault: %v", err)
	}
	id, err := identity.Load(v, s)
	if err != nil {
		v.Close()
		return nil, nil, err
	}
	return v, id, nil
}

// readPassphrase lee la passphrase de un fichero o del terminal SIN ECO.
//
// Sin eco no es un detalle de comodidad: una passphrase escrita en pantalla
// queda en el scrollback del terminal, en las capturas y a la vista de quien
// pase por detrás. Y no se acepta por argumento en ningún caso, porque los
// argumentos son visibles en la lista de procesos de toda la máquina.
func readPassphrase(e *env, file, prompt string, confirm bool) ([]byte, error) {
	if file != "" {
		raw, err := readLimited(file, maxKeyFile, "el fichero de passphrase")
		if err != nil {
			return nil, err
		}
		pass := []byte(strings.TrimRight(string(raw), "\r\n"))
		if len(pass) == 0 {
			return nil, usageErr("el fichero de passphrase %q está vacío", file)
		}
		return pass, nil
	}
	if pass, ok := hookPassphrase(); ok {
		return []byte(pass), nil
	}
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return nil, usageErr("no hay terminal para pedir la passphrase; usa --passphrase-file")
	}
	fmt.Fprint(e.stderr, prompt)
	pass, err := term.ReadPassword(fd)
	fmt.Fprintln(e.stderr)
	if err != nil {
		return nil, err
	}
	if len(pass) == 0 {
		return nil, usageErr("la passphrase está vacía")
	}
	if confirm {
		fmt.Fprint(e.stderr, "Repite la passphrase: ")
		again, err := term.ReadPassword(fd)
		fmt.Fprintln(e.stderr)
		if err != nil {
			return nil, err
		}
		if string(again) != string(pass) {
			return nil, usageErr("las dos passphrases no coinciden")
		}
	}
	return pass, nil
}

// hexKey parsea una clave pública Ed25519 en hexadecimal.
func hexKey(s string) (ed25519.PublicKey, error) {
	raw, err := hex.DecodeString(s)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, usageErr("clave pública inválida %q: se esperan %d bytes en hexadecimal", s, ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(raw), nil
}

// sortedKeys devuelve las claves de un mapa en orden, para salidas estables.
func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// unmarshalJSON evita repetir el import de encoding/json en cada subcomando.
func unmarshalJSON(raw []byte, v any) error { return json.Unmarshal(raw, v) }

// marshalJSON serializa de forma estable.
func marshalJSON(v any) ([]byte, error) { return json.Marshal(v) }
