package witness

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/nucleoledger/nucleo/internal/checkpoint"
	"github.com/nucleoledger/nucleo/internal/estricto"
)

// MaxConfigSize es el tamaño máximo del fichero de configuración del testigo: 1 MiB,
// que son miles de logs.
const MaxConfigSize = 1 << 20

// ErrConfig es la causa de todo rechazo de la configuración del testigo.
var ErrConfig = errors.New("configuración del testigo inválida")

// Config es la configuración de un testigo de varios logs (ADR-030), ya validada.
type Config struct {
	// Name es el nombre del testigo, el que va en sus cosignatures.
	Name string
	// Logs son los logs que cosigna: origin → clave pública.
	Logs map[string]ed25519.PublicKey
	// Retired son los logs retirados: se recuerdan y se publican, no se cosignan.
	Retired map[string]ed25519.PublicKey
}

var miembrosDeConfig = []string{"name", "logs", "retired"}

// ParseConfig lee y valida la configuración con la gramática estricta de la política
// (ADR-018): miembros repetidos, variantes de mayúsculas, miembros desconocidos,
// comentarios, comas finales, BOM, arrays, booleanos y null son error.
//
//	{
//	  "name":    "testigo.ejemplo.ec/w1",
//	  "logs":    { "<origin>": "<clave hex>", … },
//	  "retired": { "<origin>": "<clave hex>", … }
//	}
func ParseConfig(raw []byte) (*Config, error) {
	obj, err := estricto.Leer(raw, estricto.Opciones{
		Error:       ErrConfig,
		Max:         MaxConfigSize,
		Profundidad: 2, // el documento y, debajo, los objetos de logs
		MsgAnidado:  "objeto anidado donde la configuración del testigo no admite ninguno",
		MsgValor:    "valor no admitido en la configuración del testigo (solo cadenas y los objetos de logs)",
	})
	if err != nil {
		return nil, err
	}
	c := &Config{Logs: map[string]ed25519.PublicKey{}, Retired: map[string]ed25519.PublicKey{}}
	tiene := map[string]bool{}
	for _, m := range obj {
		if !esMiembroDeConfig(m.Nombre) {
			for _, k := range miembrosDeConfig {
				if estricto.AsciiIgual(m.Nombre, k) {
					return nil, fmt.Errorf("%w: el miembro %q es una variante de mayúsculas de %q", ErrConfig, m.Nombre, k)
				}
			}
			return nil, fmt.Errorf("%w: miembro desconocido %q", ErrConfig, m.Nombre)
		}
		tiene[m.Nombre] = true
		switch m.Nombre {
		case "name":
			if m.Valor.Tipo != 's' || m.Valor.Cadena == "" {
				return nil, fmt.Errorf("%w: name tiene que ser una cadena no vacía", ErrConfig)
			}
			c.Name = m.Valor.Cadena
		case "logs", "retired":
			destino := c.Logs
			if m.Nombre == "retired" {
				destino = c.Retired
			}
			if err := leerLogs(m.Nombre, m.Valor, destino); err != nil {
				return nil, err
			}
		}
	}
	for _, req := range []string{"name", "logs"} {
		if !tiene[req] {
			return nil, fmt.Errorf("%w: falta el miembro %q", ErrConfig, req)
		}
	}
	if len(c.Logs) == 0 {
		return nil, fmt.Errorf("%w: logs no trae ningún log; un testigo que no cosigna nada no hace falta", ErrConfig)
	}
	for origin := range c.Retired {
		if _, ok := c.Logs[origin]; ok {
			return nil, fmt.Errorf("%w: %q está en logs y en retired: o se cosigna o está retirado", ErrConfig, origin)
		}
	}
	// El nombre del testigo, validado con las reglas de nombre de signed-note, que son
	// las que aplicará su firmante.
	if _, err := checkpoint.NewVerifier(c.Name, make(ed25519.PublicKey, ed25519.PublicKeySize)); err != nil {
		return nil, fmt.Errorf("%w: name %q: %w", ErrConfig, c.Name, err)
	}
	return c, nil
}

func leerLogs(nombre string, v estricto.Valor, destino map[string]ed25519.PublicKey) error {
	if v.Tipo != 'o' {
		return fmt.Errorf("%w: %s tiene que ser un objeto origin → clave", ErrConfig, nombre)
	}
	for _, l := range v.Objeto {
		if l.Nombre == "" {
			return fmt.Errorf("%w: un log sin origin en %s", ErrConfig, nombre)
		}
		if l.Valor.Tipo != 's' || !estricto.HexClave(l.Valor.Cadena) {
			return fmt.Errorf("%w: la clave de %q en %s tiene que ser de 64 caracteres hexadecimales en minúsculas", ErrConfig, l.Nombre, nombre)
		}
		raw, _ := hex.DecodeString(l.Valor.Cadena) // HexClave ya lo garantizó
		pub := ed25519.PublicKey(raw)
		// El origin, validado como lo hará el verificador del testigo.
		if _, err := checkpoint.NewVerifier(l.Nombre, pub); err != nil {
			return fmt.Errorf("%w: el origin %q en %s: %w", ErrConfig, l.Nombre, nombre, err)
		}
		destino[l.Nombre] = pub
	}
	return nil
}

func esMiembroDeConfig(nombre string) bool {
	for _, k := range miembrosDeConfig {
		if nombre == k {
			return true
		}
	}
	return false
}

// Apply registra en el testigo los logs de la configuración: los activos con AddLog y
// los retirados con RetireLog.
func (c *Config) Apply(w *Witness) error {
	for origin, pub := range c.Logs {
		if err := w.AddLog(origin, pub); err != nil {
			return err
		}
	}
	for origin, pub := range c.Retired {
		if err := w.RetireLog(origin, pub); err != nil {
			return err
		}
	}
	return nil
}
