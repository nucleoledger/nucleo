package main

import (
	"fmt"
	"sort"
	"strings"

	"github.com/nucleoledger/nucleo/internal/commit"
	"github.com/nucleoledger/nucleo/internal/store"
	"github.com/nucleoledger/nucleo/internal/vault"
	"github.com/nucleoledger/nucleo/profiles/ecuador"
)

// profileResult es lo que un perfil extrae de un documento.
type profileResult struct {
	name      string
	tenant    string
	plain     map[string]string
	sensitive []ecuador.Field
}

// applyProfile interpreta el documento con el perfil pedido.
func applyProfile(name string, data []byte) (*profileResult, error) {
	switch strings.TrimPrefix(name, "ecuador.") {
	case "sri.factura":
		rec, clave, err := ecuador.ParseFactura(data)
		if err != nil {
			return nil, err
		}
		return newProfileResult("ecuador.sri.factura", clave.RUCEmisor, rec), nil
	default:
		return nil, fmt.Errorf("perfil desconocido %q; los disponibles son: ecuador.sri.factura", name)
	}
}

func newProfileResult(name, tenant string, rec ecuador.Record) *profileResult {
	p := &profileResult{name: name, tenant: tenant, plain: map[string]string{}}
	for _, f := range rec.Plain() {
		p.plain[f.Name] = f.Value
	}
	p.sensitive = rec.Sensitive()
	return p
}

// metaCommitPrefix es el prefijo bajo el que viven los compromisos de un
// registro en vault_meta.
const metaCommitPrefix = "commit/v1/"

// storeCommitments calcula y guarda los compromisos de los campos sensibles.
//
// Se guardan en vault_meta y no en el header del bloque a propósito. El header
// lo fija PROTOCOL.md §2 con ocho campos escalares, y cada campo nuevo ahí sería
// un cambio de formato que rompería los vectores compartidos y los verificadores
// de otros lenguajes. Los compromisos son metadatos del perfil: se atan al
// registro por su payload_hash, que sí está firmado.
func storeCommitments(s *store.Store, v *vault.Vault, tenant, payloadHash string, p *profileResult) (map[string]string, error) {
	if len(p.sensitive) == 0 {
		return nil, nil
	}
	key, err := v.CommitKey(tenant)
	if err != nil {
		return nil, err
	}
	out := make(map[string]string, len(p.sensitive))
	for _, f := range p.sensitive {
		c, err := commit.CommitField(key, f.Name, f.Value)
		if err != nil {
			return nil, err
		}
		out[f.Name] = c
	}
	blob, err := marshalJSON(out)
	if err != nil {
		return nil, err
	}
	if err := s.PutMeta(metaCommitPrefix+payloadHash, blob); err != nil {
		return nil, err
	}
	return out, nil
}

// printProfile enseña lo que el perfil entendió y lo que decidió ocultar.
func printProfile(e *env, p *profileResult, commitments map[string]string) {
	e.printf("\n  perfil       : %s\n", p.name)
	for _, k := range sortedKeys(p.plain) {
		e.printf("    %-24s %s\n", k+":", p.plain[k])
	}
	if len(commitments) == 0 {
		return
	}
	e.printf("\n  campos sensibles, registrados como COMPROMISO (nunca como hash desnudo):\n")
	names := make([]string, 0, len(commitments))
	for k := range commitments {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, k := range names {
		e.printf("    %-24s %s…\n", k+":", commitments[k][:38])
	}
	e.printf("\n  Un hash desnudo de una cédula o un importe se invierte probando: el\n")
	e.printf("  espacio de valores es diminuto. Con clave, el diccionario no sirve.\n")
}
