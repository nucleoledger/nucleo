package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"flag"
	"strings"

	"github.com/nucleoledger/nucleo/internal/store"
)

// La política es la única raíz de confianza (ADR-017): todo lo que un verificador
// —o el propio operador al abrir su ledger— tiene que traer de FUERA del fichero.
//
// Un solo formato, el mismo JSON que consumen el SDK de TypeScript y la página
// web, para que operador y contraparte usen el mismo fichero:
//
//	{
//	  "origin":    "nucleoledger.com/mi-empresa",
//	  "logKey":    "<hex>",
//	  "signerKey": "<hex>",
//	  "witnesses": { "witness.nucleoledger.com/w1": "<hex>" },
//	  "quorum":    1
//	}

// policyFile es el fichero tal como se escribe. Los nombres son los del SDK.
type policyFile struct {
	Origin    string            `json:"origin"`
	LogKey    string            `json:"logKey"`
	SignerKey string            `json:"signerKey,omitempty"`
	Witnesses map[string]string `json:"witnesses"`
	Quorum    int               `json:"quorum"`
}

// policyFlags son las banderas con las que un subcomando recibe la política: un
// fichero, o las sueltas. Las dos a la vez es error de uso — dos fuentes de verdad
// se contradicen en silencio.
type policyFlags struct {
	file, witnessName, witnessKey, signerKey *string
}

// registerPolicyFlags registra las banderas en el FlagSet del subcomando.
func registerPolicyFlags(fs *flag.FlagSet) policyFlags {
	return policyFlags{
		file:        fs.String("policy-file", "", "fichero JSON con la política (origin, logKey, signerKey, witnesses, quorum)"),
		witnessName: fs.String("witness-name", "", "nombre del testigo cuya cosignature avala el ledger"),
		witnessKey:  fs.String("witness-key", "", "clave pública de ese testigo, en hexadecimal"),
		signerKey:   fs.String("signer-key", "", "clave pública esperada del firmante de bloques, en hexadecimal"),
	}
}

// resolve convierte las banderas en la política de apertura, o en nil si no se
// dio ninguna. Devuelve también el fichero leído, si lo hubo, para que quien
// emite recibos pueda cotejar origin y claves con su propio ledger.
func (pf policyFlags) resolve() (*store.WitnessPolicy, *policyFile, error) {
	sueltas := *pf.witnessName != "" || *pf.witnessKey != "" || *pf.signerKey != ""
	switch {
	case *pf.file != "" && sueltas:
		return nil, nil, usageErr("--policy-file no se combina con --witness-name, --witness-key ni --signer-key: " +
			"dos fuentes de política se contradicen en silencio; usa una")
	case *pf.file != "":
		f, err := loadPolicyFile(*pf.file)
		if err != nil {
			return nil, nil, err
		}
		wp, err := f.witnessPolicy()
		if err != nil {
			return nil, nil, err
		}
		return wp, f, nil
	case !sueltas:
		return nil, nil, nil
	}

	if *pf.witnessName == "" || *pf.witnessKey == "" {
		return nil, nil, usageErr("--witness-name y --witness-key van juntos")
	}
	pub, err := hexKey(*pf.witnessKey)
	if err != nil {
		return nil, nil, err
	}
	wp := &store.WitnessPolicy{
		Witnesses: map[string]ed25519.PublicKey{*pf.witnessName: pub}, Quorum: 1,
	}
	if *pf.signerKey != "" {
		if wp.SignerKey, err = hexKey(*pf.signerKey); err != nil {
			return nil, nil, err
		}
	}
	return wp, nil, nil
}

// loadPolicyFile lee y valida el fichero. Un fichero de política es entrada del
// usuario y se lee con el mismo límite que los demás ficheros pequeños.
func loadPolicyFile(path string) (*policyFile, error) {
	raw, err := readLimited(path, maxKeyFile, "el fichero de política")
	if err != nil {
		return nil, err
	}
	var f policyFile
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields() // una clave mal escrita no se ignora: se señala
	if err := dec.Decode(&f); err != nil {
		return nil, usageErr("la política %q no es válida: %v", path, err)
	}
	if f.Origin == "" {
		return nil, usageErr("la política %q no trae origin", path)
	}
	if _, err := hexKey(f.LogKey); err != nil {
		return nil, usageErr("la política %q: logKey: %v", path, err)
	}
	if f.SignerKey != "" {
		if _, err := hexKey(f.SignerKey); err != nil {
			return nil, usageErr("la política %q: signerKey: %v", path, err)
		}
	}
	if len(f.Witnesses) == 0 {
		return nil, usageErr("la política %q no trae ningún testigo; sin testigos no verifica nada", path)
	}
	for name, k := range f.Witnesses {
		if name == "" {
			return nil, usageErr("la política %q tiene un testigo sin nombre", path)
		}
		if _, err := hexKey(k); err != nil {
			return nil, usageErr("la política %q: testigo %q: %v", path, name, err)
		}
	}
	if f.Quorum < 1 || f.Quorum > len(f.Witnesses) {
		return nil, usageErr("la política %q: quorum %d con %d testigos", path, f.Quorum, len(f.Witnesses))
	}
	return &f, nil
}

// witnessPolicy convierte el fichero en la política de apertura del almacén.
func (f *policyFile) witnessPolicy() (*store.WitnessPolicy, error) {
	wp := &store.WitnessPolicy{Witnesses: map[string]ed25519.PublicKey{}, Quorum: f.Quorum}
	var err error
	if wp.LogKey, err = hexKey(f.LogKey); err != nil {
		return nil, err
	}
	if f.SignerKey != "" {
		if wp.SignerKey, err = hexKey(f.SignerKey); err != nil {
			return nil, err
		}
	}
	for name, k := range f.Witnesses {
		if wp.Witnesses[name], err = hexKey(k); err != nil {
			return nil, err
		}
	}
	return wp, nil
}

// policySnippet escribe la política lista para guardar y el comando listo para el
// cron. Lo imprime sync al terminar (ADR-017 c): quien acaba de sincronizar tiene
// en pantalla lo que tiene que pegar, y la política deja de ser algo que hay que
// saber construir.
func policySnippet(e *env, origin string, logKey, signerKey ed25519.PublicKey, witnessName string, witnessKey ed25519.PublicKey) {
	f := policyFile{
		Origin: origin, LogKey: hex.EncodeToString(logKey), SignerKey: hex.EncodeToString(signerKey),
		Witnesses: map[string]string{witnessName: hex.EncodeToString(witnessKey)}, Quorum: 1,
	}
	raw, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return
	}
	e.printf("\n  Tu política, lista para guardar como politica.json:\n\n")
	for _, l := range strings.Split(string(raw), "\n") {
		e.printf("  %s\n", l)
	}
	e.printf("\n  Y el cron, con ella:\n\n")
	e.printf("    nucleo --dir %s sync --witness URL --policy-file politica.json\n", e.dir)
	e.printf("    nucleo --dir %s status --policy-file politica.json\n\n", e.dir)
	e.printf("  Es lo mismo que tu contraparte necesita para verificar tus recibos:\n")
	e.printf("  la misma política, el mismo fichero.\n")
}

// jsonPolicy es el objeto "policy" que sync emite en --json.
func jsonPolicy(origin string, logKey, signerKey ed25519.PublicKey, witnessName string, witnessKey ed25519.PublicKey) policyFile {
	return policyFile{
		Origin: origin, LogKey: hex.EncodeToString(logKey), SignerKey: hex.EncodeToString(signerKey),
		Witnesses: map[string]string{witnessName: hex.EncodeToString(witnessKey)}, Quorum: 1,
	}
}

// checkPolicyMatchesLedger coteja el fichero contra lo que el ledger declara. Un
// fichero de otro ledger emitiría recibos con una política que no es la del
// emisor, y es mejor decirlo aquí que descubrirlo en la contraparte.
func checkPolicyMatchesLedger(f *policyFile, origin string, logKey, signerKey ed25519.PublicKey) error {
	if f.Origin != origin {
		return usageErr("la política es del log %q y este ledger es %q", f.Origin, origin)
	}
	if !strings.EqualFold(f.LogKey, hex.EncodeToString(logKey)) {
		return usageErr("la clave del log de la política no es la de este ledger")
	}
	if f.SignerKey != "" && !strings.EqualFold(f.SignerKey, hex.EncodeToString(signerKey)) {
		return usageErr("la clave del firmante de la política no es la de este vault")
	}
	return nil
}
