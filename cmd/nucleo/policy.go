package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"runtime"
	"strings"

	"github.com/nucleoledger/nucleo/internal/identity"
	"github.com/nucleoledger/nucleo/internal/policy"
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

// policyDoc es la política tal como la ESCRIBE la CLI (el snippet de sync y el
// objeto "policy" de --json). Para LEERLA está internal/policy, con la gramática
// estricta de PROTOCOL.md §3.2: encoding/json no sirve para eso (ADR-018).
type policyDoc struct {
	Origin    string            `json:"origin"`
	LogKey    string            `json:"logKey"`
	SignerKey string            `json:"signerKey,omitempty"`
	Witnesses map[string]string `json:"witnesses"`
	Quorum    int               `json:"quorum"`
}

// optString es una bandera de texto que recuerda si se pasó. flag.String no
// distingue "--policy-file ”" de no pasar la bandera, y esa diferencia es la de
// un cron con una variable vacía que degradaba en silencio a "sin política".
type optString struct {
	set bool
	v   string
}

func (o *optString) String() string { return o.v }
func (o *optString) Set(v string) error {
	o.set, o.v = true, v
	return nil
}

// policyFlags son las banderas con las que un subcomando recibe la política: un
// fichero, o las sueltas. Las dos a la vez es error de uso — dos fuentes de verdad
// se contradicen en silencio.
type policyFlags struct {
	file                               *optString
	witnessName, witnessKey, signerKey *string
}

// registerPolicyFlags registra las banderas en el FlagSet del subcomando.
func registerPolicyFlags(fs *flag.FlagSet) policyFlags {
	pf := policyFlags{
		file:        &optString{},
		witnessName: fs.String("witness-name", "", "nombre del testigo cuya cosignature avala el ledger"),
		witnessKey:  fs.String("witness-key", "", "clave pública de ese testigo, en hexadecimal"),
		signerKey:   fs.String("signer-key", "", "clave pública esperada del firmante de bloques, en hexadecimal"),
	}
	fs.Var(pf.file, "policy-file", "fichero JSON con la política (origin, logKey, signerKey, witnesses, quorum)")
	return pf
}

// resolve convierte las banderas en la política de apertura, o en nil si no se
// dio ninguna. Devuelve también el fichero leído, si lo hubo, para que quien
// emite recibos pueda cotejar origin y claves con su propio ledger.
func (pf policyFlags) resolve(e *env) (*store.WitnessPolicy, *policy.File, error) {
	sueltas := *pf.witnessName != "" || *pf.witnessKey != "" || *pf.signerKey != ""
	switch {
	case pf.file.set && pf.file.v == "":
		return nil, nil, usageErr("--policy-file vacío: si una variable de entorno no está definida, " +
			"el comando no puede seguir como si no se hubiera pedido política")
	case pf.file.set && sueltas:
		return nil, nil, usageErr("--policy-file no se combina con --witness-name, --witness-key ni --signer-key: " +
			"dos fuentes de política se contradicen en silencio; usa una")
	case pf.file.set:
		f, err := loadPolicyFile(e, pf.file.v)
		if err != nil {
			return nil, nil, err
		}
		return f.WitnessPolicy(), f, nil
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

// loadPolicyFile lee y valida el fichero con internal/policy.
//
// Avisa, sin fallar, si el fichero tiene permisos distintos de 0600 y 0644. La
// política no es secreta, pero quien pueda escribirla decide qué se verifica: la
// tercera auditoría la dejó en 0666 y ni un aviso. En Windows esos bits no
// significan lo mismo y no se mira.
func loadPolicyFile(e *env, path string) (*policy.File, error) {
	raw, err := readLimited(path, policy.MaxSize, "el fichero de política")
	if err != nil {
		return nil, err
	}
	if runtime.GOOS != "windows" {
		if st, err := os.Stat(path); err == nil {
			if perm := st.Mode().Perm(); perm != 0o600 && perm != 0o644 {
				fmt.Fprintf(e.stderr, "AVISO: la política %q tiene permisos %04o. Quien pueda escribirla decide qué\n"+
					"       se verifica; déjala en 0600 o 0644.\n", path, perm)
			}
		}
	}
	f, err := policy.Parse(raw)
	if err != nil {
		return nil, usageErr("la política %q no es válida: %v", path, err)
	}
	return f, nil
}

// policySnippet escribe la política lista para guardar y el comando listo para el
// cron. Lo imprime sync al terminar (ADR-017 c): quien acaba de sincronizar tiene
// en pantalla lo que tiene que pegar, y la política deja de ser algo que hay que
// saber construir.
func policySnippet(e *env, origin string, logKey, signerKey ed25519.PublicKey, witnessName string, witnessKey ed25519.PublicKey) {
	f := policyDoc{
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
func jsonPolicy(origin string, logKey, signerKey ed25519.PublicKey, witnessName string, witnessKey ed25519.PublicKey) policyDoc {
	return policyDoc{
		Origin: origin, LogKey: hex.EncodeToString(logKey), SignerKey: hex.EncodeToString(signerKey),
		Witnesses: map[string]string{witnessName: hex.EncodeToString(witnessKey)}, Quorum: 1,
	}
}

// checkPolicyMatchesLedger coteja el fichero contra lo que el ledger declara. Un
// fichero de otro ledger emitiría recibos con una política que no es la del
// emisor, y es mejor decirlo aquí que descubrirlo en la contraparte.
func checkPolicyMatchesLedger(f *policy.File, origin string, logKey, signerKey ed25519.PublicKey) error {
	if f.Origin != origin {
		return usageErr("la política es del log %q y este ledger es %q", f.Origin, origin)
	}
	if f.LogKey != hex.EncodeToString(logKey) {
		return usageErr("la clave del log de la política no es la de este ledger")
	}
	if f.SignerKey != "" && f.SignerKey != hex.EncodeToString(signerKey) {
		return usageErr("la clave del firmante de la política no es la de este vault")
	}
	return nil
}

// checkChainSigner exige que la cadena la firme la clave de ESTE vault antes de
// escribir en ella o de pedir a un testigo que la cosigne (E.3).
//
// seal y sync son los dos únicos procesos que tienen la clave legítima en la mano
// —acaban de desbloquear el vault— y no la comparaban con la cadena. La tercera
// auditoría reescribió la cadena entera con otra clave: seal añadía un bloque
// legítimo encima y respondía ok:true, y el primer sync con banderas sueltas hacía
// que el testigo cosignara la historia ajena, que a partir de ahí su memoria
// protegía frente a la legítima. Sin política no hay forma de distinguir una
// cadena ajena de la propia; con el vault abierto, sí.
func checkChainSigner(res store.OpenResult, id *identity.Identity, accion string) error {
	own := hex.EncodeToString(id.TenantPublic())
	if res.SignerKey == "" || res.SignerKey == own {
		return nil
	}
	return verifyErr("no se %s: los %d bloques de este ledger los firma %s… y la clave de este vault es %s…. "+
		"O la cadena entera fue reescrita con otra clave, o este vault no es el de este ledger; "+
		"en ninguno de los dos casos se escribe encima ni se pide a un testigo que la avale",
		accion, res.TreeSize, prefijoClave(res.SignerKey), prefijoClave(own))
}

// prefijoClave recorta una clave en hexadecimal para un mensaje de error.
//
// Existe porque el recorte directo —clave[:16]— es un PÁNICO en cuanto la clave viene
// más corta, y esas claves vienen de un recibo ajeno o de una base que el modelo de
// amenaza da por manipulable. La cuarta auditoría lo señaló (H3) y era alcanzable:
// Parse de un recibo con signer_pubkey de cuatro caracteres tumbaba el proceso. Un
// pánico es una caída provocable; un rechazo con mensaje es un rechazo.
func prefijoClave(s string) string {
	const n = 16
	if len(s) <= n {
		return s
	}
	return s[:n]
}
