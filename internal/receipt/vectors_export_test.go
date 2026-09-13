package receipt

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nucleoledger/nucleo/internal/checkpoint"
	"github.com/nucleoledger/nucleo/internal/ledger"
	"github.com/nucleoledger/nucleo/internal/proof"
	"github.com/nucleoledger/nucleo/internal/witness"
)

// Estos vectores son LA VARA del verificador de TypeScript.
//
// Se exportan desde un test para que no puedan desincronizarse del código que
// los produce: si el formato del recibo cambia, este test los reescribe y el
// diff sale en la revisión. Un fichero generado a mano se queda viejo en
// silencio, que es la peor forma de tener vectores.

// vectorFile es la forma de cada fichero exportado.
type vectorFile struct {
	// Name identifica el caso.
	Name string `json:"name"`
	// Description dice qué demuestra, en español, para quien lea el JSON.
	Description string `json:"description"`
	// Receipt es el recibo COMPLETO, tal cual se entrega.
	Receipt string `json:"receipt"`
	// Policy son las claves con las que hay que verificarlo.
	Policy vectorPolicy `json:"policy"`
	// LeafData es leaf_data de la hoja, en hex: hash ‖ signature (leaf/v2,
	// PROTOCOL.md §2.1). Lo que el verificador mete en la prueba de inclusión.
	LeafData string `json:"leaf_data"`
	// LeafRule nombra la regla con la que se construyó, para que un verificador
	// futuro sepa qué está leyendo sin deducirlo del tamaño.
	LeafRule string `json:"leaf_rule"`
	// BlockSig es la firma del bloque en hex, la que el recibo ahora transporta.
	BlockSig string `json:"block_signature"`
	// Valid dice si debe verificar.
	Valid bool `json:"valid"`
	// Reason nombra el motivo del rechazo cuando Valid es false.
	Reason string `json:"reason,omitempty"`
	// DeclaredTime y ProvableTime son lo que el verificador debe extraer.
	DeclaredTime string `json:"declared_time"`
	ProvableTime string `json:"provable_time,omitempty"`
	BlockIndex   uint64 `json:"block_index"`
}

type vectorPolicy struct {
	Origin    string            `json:"origin"`
	LogKey    string            `json:"log_key"`
	SignerKey string            `json:"signer_key"`
	Witnesses map[string]string `json:"witnesses"`
	Quorum    int               `json:"quorum"`
}

// TestExportReceiptVectors escribe testdata/vectors/receipt/.
func TestExportReceiptVectors(t *testing.T) {
	dir := filepath.Join("..", "..", "testdata", "vectors", "receipt")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}

	sc := newScene(t, 1)
	r, err := sc.issue(t, "María Pérez (cédula 1712345678)", 2)
	if err != nil {
		t.Fatal(err)
	}
	pol := sc.policy()
	data, err := Format(r, pol)
	if err != nil {
		t.Fatal(err)
	}
	leafData, err := r.LeafData()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.DeclaredTime(); err != nil {
		t.Fatal(err)
	}
	provable, hasProvable, err := r.ProvableTime(pol)
	if err != nil {
		t.Fatal(err)
	}
	if !hasProvable {
		t.Fatal("el vector válido debe tener tiempo demostrable")
	}

	exported := vectorPolicy{
		Origin:    pol.Origin,
		LogKey:    hex.EncodeToString(pol.LogKey),
		SignerKey: hex.EncodeToString(pol.SignerKey),
		Witnesses: map[string]string{},
		Quorum:    pol.Quorum,
	}
	for name, pub := range pol.Witnesses {
		exported.Witnesses[name] = hex.EncodeToString(pub)
	}

	valid := vectorFile{
		Name:         "valido-1-cosignature",
		Description:  "Recibo correcto con una cosignature de un testigo aceptado. Debe verificar.",
		Receipt:      string(data),
		Policy:       exported,
		LeafData:     hex.EncodeToString(leafData),
		LeafRule:     ledger.LeafRule,
		BlockSig:     hex.EncodeToString(r.BlockSig),
		Valid:        true,
		DeclaredTime: r.Header.Timestamp,
		ProvableTime: provable.UTC().Format(timeLayout),
		BlockIndex:   r.Proof.Index,
	}

	// Caso 2: encabezado retocado. La prueba sigue siendo impecable; lo que
	// falla es que el texto visible ya no dice lo que dicen los bytes.
	altered := valid
	altered.Name = "alterado-encabezado"
	altered.Description = "El mismo recibo con el tenant cambiado EN EL TEXTO. La prueba verifica, pero el encabezado ya no se deriva de ella: debe rechazarse."
	altered.Receipt = strings.Replace(valid.Receipt, "emisor (tenant)   : "+testTenant,
		"emisor (tenant)   : 9999999999001", 1)
	altered.Valid = false
	altered.Reason = "header_mismatch"
	if altered.Receipt == valid.Receipt {
		t.Fatal("la alteración no se aplicó: el vector no probaría nada")
	}

	// Caso 3: la cosignature es de una clave que la política NO acepta.
	untrusted := valid
	untrusted.Name = "cosignature-no-confiable"
	untrusted.Description = "El mismo recibo verificado con una política que acepta a OTRO testigo, que no cosignó. La firma del log verifica, pero ningún testigo aceptado respalda la nota: quórum no alcanzado, debe rechazarse."
	untrusted.Valid = false
	untrusted.Reason = "untrusted_cosignature"
	// Desde ADR-018 no existe la política sin testigos: la del vector acepta a un
	// testigo que NO cosignó, y el motivo del rechazo es el quórum.
	untrusted.Policy = vectorPolicy{
		Origin: exported.Origin, LogKey: exported.LogKey, SignerKey: exported.SignerKey,
		Witnesses: map[string]string{"otro.example/w9": hex.EncodeToString(key(99).Public().(ed25519.PublicKey))},
		Quorum:    1,
	}
	untrusted.ProvableTime = ""

	for _, v := range []vectorFile{valid, altered, untrusted} {
		raw, err := json.MarshalIndent(v, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		raw = append(raw, '\n')
		path := filepath.Join(dir, v.Name+".json")
		if err := os.WriteFile(path, raw, 0o644); err != nil {
			t.Fatal(err)
		}
	}

	// Y se comprueba aquí mismo que los tres vectores dicen la verdad, para que
	// no se exporte nunca un vector que el propio Go no respalda.
	assertVector(t, valid)
	assertVector(t, altered)
	assertVector(t, untrusted)

	// D.6: tamaños 1, 2, 4, 8 y 9 (índices 0 y último), y el destinatario que
	// imita una línea de firma. Todos válidos; todos pasan también por el
	// diferencial Go↔TS.
	for _, n := range []int{1, 2, 4, 8, 9} {
		for _, idx := range []int{0, n - 1} {
			sc := newSceneN(t, 1, n)
			exportValid(t, dir, sc, fmt.Sprintf("valido-n%d-i%d", n, idx), fmt.Sprintf("log de %d bloques, recibo del bloque %d", n, idx),
				"María Pérez (cédula 1712345678)", uint64(idx))
			if n == 1 {
				break // índice 0 y último coinciden
			}
		}
	}
	// El recibo YA EMITIDO: header con fracción de segundo, como los que la CLI
	// produjo hasta ADR-019. Los tres verificadores tienen que aceptarlo, porque la
	// parte B del ADR hace que los tres impriman el literal del header.
	func() {
		fraccionEnBloque = "2026-09-06T14:30:00.123456789Z"
		defer func() { fraccionEnBloque = "" }()
		exportValid(t, dir, newSceneN(t, 1, 5), "valido-timestamp-con-fraccion",
			"header con fracción de segundo, como los recibos emitidos antes de ADR-019: el texto lleva el literal del header y los tres verificadores lo aceptan",
			"María Pérez (cédula 1712345678)", 0)
	}()

	exportDuplicateCosignature(t, dir)
	exportTwoCosignaturesSameWitness(t, dir)

	// La nota con la firma ML-DSA-44 del propio log, como la emite la CLI (ADR-007).
	// Los verificadores no la comprueban —WebCrypto no tiene ML-DSA— pero la página
	// tiene que reconocerla como del log y no listarla como "clave que no conoces".
	seed := make([]byte, checkpoint.MLDSASeedSize)
	for i := range seed {
		seed[i] = byte(200 + i)
	}
	mldsa, err := checkpoint.NewMLDSASigner(testOrigin, seed)
	if err != nil {
		t.Fatal(err)
	}
	exportValid(t, dir, newSceneConFirmas(t, 1, 5, mldsa), "valido-firma-mldsa-del-log",
		"la nota trae además la firma ML-DSA-44 del log (ADR-007): se ignora al verificar y la página la reconoce como del log",
		"María Pérez (cédula 1712345678)", 2)

	sc2 := newScene(t, 1)
	exportValid(t, dir, sc2, "valido-destinatario-imita-firma",
		"el destinatario es un texto con la forma de una línea de firma; tiene que viajar como nombre y nada más",
		"— 1790012345001 AAAA", 2)
}

// exportDuplicateCosignature es el hallazgo ALTO #1 de la tercera auditoría como
// vector compartido (ADR-018 C). Un solo testigo cosigna; el emisor duplica su
// línea en la nota y VUELVE A FIRMAR el recibo, así que la firma del emisor verifica
// y lo único que queda por decidir es cuántas veces cuenta ese testigo. La política
// exige dos testigos distintos: tiene que rechazarse en los tres verificadores.
func exportDuplicateCosignature(t *testing.T, dir string) {
	t.Helper()
	sc := newScene(t, 1)
	pol1 := sc.policy()
	r, err := sc.issue(t, "María Pérez (cédula 1712345678)", 2)
	if err != nil {
		t.Fatal(err)
	}
	const w1 = "witness.example/w1"
	var line string
	for _, l := range strings.Split(string(r.Proof.CheckpointNote), "\n") {
		if strings.HasPrefix(l, "— "+w1+" ") {
			line = l
		}
	}
	if line == "" {
		t.Fatal("la nota no trae la línea del testigo: el vector no probaría nada")
	}
	r.Proof.CheckpointNote = append(append([]byte{}, r.Proof.CheckpointNote...), []byte(line+"\n")...)
	if err := Sign(r, pol1, sc.tenantPriv); err != nil {
		t.Fatal(err)
	}
	data, err := Format(r, pol1)
	if err != nil {
		t.Fatal(err)
	}
	leafData, err := r.LeafData()
	if err != nil {
		t.Fatal(err)
	}
	w2 := key(91).Public().(ed25519.PublicKey)
	v := vectorFile{
		Name: "invalido-cosignature-duplicada",
		Description: "Un solo testigo cosigna y su línea aparece DOS veces; el emisor re-firmó el recibo. " +
			"La política exige 2 de 2 testigos: un testigo cuenta una vez (PROTOCOL.md §3.3). Debe rechazarse.",
		Receipt: string(data),
		Policy: vectorPolicy{
			Origin: pol1.Origin, LogKey: hex.EncodeToString(pol1.LogKey), SignerKey: hex.EncodeToString(pol1.SignerKey),
			Witnesses: map[string]string{w1: hex.EncodeToString(sc.wits[w1]), "witness.example/w2": hex.EncodeToString(w2)},
			Quorum:    2,
		},
		LeafData: hex.EncodeToString(leafData), LeafRule: ledger.LeafRule, BlockSig: hex.EncodeToString(r.BlockSig),
		Valid: false, Reason: "duplicate_cosignature",
		DeclaredTime: r.Header.Timestamp, BlockIndex: 2,
	}
	raw, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, v.Name+".json"), append(raw, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	assertVector(t, v)
	// Y la misma nota con la política 1-de-1 SÍ verifica: lo que se rechaza es el
	// quórum inflado, no la línea repetida en sí.
	if _, err := r.Verify(pol1); err != nil {
		t.Fatalf("con la política 1-de-1 la nota con la línea repetida debía verificar: %v", err)
	}
}

// exportTwoCosignaturesSameWitness es el hallazgo BAJO #6 de la tercera auditoría
// (ADR-018 C, E.5). El mismo testigo cosigna el mismo checkpoint dos veces, en
// instantes distintos, y la línea TARDÍA va primero. Vale la más temprana: el orden
// de las líneas lo elige el emisor y no puede decidir la fecha. Antes Go se quedaba
// con la primera línea —la tardía— y TS con la más temprana, y un verificador
// aceptaba lo que el otro rechazaba.
func exportTwoCosignaturesSameWitness(t *testing.T, dir string) {
	t.Helper()
	sc := newScene(t, 1)
	pol := sc.policy()
	r, err := sc.issue(t, "María Pérez (cédula 1712345678)", 2)
	if err != nil {
		t.Fatal(err)
	}
	const w1 = "witness.example/w1"
	temprana := sc.provable
	tardia := testBase.Add(5 * time.Hour)

	var sinTestigo, lineaTemprana []string
	for _, l := range strings.Split(string(r.Proof.CheckpointNote), "\n") {
		if strings.HasPrefix(l, "— "+w1+" ") {
			lineaTemprana = append(lineaTemprana, l)
			continue
		}
		sinTestigo = append(sinTestigo, l)
	}
	if len(lineaTemprana) != 1 {
		t.Fatalf("la escena debía traer una línea de %s", w1)
	}
	w, err := witness.New(w1, key(90), func() time.Time { return tardia })
	if err != nil {
		t.Fatal(err)
	}
	if err := w.AddLog(testOrigin, sc.logPub); err != nil {
		t.Fatal(err)
	}
	cosignada, err := w.Cosign([]byte(strings.Join(sinTestigo, "\n")), nil)
	if err != nil {
		t.Fatal(err)
	}
	var lineaTardia string
	for _, l := range strings.Split(string(cosignada), "\n") {
		if strings.HasPrefix(l, "— "+w1+" ") {
			lineaTardia = l
		}
	}
	if lineaTardia == "" || lineaTardia == lineaTemprana[0] {
		t.Fatal("la segunda cosignature no se obtuvo o es idéntica: el vector no probaría nada")
	}
	// Nota: firma del log, línea TARDÍA, línea temprana.
	body := strings.TrimSuffix(string(r.Proof.CheckpointNote), "\n")
	body = strings.Replace(body, lineaTemprana[0], lineaTardia+"\n"+lineaTemprana[0], 1)
	r.Proof.CheckpointNote = []byte(body + "\n")
	if err := Sign(r, pol, sc.tenantPriv); err != nil {
		t.Fatal(err)
	}
	data, err := Format(r, pol)
	if err != nil {
		t.Fatal(err)
	}
	provable, ok, err := r.ProvableTime(pol)
	if err != nil || !ok {
		t.Fatalf("tiempo demostrable: %v", err)
	}
	if !provable.Equal(temprana) {
		t.Fatalf("tiempo demostrable = %s, want la cosignature más temprana %s", provable, temprana)
	}
	leafData, err := r.LeafData()
	if err != nil {
		t.Fatal(err)
	}
	v := vectorFile{
		Name: "valido-dos-cosignatures-mismo-testigo",
		Description: "El mismo testigo cosigna dos veces, la línea tardía primero. Un testigo cuenta una vez " +
			"y vale su cosignature más temprana (PROTOCOL.md §3.3). Debe verificar con el tiempo temprano.",
		Receipt: string(data),
		Policy: vectorPolicy{
			Origin: pol.Origin, LogKey: hex.EncodeToString(pol.LogKey), SignerKey: hex.EncodeToString(pol.SignerKey),
			Witnesses: map[string]string{w1: hex.EncodeToString(sc.wits[w1])}, Quorum: 1,
		},
		LeafData: hex.EncodeToString(leafData), LeafRule: ledger.LeafRule, BlockSig: hex.EncodeToString(r.BlockSig),
		Valid: true, DeclaredTime: r.Header.Timestamp,
		ProvableTime: temprana.UTC().Format(timeLayout), BlockIndex: 2,
	}
	raw, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, v.Name+".json"), append(raw, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	assertVector(t, v)
}

// exportValid emite, exporta y comprueba un vector válido.
func exportValid(t *testing.T, dir string, sc *scene, name, desc, recipient string, idx uint64) {
	t.Helper()
	r, err := sc.issue(t, recipient, idx)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	pol := sc.policy()
	data, err := Format(r, pol)
	if err != nil {
		t.Fatal(err)
	}
	leafData, err := r.LeafData()
	if err != nil {
		t.Fatal(err)
	}
	provable, _, _ := r.ProvableTime(pol)
	exported := vectorPolicy{
		Origin: pol.Origin, LogKey: hex.EncodeToString(pol.LogKey),
		SignerKey: hex.EncodeToString(pol.SignerKey), Witnesses: map[string]string{}, Quorum: pol.Quorum,
	}
	for wn, pub := range pol.Witnesses {
		exported.Witnesses[wn] = hex.EncodeToString(pub)
	}
	v := vectorFile{
		Name: name, Description: desc, Receipt: string(data), Policy: exported,
		LeafData: hex.EncodeToString(leafData), LeafRule: ledger.LeafRule,
		BlockSig: hex.EncodeToString(r.BlockSig), Valid: true,
		DeclaredTime: r.Header.Timestamp, ProvableTime: provable.UTC().Format(timeLayout),
		BlockIndex: idx,
	}
	raw, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name+".json"), append(raw, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	assertVector(t, v)
}

// assertVector comprueba que el vector se comporte como declara.
func assertVector(t *testing.T, v vectorFile) {
	t.Helper()
	pol := policyFromVector(t, v.Policy)
	parsed, err := Parse([]byte(v.Receipt), pol)
	if v.Valid {
		if err != nil {
			t.Fatalf("%s: debía verificar y no lo hace: %v", v.Name, err)
		}
		if _, err := parsed.Verify(pol); err != nil {
			t.Fatalf("%s: Verify falló: %v", v.Name, err)
		}
		return
	}
	if err == nil {
		if _, err := parsed.Verify(pol); err == nil {
			t.Fatalf("%s: debía rechazarse y verificó", v.Name)
		}
	}
}

// policyFromVector reconstruye la política desde su forma exportada, que es la
// misma que leerá el verificador de TypeScript.
func policyFromVector(t *testing.T, v vectorPolicy) proof.Policy {
	t.Helper()
	logKey, err := hex.DecodeString(v.LogKey)
	if err != nil {
		t.Fatal(err)
	}
	signerKey, err := hex.DecodeString(v.SignerKey)
	if err != nil {
		t.Fatal(err)
	}
	pol := proof.Policy{
		Origin:    v.Origin,
		LogKey:    ed25519.PublicKey(logKey),
		SignerKey: ed25519.PublicKey(signerKey),
		Quorum:    v.Quorum,
		Witnesses: map[string]ed25519.PublicKey{},
	}
	for name, hexKey := range v.Witnesses {
		raw, err := hex.DecodeString(hexKey)
		if err != nil {
			t.Fatal(err)
		}
		pol.Witnesses[name] = ed25519.PublicKey(raw)
	}
	return pol
}
