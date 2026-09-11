package receipt

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nucleoledger/nucleo/internal/checkpoint"
	"github.com/nucleoledger/nucleo/internal/ledger"
	"github.com/nucleoledger/nucleo/internal/proof"
	"github.com/nucleoledger/nucleo/internal/store"
	"github.com/nucleoledger/nucleo/internal/witness"
)

const (
	testOrigin = "nucleoledger.com/recibos"
	testTenant = "1790012345001"
)

var testBase = time.Date(2026, 9, 6, 14, 30, 0, 0, time.UTC)

func key(b byte) ed25519.PrivateKey {
	s := make([]byte, ed25519.SeedSize)
	for i := range s {
		s[i] = b + byte(i)
	}
	return ed25519.NewKeyFromSeed(s)
}

// scene sella una historia y la cosigna con los testigos pedidos.
type scene struct {
	store    *store.Store
	logPub   ed25519.PublicKey
	wits     map[string]ed25519.PublicKey
	provable time.Time
}

func newScene(t *testing.T, cosigners int) *scene {
	t.Helper()
	s, _, err := store.Open(filepath.Join(t.TempDir(), "nucleo.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })

	tenantPriv := key(1)
	tenantPub := tenantPriv.Public().(ed25519.PublicKey)
	var prev *ledger.Block
	for i := 0; i < 5; i++ {
		h, err := ledger.NewHeader(prev, testTenant, "sri.factura.v1",
			[]byte(fmt.Sprintf(`{"factura":%d,"importe":"1250.00"}`, i)), "blob://x",
			tenantPub, testBase.Add(time.Duration(i)*time.Minute))
		if err != nil {
			t.Fatal(err)
		}
		b, err := ledger.Seal(h, tenantPriv)
		if err != nil {
			t.Fatal(err)
		}
		if err := s.AppendBlock(b); err != nil {
			t.Fatal(err)
		}
		prev = b
	}

	logPriv := key(50)
	logSigner, err := checkpoint.NewSigner(testOrigin, logPriv)
	if err != nil {
		t.Fatal(err)
	}
	root, err := s.Root()
	if err != nil {
		t.Fatal(err)
	}
	msg, err := checkpoint.Sign(checkpoint.Checkpoint{
		Origin: testOrigin, Size: 5, RootHash: root,
	}, logSigner)
	if err != nil {
		t.Fatal(err)
	}

	sc := &scene{store: s, logPub: logPriv.Public().(ed25519.PublicKey), wits: map[string]ed25519.PublicKey{}}
	// Los testigos cosignan en instantes DISTINTOS y en orden decreciente, para
	// que el mínimo no sea trivialmente el primero que se procesa.
	for i := 0; i < cosigners; i++ {
		name := fmt.Sprintf("witness.example/w%d", i+1)
		priv := key(byte(90 + i))
		at := testBase.Add(time.Duration(30-10*i) * time.Minute)
		w, err := witness.New(name, priv, func() time.Time { return at })
		if err != nil {
			t.Fatal(err)
		}
		if err := w.AddLog(testOrigin, sc.logPub); err != nil {
			t.Fatal(err)
		}
		msg, err = w.Cosign(msg, nil)
		if err != nil {
			t.Fatal(err)
		}
		sc.wits[name] = priv.Public().(ed25519.PublicKey)
		if sc.provable.IsZero() || at.Before(sc.provable) {
			sc.provable = at
		}
	}
	if err := s.PutCheckpoint(msg); err != nil {
		t.Fatal(err)
	}
	return sc
}

func (sc *scene) policy() proof.Policy {
	return proof.Policy{
		Origin: testOrigin, LogKey: sc.logPub,
		Witnesses: sc.wits, Quorum: len(sc.wits),
	}
}

// TestReceiptShowsBothClocks es el corazón de PROTOCOL §4: los dos relojes,
// etiquetados por separado y nunca confundidos.
func TestReceiptShowsBothClocks(t *testing.T) {
	sc := newScene(t, 3)
	r, err := Issue(sc.store, "María Pérez (cédula 1712345678)", 2)
	if err != nil {
		t.Fatal(err)
	}

	declared, err := r.DeclaredTime()
	if err != nil {
		t.Fatal(err)
	}
	if want := testBase.Add(2 * time.Minute); !declared.Equal(want) {
		t.Errorf("tiempo declarado = %v, want %v", declared, want)
	}

	// El demostrable es el MÍNIMO de los tres, no el primero ni el último.
	provable, ok, err := r.ProvableTime(sc.policy())
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("no hay tiempo demostrable con tres cosignatures")
	}
	if !provable.Equal(sc.provable) {
		t.Errorf("tiempo demostrable = %v, want %v (el mínimo de las tres)", provable, sc.provable)
	}
	if !provable.Before(declared) && !provable.After(declared) {
		t.Error("los dos relojes coinciden: el test no distingue nada")
	}

	data, err := Format(r, sc.policy())
	if err != nil {
		t.Fatal(err)
	}
	text := Text(data)
	if !strings.Contains(text, "TIEMPO DECLARADO  : "+declared.UTC().Format(timeLayout)) {
		t.Errorf("el encabezado no muestra el tiempo declarado:\n%s", text)
	}
	if !strings.Contains(text, "TIEMPO DEMOSTRABLE: "+provable.UTC().Format(timeLayout)) {
		t.Errorf("el encabezado no muestra el tiempo demostrable:\n%s", text)
	}
	if !strings.Contains(text, "(declarado por el sistema emisor)") ||
		!strings.Contains(text, "(atestiguado por testigos)") {
		t.Errorf("las etiquetas no distinguen los dos relojes:\n%s", text)
	}

	res, err := r.Verify(sc.policy())
	if err != nil {
		t.Fatalf("el recibo no verifica: %v", err)
	}
	if !res.ProvableTime.Equal(sc.provable) {
		t.Errorf("Verify devolvió %v, want %v", res.ProvableTime, sc.provable)
	}
	if len(res.Cosigners) != 3 {
		t.Errorf("%d cosignatarios, want 3", len(res.Cosigners))
	}
}

// TestReceiptWithoutCosignatures comprueba que la ausencia de tiempo demostrable
// se dice con todas las letras. Callarse y mostrar solo el declarado sería
// presentarlo como prueba, que es justo lo que PROTOCOL.md §4 prohíbe.
func TestReceiptWithoutCosignatures(t *testing.T) {
	sc := newScene(t, 0)
	r, err := Issue(sc.store, "Contraparte S.A.", 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok, err := r.ProvableTime(sc.policy()); err != nil || ok {
		t.Fatalf("hay tiempo demostrable sin ninguna cosignature: %v %v", ok, err)
	}
	data, err := Format(r, sc.policy())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(Text(data), "TIEMPO DEMOSTRABLE: "+NoProvableTime) {
		t.Errorf("no se anuncia la ausencia de tiempo demostrable:\n%s", Text(data))
	}

	// Y sigue verificando: un recibo sin testigos prueba inclusión, no tiempo.
	if _, err := r.Verify(sc.policy()); err != nil {
		t.Errorf("un recibo sin cosignatures debe verificar igual: %v", err)
	}
}

// TestParseRejectsDoctoredText es el rechazo que hace del recibo un documento
// fiable para una persona: si el texto visible dice una cosa y la prueba otra,
// el recibo no se acepta. Un recibo con prueba impecable y texto retocado sería
// un documento engañoso con aspecto de válido.
func TestParseRejectsDoctoredText(t *testing.T) {
	sc := newScene(t, 2)
	r, err := Issue(sc.store, "María Pérez", 3)
	if err != nil {
		t.Fatal(err)
	}
	data, err := Format(r, sc.policy())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Parse(data, sc.policy()); err != nil {
		t.Fatalf("el recibo recién emitido no parsea: %v", err)
	}

	provable, _, _ := r.ProvableTime(sc.policy())
	for _, c := range []struct{ name, from, to string }{
		{"tenant cambiado", testTenant, "9999999999001"},
		{"tipo cambiado", "sri.factura.v1", "sri.nota-credito.v1"},
		{"tiempo declarado adelantado", "TIEMPO DECLARADO  : 2026-09-06T14:33:00Z", "TIEMPO DECLARADO  : 2026-09-06T09:00:00Z"},
		{"tiempo demostrable inventado", "TIEMPO DEMOSTRABLE: " + provable.UTC().Format(timeLayout), "TIEMPO DEMOSTRABLE: 2020-01-01T00:00:00Z"},
		// La advertencia legal viaja en el texto, así que la cubre esta misma
		// regla. No es un detalle de redacción: si se pudiera borrar con un
		// editor, el primer uso comercial la borraría, y el recibo seguiría
		// verificando sin ella. Estas tres filas son lo que lo impide.
		{"advertencia legal borrada", "\nADVERTENCIA LEGAL\nEste recibo es evidencia", "\nEste recibo es evidencia"},
		{"advertencia legal suavizada", "No constituye por sí\nmismo un acto público", "Constituye por sí\nmismo un acto público"},
		{"advertencia legal entera fuera", "\n" + LegalNotice + "\n", "\n"},
	} {
		t.Run(c.name, func(t *testing.T) {
			doctored := strings.Replace(string(data), c.from, c.to, 1)
			if doctored == string(data) {
				t.Fatalf("la sustitución %q no se aplicó: el test no prueba nada", c.from)
			}
			if _, err := Parse([]byte(doctored), sc.policy()); !errors.Is(err, ErrTextMismatch) && !errors.Is(err, ErrFormat) {
				t.Errorf("err = %v, want que el texto retocado se rechace", err)
			}
		})
	}
}

// TestUntrustedCosignatureGivesNoProvableTime es el hallazgo MEDIO de la
// auditoría: una cosignature de una clave que la política NO acepta no aporta
// tiempo demostrable, y no lo aporta ya al calcularlo, no solo al verificar.
//
// Antes el tiempo se sacaba de la FORMA del blob de firma, así que cualquier
// cosa de 72 bytes pegada al final de la nota se convertía en una fecha con
// aspecto de atestiguada. El recibo la imprimía, y solo Verify —si alguien lo
// llamaba— desmentía el papel.
func TestUntrustedCosignatureGivesNoProvableTime(t *testing.T) {
	sc := newScene(t, 2)
	r, err := Issue(sc.store, "Contraparte S.A.", 0)
	if err != nil {
		t.Fatal(err)
	}

	// Política sin ningún testigo aceptado: la nota TRAE dos cosignatures, pero
	// ninguna cuenta.
	none := sc.policy()
	none.Witnesses = nil
	none.Quorum = 0

	if _, ok, err := r.ProvableTime(none); err != nil || ok {
		t.Fatalf("cosignatures no confiables aportaron tiempo: ok=%v err=%v", ok, err)
	}
	data, err := Format(r, none)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(Text(data), "TIEMPO DEMOSTRABLE: "+NoProvableTime) {
		t.Errorf("se imprimió una fecha sin testigo que la respalde:\n%s", Text(data))
	}

	// Política que solo acepta al testigo MÁS TARDÍO: el mínimo cambia, y el
	// encabezado cambia con él.
	narrow := sc.policy()
	narrow.Witnesses = map[string]ed25519.PublicKey{"witness.example/w1": sc.wits["witness.example/w1"]}
	narrow.Quorum = 1
	narrowed, ok, err := r.ProvableTime(narrow)
	if err != nil || !ok {
		t.Fatalf("el testigo aceptado no aportó tiempo: %v %v", ok, err)
	}
	full, _, err := r.ProvableTime(sc.policy())
	if err != nil {
		t.Fatal(err)
	}
	if !narrowed.After(full) {
		t.Errorf("con menos testigos el tiempo demostrable debería ser MAYOR: %v vs %v", narrowed, full)
	}

	// Y un recibo emitido con la política ancha no se acepta al releerlo con la
	// estrecha: enseñar una fecha que quien mira no puede verificar sería peor
	// que rechazar el documento.
	wide, err := Format(r, sc.policy())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Parse(wide, narrow); !errors.Is(err, ErrTextMismatch) {
		t.Errorf("err = %v, want %v", err, ErrTextMismatch)
	}
}

// TestIssueRefusesUnattestedEntry: no se emite recibo de lo que ningún
// checkpoint cubre todavía.
func TestIssueRefusesUnattestedEntry(t *testing.T) {
	sc := newScene(t, 1)
	if _, err := Issue(sc.store, "alguien", 9); !errors.Is(err, ErrNotAttested) {
		t.Errorf("err = %v, want %v", err, ErrNotAttested)
	}
	if _, err := Issue(sc.store, "", 0); !errors.Is(err, ErrFormat) {
		t.Errorf("sin destinatario: err = %v, want %v", err, ErrFormat)
	}
}

// TestRecipientIsNotCoveredBySignatures documenta un LÍMITE real del formato, en
// vez de dejarlo implícito.
//
// El destinatario se elige al emitir el recibo, mucho después de que el bloque
// se sellara, así que no está dentro de nada firmado y no puede estarlo sin
// firmar el recibo entero con otra clave. Cambiarlo produce un recibo dirigido a
// otra persona cuya prueba sigue siendo válida.
//
// Eso no rompe lo que el recibo demuestra —que ESTE contenido estaba en el log
// en ESE momento— pero sí significa que el nombre del destinatario no es prueba
// de nada. Cualquier lectura contraria sería falsa, y por eso hay un test que lo
// dice en voz alta.
func TestRecipientIsNotCoveredBySignatures(t *testing.T) {
	sc := newScene(t, 1)
	r, err := Issue(sc.store, "María Pérez", 1)
	if err != nil {
		t.Fatal(err)
	}
	data, err := Format(r, sc.policy())
	if err != nil {
		t.Fatal(err)
	}

	redirected := strings.Replace(string(data), "María Pérez", "Juan Gómez", 1)
	if redirected == string(data) {
		t.Fatal("la sustitución no se aplicó")
	}
	other, err := Parse([]byte(redirected), sc.policy())
	if err != nil {
		t.Fatalf("cambiar el destinatario NO invalida el recibo, y el test existe para dejarlo escrito: %v", err)
	}
	if other.Recipient != "Juan Gómez" {
		t.Errorf("destinatario = %q, want %q", other.Recipient, "Juan Gómez")
	}
	// Lo que sí se conserva intacto es lo que la prueba demuestra.
	if _, err := other.Verify(sc.policy()); err != nil {
		t.Errorf("la prueba dejó de verificar al cambiar el destinatario: %v", err)
	}
	if other.Header.PayloadHash != r.Header.PayloadHash {
		t.Error("el contenido sellado cambió, que sería otra cosa muy distinta")
	}
}

// TestGoldenHeaderFormat fija el formato del encabezado byte a byte.
//
// Un recibo es un documento que se imprime, se archiva y se compara con otro
// emitido dos años después. Si el formato cambia sin querer, dos recibos del
// mismo hecho dejan de parecerse, y este test es lo que obliga a que el cambio
// sea deliberado.
func TestGoldenHeaderFormat(t *testing.T) {
	sc := newScene(t, 1)
	r, err := Issue(sc.store, "María Pérez (cédula 1712345678)", 2)
	if err != nil {
		t.Fatal(err)
	}
	data, err := Format(r, sc.policy())
	if err != nil {
		t.Fatal(err)
	}

	const want = `nucleo.org/receipt@v1
destinatario      : María Pérez (cédula 1712345678)
emisor (tenant)   : 1790012345001
tipo de registro  : sri.factura.v1
hash del contenido: 5c7d1a10a8e4d0aa5cf8d1d05f3d6d13ca0fd0f2b5d3b8ba50e19e10d0f7a0dd
bloque            : 2

TIEMPO DECLARADO  : 2026-09-06T14:32:00Z  (declarado por el sistema emisor)
TIEMPO DEMOSTRABLE: 2026-09-06T15:00:00Z  (atestiguado por testigos)

ADVERTENCIA LEGAL
Este recibo es evidencia técnica de integridad y tiempo. No constituye por sí
mismo un acto público, una certificación notarial ni un pronunciamiento de
autoridad. Su valor probatorio lo determina un perito o un juez.`

	got := Text(data)
	// El payload_hash depende del contenido del test, así que se compara todo
	// menos esa línea, que se comprueba aparte contra el hash del propio bloque.
	if normalizeHash(got) != normalizeHash(want) {
		t.Errorf("encabezado:\n%s\n\nwant:\n%s", got, want)
	}
	if !strings.Contains(got, "hash del contenido: "+r.Header.PayloadHash) {
		t.Errorf("el encabezado no muestra el payload_hash del bloque")
	}
}

// normalizeHash sustituye el valor del payload_hash por una marca fija.
func normalizeHash(s string) string {
	const prefix = "hash del contenido: "
	i := strings.Index(s, prefix)
	if i < 0 {
		return s
	}
	j := strings.IndexByte(s[i:], '\n')
	if j < 0 {
		return s
	}
	return s[:i+len(prefix)] + "<payload_hash>" + s[i+j:]
}
