package receipt

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/nucleoledger/nucleo/internal/proof"
	"github.com/nucleoledger/nucleo/internal/witness"
)

// SEGUNDO CATÁLOGO DEL DIFERENCIAL: mutaciones RE-FIRMADAS por el emisor (ADR-018 E).
//
// El primer catálogo muta los bytes del recibo y no vuelve a firmarlo, así que
// cualquier cambio en la nota rompe la firma del emisor en los dos verificadores
// y el veredicto coincide por la razón equivocada. La tercera auditoría encontró
// sus dos divergencias —la cosignature duplicada y las dos cosignatures del mismo
// testigo— justo ahí: en recibos que el emisor había vuelto a firmar. Este catálogo
// es ese atacante: toca las líneas de firma de la nota, recompone el recibo y lo
// firma con la clave del emisor, de modo que lo único que decide el veredicto es
// cómo lee cada verificador el bloque de firmas (PROTOCOL.md §3.3).

// refirmar sustituye la nota del recibo por nota y vuelve a firmarlo con la clave
// del emisor. Trabaja sobre los BYTES, como un atacante, y no con Format: Format
// deriva el texto verificando la nota, y una nota rota no se podría ni firmar. El
// texto legible se conserva, así que si una mutación cambia el tiempo demostrable,
// el recibo lo delatará por el texto en los dos lados por igual.
func refirmar(t *testing.T, recibo, tenant string, priv ed25519.PrivateKey, nota string) string {
	t.Helper()
	sep := strings.Index(recibo, separator+"\n")
	if sep < 0 {
		t.Fatal("recibo sin separador")
	}
	prefijo := ReceiptSigPrefix + tenant + " "
	ini := strings.Index(recibo[sep:], "\n"+prefijo)
	if ini < 0 {
		t.Fatal("recibo sin línea de firma del emisor")
	}
	ini += sep + 1
	fin := ini + strings.Index(recibo[ini:], "\n") + 1
	sinFirma := recibo[:ini] + recibo[fin:]

	tp := strings.Index(sinFirma, proof.Magic+"\n")
	if tp < 0 {
		t.Fatal("recibo sin tlog-proof")
	}
	corte := tp + strings.Index(sinFirma[tp:], "\n\n") + 2
	sinFirma = sinFirma[:corte] + nota

	digest := sha256.Sum256([]byte(sinFirma))
	firma := prefijo + base64.StdEncoding.EncodeToString(ed25519.Sign(priv, digest[:])) + "\n"
	return sinFirma[:ini] + firma + sinFirma[ini:]
}

// escenaRefirmada es un recibo de partida con todo lo que el atacante-emisor tiene.
type escenaRefirmada struct {
	nombre  string
	recibo  string
	nota    string
	priv    ed25519.PrivateKey
	pol     proof.Policy
	wPriv   map[string]ed25519.PrivateKey
	logPub  ed25519.PublicKey
	origin  string
	testigo string
}

func nuevaEscenaRefirmada(t *testing.T, nombre string, testigos int) escenaRefirmada {
	t.Helper()
	sc := newScene(t, testigos)
	r, err := sc.issue(t, "María Pérez (cédula 1712345678)", 2)
	if err != nil {
		t.Fatal(err)
	}
	pol := sc.policy()
	data, err := Format(r, pol)
	if err != nil {
		t.Fatal(err)
	}
	w := map[string]ed25519.PrivateKey{}
	for i := 0; i < testigos; i++ {
		w[fmt.Sprintf("witness.example/w%d", i+1)] = key(byte(90 + i))
	}
	return escenaRefirmada{nombre: nombre, recibo: string(data), nota: string(r.Proof.CheckpointNote),
		priv: sc.tenantPriv, pol: pol, wPriv: w, logPub: sc.logPub, origin: testOrigin, testigo: "witness.example/w1"}
}

// mutacionesDeNota devuelve las notas mutadas, por nombre. Cada una ataca una regla
// de PROTOCOL.md §3.3 o una de las divergencias de la tercera auditoría.
func mutacionesDeNota(t *testing.T, e escenaRefirmada) [][2]string {
	t.Helper()
	cut := strings.LastIndex(e.nota, "\n\n")
	cuerpo, bloque := e.nota[:cut+2], strings.TrimSuffix(e.nota[cut+2:], "\n")
	firmas := strings.Split(bloque, "\n")
	nota := func(ls []string) string { return cuerpo + strings.Join(ls, "\n") + "\n" }
	copia := func() []string { return append([]string{}, firmas...) }
	var out [][2]string
	add := func(n, v string) { out = append(out, [2]string{n, v}) }

	// blob de una línea, y línea con blob sustituido.
	blobDe := func(l string) []byte {
		b, err := base64.StdEncoding.DecodeString(l[strings.LastIndex(l, " ")+1:])
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	conBlob := func(l string, b []byte) string {
		return l[:strings.LastIndex(l, " ")+1] + base64.StdEncoding.EncodeToString(b)
	}
	desconocida := "— otro.example/w9 " + base64.StdEncoding.EncodeToString(append([]byte{1, 2, 3, 4}, make([]byte, 72)...))

	add("intacto re-firmado", e.nota)
	for i, l := range firmas {
		et := fmt.Sprintf("firma %d (%.28s)", i, l)
		d := copia()
		add("duplica "+et, nota(append(d[:i+1:i+1], append([]string{l}, d[i+1:]...)...)))
		q := copia()
		add("quita "+et, nota(append(q[:i:i], q[i+1:]...)))
		b := blobDe(l)
		b[len(b)-1] ^= 0xff
		add("añade copia basura de "+et, nota(append(copia(), conBlob(l, b))))
		add("añade copia basura DELANTE de "+et, nota(append([]string{conBlob(l, b)}, copia()...)))
		m := copia()
		m = append(append(m[:i:i], m[i+1:]...), l)
		add("mueve al final "+et, nota(m))
		add("espacio al final de "+et, nota(append(copia()[:i:i], append([]string{l + " "}, firmas[i+1:]...)...)))
		add("CR al final de "+et, nota(append(copia()[:i:i], append([]string{l + "\r"}, firmas[i+1:]...)...)))
		add("dos espacios tras el nombre en "+et, nota(append(copia()[:i:i], append([]string{strings.Replace(l, " ", "  ", 2)[:len("— ")] + strings.Replace(l[len("— "):], " ", "  ", 1)}, firmas[i+1:]...)...)))
		sinPad := strings.TrimRight(l, "=")
		if sinPad != l {
			add("base64 sin relleno en "+et, nota(append(copia()[:i:i], append([]string{sinPad}, firmas[i+1:]...)...)))
		}
		// Base64 NO canónico: mismos bytes, bits de relleno distintos de cero.
		if strings.HasSuffix(l, "==") {
			enc := l[strings.LastIndex(l, " ")+1:]
			alfabeto := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
			ult := strings.IndexByte(alfabeto, enc[len(enc)-3])
			if ult >= 0 && ult&0x0f == 0 {
				nc := enc[:len(enc)-3] + string(alfabeto[ult|0x01]) + "=="
				add("base64 no canónico en "+et, nota(append(copia()[:i:i], append([]string{l[:strings.LastIndex(l, " ")+1] + nc}, firmas[i+1:]...)...)))
			}
		}
	}
	rev := copia()
	for i, j := 0, len(rev)-1; i < j; i, j = i+1, j-1 {
		rev[i], rev[j] = rev[j], rev[i]
	}
	add("invierte el orden de las firmas", nota(rev))
	add("injerta firma de clave desconocida", nota(append(copia(), desconocida)))
	add("injerta línea sin prefijo", nota(append(copia(), "hola")))
	add("injerta línea vacía entre firmas", nota(append(copia()[:1:1], append([]string{""}, firmas[1:]...)...)))
	add("injerta '—' sin espacio", nota(append(copia(), "—otro.example/w9 "+desconocida[len("— otro.example/w9 "):])))
	add("injerta nombre con +", nota(append(copia(), strings.Replace(desconocida, "otro.example/w9", "otro+w9", 1))))
	add("injerta nombre con NBSP", nota(append(copia(), strings.Replace(desconocida, "otro.example/w9", "otro\u00a0w9", 1))))
	add("injerta nombre con U+2028", nota(append(copia(), strings.Replace(desconocida, "otro.example/w9", "otro\u2028w9", 1))))
	add("injerta nombre con U+3000", nota(append(copia(), strings.Replace(desconocida, "otro.example/w9", "otro\u3000w9", 1))))
	add("injerta nombre con U+FEFF (no es espacio para Go)", nota(append(copia(), strings.Replace(desconocida, "otro.example/w9", "otro\ufeffw9", 1))))
	add("injerta nombre con U+0085", nota(append(copia(), strings.Replace(desconocida, "otro.example/w9", "otro\u0085w9", 1))))
	add("injerta nombre con carácter de control", nota(append(copia(), strings.Replace(desconocida, "otro.example/w9", "otro\x01w9", 1))))
	add("injerta nombre vacío", nota(append(copia(), "—  "+desconocida[len("— otro.example/w9 "):])))
	add("injerta blob de 4 bytes", nota(append(copia(), "— otro.example/w9 AQIDBA==")))
	add("injerta firma sin blob", nota(append(copia(), "— otro.example/w9")))
	add("injerta firma con blob vacío", nota(append(copia(), "— otro.example/w9 ")))
	muchas := func(n int) []string {
		ls := copia()
		for k := 0; k < n; k++ {
			ls = append(ls, strings.Replace(desconocida, "w9", fmt.Sprintf("w%d", 100+k), 1))
		}
		return ls
	}
	add(fmt.Sprintf("hasta 100 líneas (%d desconocidas)", 100-len(firmas)), nota(muchas(100-len(firmas))))
	add(fmt.Sprintf("101 líneas (%d desconocidas)", 101-len(firmas)), nota(muchas(101-len(firmas))))
	add("línea de extensión en el cuerpo", strings.Replace(e.nota, "\n\n", "\nextension\n\n", 1))
	add("bloque de firmas sin salto final", strings.TrimSuffix(e.nota, "\n"))

	// Cosignatures del testigo conocido con otras formas.
	var linea string
	for _, l := range firmas {
		if strings.HasPrefix(l, "— "+e.testigo+" ") {
			linea = l
		}
	}
	if linea != "" {
		b := blobDe(linea)
		add("cosignature del testigo con 75 bytes", nota(append(copia(), conBlob(linea, b[:len(b)-1]))))
		add("cosignature del testigo con 77 bytes", nota(append(copia(), conBlob(linea, append(append([]byte{}, b...), 0)))))
		for _, desfase := range []time.Duration{-10 * time.Minute, 5 * time.Hour} {
			w, err := witness.New(e.testigo, e.wPriv[e.testigo], func() time.Time { return testBase.Add(30*time.Minute + desfase) })
			if err != nil {
				t.Fatal(err)
			}
			if err := w.AddLog(e.origin, e.logPub); err != nil {
				t.Fatal(err)
			}
			var sinTestigo []string
			for _, l := range strings.Split(e.nota, "\n") {
				if l != linea {
					sinTestigo = append(sinTestigo, l)
				}
			}
			otra, err := w.Cosign([]byte(strings.Join(sinTestigo, "\n")), nil)
			if err != nil {
				t.Fatal(err)
			}
			var lineaOtra string
			for _, l := range strings.Split(string(otra), "\n") {
				if strings.HasPrefix(l, "— "+e.testigo+" ") {
					lineaOtra = l
				}
			}
			add(fmt.Sprintf("segunda cosignature del mismo testigo (%+v) delante", desfase), nota(append([]string{lineaOtra}, copia()...)))
			add(fmt.Sprintf("segunda cosignature del mismo testigo (%+v) detrás", desfase), nota(append(copia(), lineaOtra)))
		}
	}
	return out
}

// catalogoRefirmado genera el segundo catálogo con los veredictos de Go.
func catalogoRefirmado(t *testing.T) []mutacionConPolitica {
	t.Helper()
	var out []mutacionConPolitica
	for _, e := range []escenaRefirmada{
		nuevaEscenaRefirmada(t, "refirmado/1-testigo", 1),
		nuevaEscenaRefirmada(t, "refirmado/2-testigos", 2),
	} {
		politicas := map[string]proof.Policy{"escena": e.pol}
		if len(e.pol.Witnesses) == 1 {
			// La del ataque #1: exige un segundo testigo que nunca cosignó.
			p2 := e.pol
			p2.Witnesses = map[string]ed25519.PublicKey{e.testigo: e.pol.Witnesses[e.testigo],
				"witness.example/w2": key(91).Public().(ed25519.PublicKey)}
			p2.Quorum = 2
			politicas["2-de-2 con un testigo ausente"] = p2
		}
		for pn, pol := range politicas {
			polJSON := map[string]any{"origin": pol.Origin, "logKey": hex.EncodeToString(pol.LogKey),
				"signerKey": hex.EncodeToString(pol.SignerKey), "quorum": pol.Quorum}
			ws := map[string]string{}
			for n, k := range pol.Witnesses {
				ws[n] = hex.EncodeToString(k)
			}
			polJSON["witnesses"] = ws
			for _, m := range mutacionesDeNota(t, e) {
				rec := refirmar(t, e.recibo, testTenant, e.priv, m[1])
				c := mutacion{Nombre: pn + ": " + m[0], Receipt: rec}
				r, err := Parse([]byte(rec), pol)
				if err == nil {
					_, err = r.Verify(pol)
				}
				if err != nil {
					c.GoErr = err.Error()
				} else {
					c.GoValid = true
				}
				out = append(out, mutacionConPolitica{mutacion: c, Vector: e.nombre, Policy: polJSON})
			}
		}
	}
	// El intacto re-firmado con la política de la escena tiene que verificar: si no,
	// refirmar no es un emisor y el catálogo entero estaría midiendo otra cosa.
	for _, c := range out {
		if strings.HasSuffix(c.Nombre, "escena: intacto re-firmado") && !c.GoValid {
			t.Fatalf("%s: el recibo re-firmado sin mutar no verifica: %s", c.Vector, c.GoErr)
		}
	}
	return out
}
