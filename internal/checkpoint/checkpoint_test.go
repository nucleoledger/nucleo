package checkpoint

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"golang.org/x/mod/sumdb/note"
)

const testOrigin = "nucleoledger.com/poc"

// testSeed es una semilla fija: los bytes de una nota firmada con ella son
// reproducibles, porque Ed25519 firma de forma determinista.
func testSeed(b byte) []byte {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = b + byte(i)
	}
	return seed
}

func testKeys(t *testing.T, name string, b byte) (note.Signer, note.Verifier, ed25519.PublicKey) {
	t.Helper()
	priv := ed25519.NewKeyFromSeed(testSeed(b))
	pub := priv.Public().(ed25519.PublicKey)
	s, err := NewSigner(name, priv)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	v, err := NewVerifier(name, pub)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	return s, v, pub
}

// rfc6962Root5 es la raíz canónica de RFC 6962 para n = 5, ya verificada en
// testdata/vectors/merkle/rfc6962. Atar el golden a un valor canónico evita que
// el checkpoint dependa de una raíz inventada.
func rfc6962Root5(t *testing.T) []byte {
	t.Helper()
	root, err := hex.DecodeString("4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4")
	if err != nil {
		t.Fatal(err)
	}
	return root
}

// TestGoldenSignedCheckpoint fija los bytes exactos del formato. Si este test
// falla, el formato de nota cambió y deja de ser interoperable con C2SP.
func TestGoldenSignedCheckpoint(t *testing.T) {
	const wantBody = "nucleoledger.com/poc\n5\nTju7H3tHjc/nH7YxYxUZo7yhLJrvyhYSv85ME6hiZNQ=\n"
	const wantNote = wantBody + "\n" +
		"— nucleoledger.com/poc GHVGGDPku5KYEIFSbHQXmHXGyHfsRxPSTPSU5S9SJVW8V+igyeKgSQsz03Hj6//jknrWEKl7GrNCMZ3/eCla7/aSKg8=\n"

	c := Checkpoint{Origin: testOrigin, Size: 5, RootHash: rfc6962Root5(t)}

	body, err := Format(c)
	if err != nil {
		t.Fatalf("Format: %v", err)
	}
	if body != wantBody {
		t.Errorf("cuerpo:\n got %q\nwant %q", body, wantBody)
	}

	signer, _, pub := testKeys(t, testOrigin, 0)
	if got, want := KeyHash(testOrigin, pub), uint32(0x18754618); got != want {
		t.Errorf("KeyHash = %08x, want %08x", got, want)
	}
	if got := signer.KeyHash(); got != KeyHash(testOrigin, pub) {
		t.Errorf("KeyHash local %08x != el de la biblioteca %08x", KeyHash(testOrigin, pub), got)
	}

	msg, err := Sign(c, signer)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if string(msg) != wantNote {
		t.Errorf("nota firmada:\n got %q\nwant %q", msg, wantNote)
	}
	if len(msg) != 187 {
		t.Errorf("tamaño de la nota = %d bytes, want 187", len(msg))
	}
}

// TestFormatParseRoundTrip comprueba Parse(Format(x)) == x en los bordes.
func TestFormatParseRoundTrip(t *testing.T) {
	root := rfc6962Root5(t)
	sizes := []uint64{0, 1, 2, 5, 1023, 1 << 20, 1<<64 - 1}
	for _, size := range sizes {
		in := Checkpoint{Origin: testOrigin, Size: size, RootHash: root}
		text, err := Format(in)
		if err != nil {
			t.Fatalf("Format(size=%d): %v", size, err)
		}
		out, err := Parse(text)
		if err != nil {
			t.Fatalf("Parse(size=%d): %v", size, err)
		}
		if out.Origin != in.Origin || out.Size != in.Size || string(out.RootHash) != string(in.RootHash) {
			t.Errorf("round-trip roto para size=%d: %+v != %+v", size, out, in)
		}
	}
}

// TestParseRejectsMalformed recorre las formas de cuerpo inválido.
func TestParseRejectsMalformed(t *testing.T) {
	valid := "nucleoledger.com/poc\n5\nTju7H3tHjc/nH7YxYxUZo7yhLJrvyhYSv85ME6hiZNQ=\n"
	cases := []struct {
		name string
		text string
	}{
		{"sin salto final", strings.TrimSuffix(valid, "\n")},
		{"cuerpo vacío", ""},
		{"solo dos líneas", "nucleoledger.com/poc\n5\n"},
		{"línea de más", valid + "extra\n"},
		{"línea en blanco de más", valid + "\n"},
		{"origin vacío", "\n5\nTju7H3tHjc/nH7YxYxUZo7yhLJrvyhYSv85ME6hiZNQ=\n"},
		{"origin con espacio al borde", " nucleoledger.com/poc\n5\nTju7H3tHjc/nH7YxYxUZo7yhLJrvyhYSv85ME6hiZNQ=\n"},
		{"tamaño vacío", "nucleoledger.com/poc\n\nTju7H3tHjc/nH7YxYxUZo7yhLJrvyhYSv85ME6hiZNQ=\n"},
		{"tamaño con cero a la izquierda", "nucleoledger.com/poc\n05\nTju7H3tHjc/nH7YxYxUZo7yhLJrvyhYSv85ME6hiZNQ=\n"},
		{"tamaño con signo", "nucleoledger.com/poc\n+5\nTju7H3tHjc/nH7YxYxUZo7yhLJrvyhYSv85ME6hiZNQ=\n"},
		{"tamaño negativo", "nucleoledger.com/poc\n-5\nTju7H3tHjc/nH7YxYxUZo7yhLJrvyhYSv85ME6hiZNQ=\n"},
		{"tamaño no numérico", "nucleoledger.com/poc\ncinco\nTju7H3tHjc/nH7YxYxUZo7yhLJrvyhYSv85ME6hiZNQ=\n"},
		{"tamaño desbordado", "nucleoledger.com/poc\n18446744073709551616\nTju7H3tHjc/nH7YxYxUZo7yhLJrvyhYSv85ME6hiZNQ=\n"},
		{"raíz no base64", "nucleoledger.com/poc\n5\nno-es-base64!!\n"},
		{"raíz en hexadecimal", "nucleoledger.com/poc\n5\n4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4\n"},
		{"raíz corta", "nucleoledger.com/poc\n5\nTju7H3tHjc/nH7YxYxUZo7yhLJrvyhYSv85ME6hiZM=\n"},
		{"raíz vacía", "nucleoledger.com/poc\n5\n\n"},
	}
	for _, c := range cases {
		if _, err := Parse(c.text); err == nil {
			t.Errorf("%s: Parse aceptó un cuerpo inválido", c.name)
		}
	}
}

// TestFormatRejectsInvalidCheckpoint cubre el dominio del serializador.
func TestFormatRejectsInvalidCheckpoint(t *testing.T) {
	root := rfc6962Root5(t)
	cases := []struct {
		name string
		c    Checkpoint
	}{
		{"origin vacío", Checkpoint{Origin: "", Size: 1, RootHash: root}},
		{"origin con salto de línea", Checkpoint{Origin: "a\nb", Size: 1, RootHash: root}},
		{"origin con espacio al borde", Checkpoint{Origin: "poc ", Size: 1, RootHash: root}},
		{"raíz nula", Checkpoint{Origin: testOrigin, Size: 1, RootHash: nil}},
		{"raíz corta", Checkpoint{Origin: testOrigin, Size: 1, RootHash: root[:31]}},
		{"raíz larga", Checkpoint{Origin: testOrigin, Size: 1, RootHash: append(root, 0)}},
	}
	for _, c := range cases {
		if _, err := Format(c.c); err == nil {
			t.Errorf("%s: Format aceptó un checkpoint inválido", c.name)
		}
	}
}

// TestVerifyRejectsTamperedNote altera la nota firmada línea por línea y byte a
// byte: ninguna variante debe verificar.
func TestVerifyRejectsTamperedNote(t *testing.T) {
	signer, verifier, _ := testKeys(t, testOrigin, 0)
	c := Checkpoint{Origin: testOrigin, Size: 5, RootHash: rfc6962Root5(t)}
	msg, err := Sign(c, signer)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := Verify(msg, verifier); err != nil {
		t.Fatalf("Verify rechaza una nota legítima: %v", err)
	}

	lines := strings.Split(string(msg), "\n")
	for i, line := range lines {
		if line == "" {
			continue
		}
		// Alterar el primer carácter de cada línea con contenido.
		mutated := append([]string{}, lines...)
		mutated[i] = "X" + line[1:]
		if _, _, err := Verify([]byte(strings.Join(mutated, "\n")), verifier); err == nil {
			t.Errorf("Verify acepta la nota con la línea %d alterada (%q)", i, line)
		}

		// Eliminar la línea entera.
		removed := append(append([]string{}, lines[:i]...), lines[i+1:]...)
		if _, _, err := Verify([]byte(strings.Join(removed, "\n")), verifier); err == nil {
			t.Errorf("Verify acepta la nota sin la línea %d (%q)", i, line)
		}
	}

	// Una clave distinta no debe verificar la nota.
	_, otherVerifier, _ := testKeys(t, testOrigin, 200)
	if _, _, err := Verify(msg, otherVerifier); err == nil {
		t.Error("Verify acepta la nota con la clave equivocada")
	}
}

// TestVerifyIgnoresUnknownSigner comprueba la regla de notas firmadas que el
// recibo necesita: una firma de clave desconocida no rompe la verificación
// mientras al menos una firma conocida verifique.
func TestVerifyIgnoresUnknownSigner(t *testing.T) {
	logSigner, logVerifier, _ := testKeys(t, testOrigin, 0)
	witnessSigner, _, _ := testKeys(t, "witness.example/w1", 100)
	c := Checkpoint{Origin: testOrigin, Size: 5, RootHash: rfc6962Root5(t)}

	msg, err := Sign(c, logSigner, witnessSigner)
	if err != nil {
		t.Fatal(err)
	}
	got, n, err := Verify(msg, logVerifier)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got.Size != 5 {
		t.Errorf("Size = %d, want 5", got.Size)
	}
	if len(n.Sigs) != 1 || len(n.UnverifiedSigs) != 1 {
		t.Errorf("firmas verificadas = %d, no verificadas = %d; want 1 y 1", len(n.Sigs), len(n.UnverifiedSigs))
	}

	// Sin ninguna clave conocida, note.Open falla: por eso la política de un
	// recibo debe incluir siempre la clave del log.
	if _, _, err := Verify(msg); err == nil {
		t.Error("Verify acepta una nota sin ningún firmante conocido")
	}
}

// TestLogRefusesRollback es la regla de PROTOCOL.md §3: un log nunca firma un
// checkpoint que contradiga a uno que ya firmó.
func TestLogRefusesRollback(t *testing.T) {
	signer, _, _ := testKeys(t, testOrigin, 0)
	root5 := rfc6962Root5(t)
	other := append([]byte(nil), root5...)
	other[0] ^= 0xff

	l, err := NewLog(testOrigin, signer)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := l.Last(); ok {
		t.Error("un log nuevo no debería tener último checkpoint")
	}

	if _, err := l.Sign(Checkpoint{Origin: testOrigin, Size: 5, RootHash: root5}); err != nil {
		t.Fatalf("primer checkpoint rechazado: %v", err)
	}
	last, ok := l.Last()
	if !ok || last.Size != 5 {
		t.Fatalf("Last() = %+v, %v", last, ok)
	}

	// Retroceso de tamaño.
	if _, err := l.Sign(Checkpoint{Origin: testOrigin, Size: 4, RootHash: root5}); !errors.Is(err, ErrRollback) {
		t.Errorf("firma un tamaño menor: err = %v, want %v", err, ErrRollback)
	}
	// Misma altura, raíz distinta: es el intento de reescritura.
	if _, err := l.Sign(Checkpoint{Origin: testOrigin, Size: 5, RootHash: other}); !errors.Is(err, ErrRollback) {
		t.Errorf("firma dos raíces para el mismo tamaño: err = %v, want %v", err, ErrRollback)
	}
	// Origin ajeno.
	if _, err := l.Sign(Checkpoint{Origin: "otro.example/log", Size: 6, RootHash: root5}); !errors.Is(err, ErrOrigin) {
		t.Errorf("firma un origin ajeno: err = %v, want %v", err, ErrOrigin)
	}
	// Tras los rechazos, el estado no cambió.
	if last, _ := l.Last(); last.Size != 5 || string(last.RootHash) != string(root5) {
		t.Errorf("un rechazo alteró el estado del log: %+v", last)
	}

	// Reemitir el mismo checkpoint es legítimo; extenderlo también.
	if _, err := l.Sign(Checkpoint{Origin: testOrigin, Size: 5, RootHash: root5}); err != nil {
		t.Errorf("rechaza reemitir el mismo checkpoint: %v", err)
	}
	if _, err := l.Sign(Checkpoint{Origin: testOrigin, Size: 9, RootHash: other}); err != nil {
		t.Errorf("rechaza una extensión legítima: %v", err)
	}
	if last, _ := l.Last(); last.Size != 9 {
		t.Errorf("no registró la extensión: %+v", last)
	}
}

// TestLogStoresCopyOfRoot comprueba que el log no guarde un alias del slice del
// llamante: si lo hiciera, mutar la raíz fuera desactivaría la guarda.
func TestLogStoresCopyOfRoot(t *testing.T) {
	signer, _, _ := testKeys(t, testOrigin, 0)
	l, err := NewLog(testOrigin, signer)
	if err != nil {
		t.Fatal(err)
	}
	root := rfc6962Root5(t)
	if _, err := l.Sign(Checkpoint{Origin: testOrigin, Size: 5, RootHash: root}); err != nil {
		t.Fatal(err)
	}
	root[0] ^= 0xff // el llamante muta su copia
	if _, err := l.Sign(Checkpoint{Origin: testOrigin, Size: 5, RootHash: root}); !errors.Is(err, ErrRollback) {
		t.Errorf("el log guardó un alias de la raíz: err = %v, want %v", err, ErrRollback)
	}
}

// appendSigLine añade a una nota una línea de firma fabricada con un blob del
// tamaño pedido. Se construye a mano, sin pasar por internal/witness: si el test
// usara el mismo código que produce las cosignatures, no probaría que IsCosigned
// reconoce la FORMA del blob, solo que dos funciones coinciden.
func appendSigLine(msg []byte, name string, blobLen int) []byte {
	blob := make([]byte, blobLen)
	for i := range blob {
		blob[i] = byte(i)
	}
	return append(append([]byte{}, msg...),
		[]byte("— "+name+" "+base64.StdEncoding.EncodeToString(blob)+"\n")...)
}

// TestIsCosignedDistinguishesBySignatureLength fija el criterio: 4 bytes de key
// ID más 64 de firma es el log; 4 más 72 es una cosignature v1.
func TestIsCosignedDistinguishesBySignatureLength(t *testing.T) {
	signer, _, _ := testKeys(t, "nucleoledger.com/poc", 1)
	msg, err := Sign(Checkpoint{Origin: "nucleoledger.com/poc", Size: 5, RootHash: rfc6962Root5(t)}, signer)
	if err != nil {
		t.Fatal(err)
	}

	if IsCosigned(msg) {
		t.Error("una nota firmada solo por el log no está cosignada")
	}
	if IsCosigned(appendSigLine(msg, "otro.example/log", 4+64)) {
		t.Error("un blob de 68 bytes es otra firma de nota, no una cosignature")
	}
	if !IsCosigned(appendSigLine(msg, "witness.example/w", 4+72)) {
		t.Error("un blob de 76 bytes es una tlog-cosignature@v1")
	}
	if IsCosigned([]byte("sin cuerpo ni firmas")) {
		t.Error("un mensaje que no separa cuerpo y firmas no está cosignado")
	}
}

// memLogState es una memoria de cerrojo en RAM, para probar Log.Bind sin base
// de datos: es justo lo que permite declarar LogState en este paquete.
type memLogState struct {
	note []byte
	err  error
	puts int
}

func (m *memLogState) LastSigned() ([]byte, error) { return m.note, m.err }
func (m *memLogState) PutLastSigned(n []byte) error {
	if m.err != nil {
		return m.err
	}
	m.puts++
	m.note = append([]byte(nil), n...)
	return nil
}

// TestLogBindRehydratesTheLock comprueba que el cerrojo se reconstruye desde la
// memoria duradera, que es lo que lo hace sobrevivir a un reinicio.
func TestLogBindRehydratesTheLock(t *testing.T) {
	const origin = "nucleoledger.com/durable"
	signer, _, _ := testKeys(t, origin, 11)

	// Un log firma un árbol de 5 y persiste.
	first, err := NewLog(origin, signer)
	if err != nil {
		t.Fatal(err)
	}
	st := &memLogState{}
	if err := first.Bind(st); err != nil {
		t.Fatal(err)
	}
	if _, err := first.Sign(Checkpoint{Origin: origin, Size: 5, RootHash: rfc6962Root5(t)}); err != nil {
		t.Fatal(err)
	}
	if st.puts != 1 {
		t.Fatalf("se persistieron %d firmas, want 1", st.puts)
	}

	// Otro log, recién creado, se ata a la misma memoria.
	second, err := NewLog(origin, signer)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := second.Last(); ok {
		t.Fatal("un Log recién creado ya recordaba algo")
	}
	if err := second.Bind(st); err != nil {
		t.Fatal(err)
	}
	last, ok := second.Last()
	if !ok || last.Size != 5 {
		t.Fatalf("tras Bind recuerda %+v (ok=%v), want tamaño 5", last, ok)
	}
	if _, err := second.Sign(Checkpoint{Origin: origin, Size: 3, RootHash: rfc6962Root5(t)}); !errors.Is(err, ErrRollback) {
		t.Errorf("el cerrojo rehidratado no frenó un retroceso: %v", err)
	}
}

// TestLogBindNeverLoosensTheLock: si el log ya recordaba algo en memoria, atarlo
// a una memoria con MENOS historia no puede aflojar el cerrojo. Rehidratar es
// recuperar lo olvidado, nunca olvidar lo recordado.
func TestLogBindNeverLoosensTheLock(t *testing.T) {
	const origin = "nucleoledger.com/durable"
	signer, _, _ := testKeys(t, origin, 11)
	l, err := NewLog(origin, signer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := l.Sign(Checkpoint{Origin: origin, Size: 5, RootHash: rfc6962Root5(t)}); err != nil {
		t.Fatal(err)
	}

	// Una memoria que solo conoce un árbol de 1.
	small, err := Sign(Checkpoint{Origin: origin, Size: 1, RootHash: rfc6962Root5(t)}, signer)
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Bind(&memLogState{note: small}); err != nil {
		t.Fatal(err)
	}
	if last, _ := l.Last(); last.Size != 5 {
		t.Errorf("tras Bind recuerda %d, want 5: el cerrojo se aflojó", last.Size)
	}
}

// TestLogBindRejectsBadState cubre las memorias que no se pueden usar.
func TestLogBindRejectsBadState(t *testing.T) {
	const origin = "nucleoledger.com/durable"
	signer, _, _ := testKeys(t, origin, 11)
	l, err := NewLog(origin, signer)
	if err != nil {
		t.Fatal(err)
	}

	if err := l.Bind(nil); err == nil {
		t.Error("se aceptó una memoria nula")
	}
	if err := l.Bind(&memLogState{note: []byte("esto no es una nota")}); err == nil {
		t.Error("se aceptó una nota ilegible")
	}
	foreignSigner, _, _ := testKeys(t, "otro.example/log", 12)
	foreign, err := Sign(Checkpoint{Origin: "otro.example/log", Size: 2, RootHash: rfc6962Root5(t)}, foreignSigner)
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Bind(&memLogState{note: foreign}); !errors.Is(err, ErrOrigin) {
		t.Errorf("memoria de otro log: err = %v, want %v", err, ErrOrigin)
	}
	boom := errors.New("disco ilegible")
	if err := l.Bind(&memLogState{err: boom}); !errors.Is(err, boom) {
		t.Errorf("err = %v, want %v", err, boom)
	}
}

// TestSignFailsIfTheLockCannotBePersisted: si el compromiso no se puede guardar,
// la nota NO sale. Devolverla y no haberla persistido dejaría abierta justo la
// ventana que el cerrojo duradero existe para cerrar.
func TestSignFailsIfTheLockCannotBePersisted(t *testing.T) {
	const origin = "nucleoledger.com/durable"
	signer, _, _ := testKeys(t, origin, 11)
	l, err := NewLog(origin, signer)
	if err != nil {
		t.Fatal(err)
	}
	l.state = &memLogState{err: errors.New("disco lleno")}

	if _, err := l.Sign(Checkpoint{Origin: origin, Size: 5, RootHash: rfc6962Root5(t)}); err == nil {
		t.Fatal("devolvió la nota sin poder persistir el compromiso")
	}
	if _, ok := l.Last(); ok {
		t.Error("el cerrojo avanzó pese a que la escritura falló")
	}
}
