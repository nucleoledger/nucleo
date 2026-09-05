package ledger

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"
)

const (
	testTenant  = "1790012345001"
	testType    = "sri.factura.v1"
	testCID     = "blob://c4f3"
	testPubHex  = "03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8"
	testPayHash = "2bfd14f43d17fc7cea24e0917a8879b4b2f880b8baeec1b9d90fbaad655e71bd"
)

var (
	testPayload = []byte(`{"n":1}`)
	testTime    = time.Date(2026, 9, 4, 15, 0, 0, 0, time.UTC)
)

func testKey(t *testing.T, b byte) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	s := make([]byte, ed25519.SeedSize)
	for i := range s {
		s[i] = b + byte(i)
	}
	priv := ed25519.NewKeyFromSeed(s)
	return priv.Public().(ed25519.PublicKey), priv
}

// genesisHeader devuelve el header del bloque 0 con los valores fijos del golden.
func genesisHeader(t *testing.T) Header {
	t.Helper()
	pub, _ := testKey(t, 0)
	h, err := NewHeader(nil, testTenant, testType, testPayload, testCID, pub, testTime)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// TestCanonicalAndDigestGolden fija los bytes exactos de la forma canónica JCS y
// su digest. Ambos golden se calcularon FUERA del código —la cadena JSON a mano
// según el orden de claves de RFC 8785, el digest con sha256sum—, así que el
// test no se limita a repetir lo que produce la implementación.
func TestCanonicalAndDigestGolden(t *testing.T) {
	const wantCanonical = `{"index":0,"payload_cid":"blob://c4f3","payload_hash":"2bfd14f43d17fc7cea24e0917a8879b4b2f880b8baeec1b9d90fbaad655e71bd","prev_hash":"0000000000000000000000000000000000000000000000000000000000000000","signer_pubkey":"03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8","tenant":"1790012345001","timestamp":"2026-09-04T15:00:00Z","type":"sri.factura.v1"}`
	const wantDigest = "c4f90cc1ffb497ddb6d4b60121965ccd34b1ce2b507ddeab03d387aa74a8e656"

	h := genesisHeader(t)
	if h.PayloadHash != testPayHash {
		t.Errorf("payload_hash = %s, want %s", h.PayloadHash, testPayHash)
	}

	canonical, err := h.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	if string(canonical) != wantCanonical {
		t.Errorf("forma canónica:\n got %s\nwant %s", canonical, wantCanonical)
	}
	if len(canonical) != 367 {
		t.Errorf("longitud canónica = %d, want 367", len(canonical))
	}

	digest, err := h.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(digest); got != wantDigest {
		t.Errorf("digest = %s, want %s", got, wantDigest)
	}
}

// TestNewHeaderGenesisAndSuccession cubre la construcción de cabeceras.
func TestNewHeaderGenesisAndSuccession(t *testing.T) {
	pub, priv := testKey(t, 0)

	h0 := genesisHeader(t)
	if h0.Index != 0 || h0.PrevHash != GenesisPrevHash {
		t.Errorf("génesis mal formado: index=%d prev=%s", h0.Index, h0.PrevHash)
	}
	if h0.SignerPubKey != testPubHex {
		t.Errorf("signer_pubkey = %s, want %s", h0.SignerPubKey, testPubHex)
	}

	b0, err := Seal(h0, priv)
	if err != nil {
		t.Fatal(err)
	}
	h1, err := NewHeader(b0, testTenant, "sas.acta.v1", []byte("acta"), "blob://9a1b", pub, testTime.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if h1.Index != 1 {
		t.Errorf("index = %d, want 1", h1.Index)
	}
	if h1.PrevHash != b0.Hash {
		t.Errorf("prev_hash = %s, want %s", h1.PrevHash, b0.Hash)
	}

	// Clave pública inválida.
	if _, err := NewHeader(nil, testTenant, testType, testPayload, testCID, ed25519.PublicKey("corta"), testTime); !errors.Is(err, ErrInvalidHeader) {
		t.Errorf("clave corta: err = %v, want %v", err, ErrInvalidHeader)
	}
	// Campos que el Validate interno debe rechazar.
	if _, err := NewHeader(nil, "  ", testType, testPayload, testCID, pub, testTime); !errors.Is(err, ErrInvalidHeader) {
		t.Errorf("tenant vacío: err = %v, want %v", err, ErrInvalidHeader)
	}
	if _, err := NewHeader(nil, testTenant, "", testPayload, testCID, pub, testTime); !errors.Is(err, ErrInvalidHeader) {
		t.Errorf("type vacío: err = %v, want %v", err, ErrInvalidHeader)
	}
	// Índice al límite de JCS.
	atLimit := &Block{Header: Header{Index: MaxSafeIndex}}
	if _, err := NewHeader(atLimit, testTenant, testType, testPayload, testCID, pub, testTime); !errors.Is(err, ErrInvalidHeader) {
		t.Errorf("índice 2^53-1: err = %v, want %v", err, ErrInvalidHeader)
	}
	// El timestamp se normaliza a UTC aunque llegue en otra zona.
	zone := time.FixedZone("ECT", -5*3600)
	hz, err := NewHeader(nil, testTenant, testType, testPayload, testCID, pub, testTime.In(zone))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(hz.Timestamp, "Z") {
		t.Errorf("timestamp no normalizado a UTC: %s", hz.Timestamp)
	}
	if hz.Timestamp != h0.Timestamp {
		t.Errorf("la zona alteró el instante: %s != %s", hz.Timestamp, h0.Timestamp)
	}
}

// TestHeaderValidate recorre cada campo inválido.
func TestHeaderValidate(t *testing.T) {
	base := genesisHeader(t)
	valid := func() Header { return base }

	cases := []struct {
		name string
		mut  func(*Header)
		want error
	}{
		{"index por encima de 2^53-1", func(h *Header) { h.Index = MaxSafeIndex + 1 }, ErrInvalidHeader},
		{"prev_hash corto", func(h *Header) { h.PrevHash = "00" }, ErrInvalidHeader},
		{"prev_hash no hexadecimal", func(h *Header) { h.PrevHash = strings.Repeat("z", 64) }, ErrInvalidHeader},
		{"payload_hash corto", func(h *Header) { h.PayloadHash = "abcd" }, ErrInvalidHeader},
		{"payload_hash no hexadecimal", func(h *Header) { h.PayloadHash = strings.Repeat("g", 64) }, ErrInvalidHeader},
		{"signer_pubkey corta", func(h *Header) { h.SignerPubKey = "00ff" }, ErrInvalidHeader},
		{"tenant vacío", func(h *Header) { h.Tenant = "" }, ErrInvalidHeader},
		{"tenant en blanco", func(h *Header) { h.Tenant = "   " }, ErrInvalidHeader},
		{"type vacío", func(h *Header) { h.Type = "" }, ErrInvalidHeader},
		{"type en blanco", func(h *Header) { h.Type = "\t" }, ErrInvalidHeader},
		{"génesis sin prev_hash de génesis", func(h *Header) { h.PrevHash = strings.Repeat("ab", 32) }, ErrGenesis},
		{"no génesis apuntando a génesis", func(h *Header) { h.Index = 3 }, ErrInvalidHeader},
		{"timestamp sin Z", func(h *Header) { h.Timestamp = "2026-09-04T15:00:00+00:00" }, ErrInvalidHeader},
		{"timestamp ilegible", func(h *Header) { h.Timestamp = "ayer por la tardeZ" }, ErrInvalidHeader},
		{"timestamp vacío", func(h *Header) { h.Timestamp = "" }, ErrInvalidHeader},
	}
	for _, c := range cases {
		h := valid()
		c.mut(&h)
		if err := h.Validate(); !errors.Is(err, c.want) {
			t.Errorf("%s: err = %v, want %v", c.name, err, c.want)
		}
	}
	if err := valid().Validate(); err != nil {
		t.Errorf("un header válido fue rechazado: %v", err)
	}
}

// TestHeaderTime cubre el parseo del timestamp.
func TestHeaderTime(t *testing.T) {
	h := genesisHeader(t)
	got, err := h.Time()
	if err != nil {
		t.Fatal(err)
	}
	if !got.Equal(testTime) {
		t.Errorf("Time = %v, want %v", got, testTime)
	}
	for _, bad := range []string{"", "2026-09-04T15:00:00+00:00", "no es una fechaZ", "2026-13-45T99:00:00Z"} {
		h.Timestamp = bad
		if _, err := h.Time(); !errors.Is(err, ErrInvalidHeader) {
			t.Errorf("Time(%q): err = %v, want %v", bad, err, ErrInvalidHeader)
		}
	}
}

// TestSealAndVerifyRoundTrip es el camino feliz del sellado.
func TestSealAndVerifyRoundTrip(t *testing.T) {
	_, priv := testKey(t, 0)
	h := genesisHeader(t)

	b, err := Seal(h, priv)
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Verify(); err != nil {
		t.Fatalf("un bloque recién sellado no verifica: %v", err)
	}
	digest, _ := h.Digest()
	if b.Hash != hex.EncodeToString(digest) {
		t.Errorf("hash = %s, want %s", b.Hash, hex.EncodeToString(digest))
	}
	// La firma es sobre el digest, no sobre el JSON: un verificador que solo
	// conserve el hash debe poder comprobarla.
	sig, err := hex.DecodeString(b.Signature)
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := testKey(t, 0)
	if !ed25519.Verify(pub, digest, sig) {
		t.Error("la firma no valida contra el digest")
	}
	hb, err := b.HashBytes()
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(hb) != b.Hash {
		t.Errorf("HashBytes = %x, want %s", hb, b.Hash)
	}
}

// TestSealRejects cubre los rechazos del sellado, incluido el firmante que no
// corresponde a signer_pubkey.
func TestSealRejects(t *testing.T) {
	h := genesisHeader(t)

	if _, err := Seal(h, ed25519.PrivateKey("corta")); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("clave corta: err = %v, want %v", err, ErrInvalidKey)
	}
	if _, err := Seal(h, nil); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("clave nula: err = %v, want %v", err, ErrInvalidKey)
	}
	// Firmante que no corresponde: el header declara la clave 0 y firma la 100.
	_, otherPriv := testKey(t, 100)
	if _, err := Seal(h, otherPriv); !errors.Is(err, ErrSignerMismatch) {
		t.Errorf("firmante ajeno: err = %v, want %v", err, ErrSignerMismatch)
	}
	// Header inválido: no se sella.
	bad := h
	bad.Tenant = ""
	_, priv := testKey(t, 0)
	if _, err := Seal(bad, priv); !errors.Is(err, ErrInvalidHeader) {
		t.Errorf("header inválido: err = %v, want %v", err, ErrInvalidHeader)
	}
}

// TestVerifyRejects recorre las alteraciones de un bloque ya sellado.
func TestVerifyRejects(t *testing.T) {
	_, priv := testKey(t, 0)
	b, err := Seal(genesisHeader(t), priv)
	if err != nil {
		t.Fatal(err)
	}

	var nilBlock *Block
	if err := nilBlock.Verify(); !errors.Is(err, ErrEmptyChain) {
		t.Errorf("bloque nulo: err = %v, want %v", err, ErrEmptyChain)
	}

	cases := []struct {
		name string
		mut  func(*Block)
		want error
	}{
		{"tenant alterado", func(b *Block) { b.Header.Tenant = "9999999999001" }, ErrHashMismatch},
		{"type alterado", func(b *Block) { b.Header.Type = "otro.tipo.v1" }, ErrHashMismatch},
		{"payload_hash alterado", func(b *Block) { b.Header.PayloadHash = strings.Repeat("ab", 32) }, ErrHashMismatch},
		{"payload_cid alterado", func(b *Block) { b.Header.PayloadCID = "blob://otro" }, ErrHashMismatch},
		{"timestamp alterado", func(b *Block) { b.Header.Timestamp = "2026-09-04T16:00:00Z" }, ErrHashMismatch},
		{"hash declarado alterado", func(b *Block) { b.Hash = strings.Repeat("ab", 32) }, ErrHashMismatch},
		{"header inválido", func(b *Block) { b.Header.Tenant = "" }, ErrInvalidHeader},
		{"firma alterada", func(b *Block) {
			s := []byte(b.Signature)
			if s[0] == 'a' {
				s[0] = 'b'
			} else {
				s[0] = 'a'
			}
			b.Signature = string(s)
		}, ErrBadSignature},
		{"firma no hexadecimal", func(b *Block) { b.Signature = strings.Repeat("zz", 64) }, ErrBadSignature},
		{"firma de longitud incorrecta", func(b *Block) { b.Signature = "00ff" }, ErrBadSignature},
		{"signer_pubkey de otro", func(b *Block) {
			pub, _ := testKey(t, 100)
			b.Header.SignerPubKey = hex.EncodeToString(pub)
		}, ErrHashMismatch},
	}
	for _, c := range cases {
		tampered := *b
		c.mut(&tampered)
		if err := tampered.Verify(); !errors.Is(err, c.want) {
			t.Errorf("%s: err = %v, want %v", c.name, err, c.want)
		}
	}

	// HashBytes sobre un hash inválido.
	broken := *b
	broken.Hash = "no-es-hex"
	if _, err := broken.HashBytes(); !errors.Is(err, ErrHashMismatch) {
		t.Errorf("HashBytes con hash inválido: err = %v, want %v", err, ErrHashMismatch)
	}
	broken.Hash = "00ff"
	if _, err := broken.HashBytes(); !errors.Is(err, ErrHashMismatch) {
		t.Errorf("HashBytes con hash corto: err = %v, want %v", err, ErrHashMismatch)
	}
}

// buildChain sella una cadena de n bloques con la clave dada.
func buildChain(t *testing.T, n int, keyByte byte) []*Block {
	t.Helper()
	pub, priv := testKey(t, keyByte)
	chain := make([]*Block, 0, n)
	var prev *Block
	for i := 0; i < n; i++ {
		h, err := NewHeader(prev, testTenant, testType, []byte{byte(i)}, testCID, pub, testTime.Add(time.Duration(i)*time.Minute))
		if err != nil {
			t.Fatal(err)
		}
		b, err := Seal(h, priv)
		if err != nil {
			t.Fatal(err)
		}
		chain = append(chain, b)
		prev = b
	}
	return chain
}

// TestVerifyLink cubre el encadenamiento entre dos bloques.
func TestVerifyLink(t *testing.T) {
	chain := buildChain(t, 3, 0)

	if err := VerifyLink(chain[0], chain[1]); err != nil {
		t.Fatalf("un enlace legítimo falla: %v", err)
	}
	if err := VerifyLink(nil, chain[1]); !errors.Is(err, ErrEmptyChain) {
		t.Errorf("prev nulo: err = %v, want %v", err, ErrEmptyChain)
	}
	if err := VerifyLink(chain[0], nil); !errors.Is(err, ErrEmptyChain) {
		t.Errorf("cur nulo: err = %v, want %v", err, ErrEmptyChain)
	}
	// Índice roto: saltarse un bloque.
	if err := VerifyLink(chain[0], chain[2]); !errors.Is(err, ErrIndexSequence) {
		t.Errorf("índice salteado: err = %v, want %v", err, ErrIndexSequence)
	}
	// prev_hash roto.
	broken := *chain[1]
	broken.Header.PrevHash = strings.Repeat("ab", 32)
	if err := VerifyLink(chain[0], &broken); !errors.Is(err, ErrPrevHashMismatch) {
		t.Errorf("prev_hash roto: err = %v, want %v", err, ErrPrevHashMismatch)
	}
	// Timestamp que retrocede.
	back := *chain[1]
	back.Header.Timestamp = testTime.Add(-time.Hour).UTC().Format(time.RFC3339Nano)
	if err := VerifyLink(chain[0], &back); !errors.Is(err, ErrTimestampOrder) {
		t.Errorf("timestamp hacia atrás: err = %v, want %v", err, ErrTimestampOrder)
	}
	// Mismo instante: permitido, el orden es no decreciente.
	same := *chain[1]
	same.Header.Timestamp = chain[0].Header.Timestamp
	if err := VerifyLink(chain[0], &same); err != nil {
		t.Errorf("mismo timestamp debería permitirse: %v", err)
	}
	// Timestamp ilegible en cualquiera de los dos lados.
	badPrev := *chain[0]
	badPrev.Header.Timestamp = "xZ"
	if err := VerifyLink(&badPrev, chain[1]); !errors.Is(err, ErrInvalidHeader) {
		t.Errorf("timestamp ilegible en prev: err = %v, want %v", err, ErrInvalidHeader)
	}
	badCur := *chain[1]
	badCur.Header.Timestamp = "xZ"
	if err := VerifyLink(chain[0], &badCur); !errors.Is(err, ErrInvalidHeader) {
		t.Errorf("timestamp ilegible en cur: err = %v, want %v", err, ErrInvalidHeader)
	}
}

// TestVerifyChain cubre la validación completa, con y sin firmante esperado.
func TestVerifyChain(t *testing.T) {
	pub, _ := testKey(t, 0)
	chain := buildChain(t, 5, 0)

	if err := VerifyChain(chain, pub); err != nil {
		t.Fatalf("una cadena legítima falla: %v", err)
	}
	if err := VerifyChain(chain, nil); err != nil {
		t.Fatalf("sin firmante esperado también debería pasar: %v", err)
	}
	if err := VerifyChain(nil, pub); !errors.Is(err, ErrEmptyChain) {
		t.Errorf("cadena nula: err = %v, want %v", err, ErrEmptyChain)
	}
	if err := VerifyChain([]*Block{}, pub); !errors.Is(err, ErrEmptyChain) {
		t.Errorf("cadena vacía: err = %v, want %v", err, ErrEmptyChain)
	}
	// No empieza en génesis.
	if err := VerifyChain(chain[1:], pub); !errors.Is(err, ErrIndexSequence) {
		t.Errorf("sin génesis: err = %v, want %v", err, ErrIndexSequence)
	}
	// Firmante esperado distinto del real: es el control que impide que un
	// intruso inserte bloques válidos firmados con su propia clave.
	intruderPub, _ := testKey(t, 100)
	if err := VerifyChain(chain, intruderPub); !errors.Is(err, ErrUnexpectedSigner) {
		t.Errorf("firmante inesperado: err = %v, want %v", err, ErrUnexpectedSigner)
	}
	// Cadena entera del intruso: internamente válida, rechazada por la clave.
	intruderChain := buildChain(t, 3, 100)
	if err := VerifyChain(intruderChain, intruderPub); err != nil {
		t.Fatalf("la cadena del intruso debería ser internamente válida: %v", err)
	}
	if err := VerifyChain(intruderChain, pub); !errors.Is(err, ErrUnexpectedSigner) {
		t.Errorf("cadena del intruso contra la clave del tenant: err = %v, want %v", err, ErrUnexpectedSigner)
	}
	// Un bloque intruso insertado en medio de la cadena legítima.
	mixed := append([]*Block{}, chain...)
	mixed[2] = intruderChain[2]
	if err := VerifyChain(mixed, pub); err == nil {
		t.Error("acepta un bloque de otro firmante insertado en la cadena")
	}
	// Enlace roto en medio.
	brokenLink := append([]*Block{}, chain...)
	cut := *chain[3]
	cut.Header.PrevHash = strings.Repeat("ab", 32)
	brokenLink[3] = &cut
	if err := VerifyChain(brokenLink, pub); err == nil {
		t.Error("acepta una cadena con prev_hash roto")
	}
}

// TestSabotagesFromDemo reproduce como tests los tres ataques que demuestra
// cmd/nucleo-demo, que hasta ahora solo se ejercitaban a ojo.
func TestSabotagesFromDemo(t *testing.T) {
	pub, priv := testKey(t, 0)
	chain := buildChain(t, 3, 0)

	// 1. Edición de un campo de un bloque ya sellado.
	edited := append([]*Block{}, chain...)
	tampered := *chain[1]
	tampered.Header.Tenant = "9999999999001"
	edited[1] = &tampered
	if err := VerifyChain(edited, pub); !errors.Is(err, ErrHashMismatch) {
		t.Errorf("edición no detectada: err = %v, want %v", err, ErrHashMismatch)
	}

	// 2. Refirma del bloque alterado con la clave correcta: el hash cambia, así
	// que el prev_hash del siguiente deja de encajar.
	resealed, err := Seal(tampered.Header, priv)
	if err != nil {
		t.Fatal(err)
	}
	if err := resealed.Verify(); err != nil {
		t.Fatalf("el bloque refirmado debería ser internamente válido: %v", err)
	}
	if resealed.Hash == chain[1].Hash {
		t.Fatal("la alteración no cambió el hash: el escenario del test es inválido")
	}
	reforged := []*Block{chain[0], resealed, chain[2]}
	if err := VerifyChain(reforged, pub); !errors.Is(err, ErrPrevHashMismatch) {
		t.Errorf("refirma no detectada: err = %v, want %v", err, ErrPrevHashMismatch)
	}

	// 3. Reescritura completa desde el bloque alterado: la cadena vuelve a ser
	// internamente coherente. Solo la raíz de Merkle anclada la delata, que es
	// justo el motivo por el que existen los checkpoints y los testigos.
	h2, err := NewHeader(resealed, testTenant, testType, []byte{2}, testCID, pub, testTime.Add(2*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	b2, err := Seal(h2, priv)
	if err != nil {
		t.Fatal(err)
	}
	rewritten := []*Block{chain[0], resealed, b2}
	if err := VerifyChain(rewritten, pub); err != nil {
		t.Fatalf("la cadena reescrita debería verificar localmente: %v", err)
	}
	if rootOf(t, rewritten) == rootOf(t, chain) {
		t.Error("la reescritura no cambió la raíz de Merkle: no sería detectable")
	}
}

// rootOf calcula la raíz de Merkle de una cadena, que es lo que se ancla.
func rootOf(t *testing.T, chain []*Block) string {
	t.Helper()
	leaves := make([][]byte, 0, len(chain))
	for _, b := range chain {
		hb, err := b.HashBytes()
		if err != nil {
			t.Fatal(err)
		}
		leaves = append(leaves, hb)
	}
	return hex.EncodeToString(Root(leaves))
}
