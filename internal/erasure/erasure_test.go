package erasure

import (
	"strings"
	"testing"
)

// El vector del evento, calculado FUERA de este código (regla anti-circularidad):
//
//	H=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
//	printf '{"erased_payload_hash":"%s"}' $H | sha256sum
//	1de24cf3e82d924ec8cb94c7d56af49adcb8776cd45b32a2e9d29b5c7053a737
//
// H es el SHA-256 de la cadena vacía: un hash que cualquiera reconoce.
const (
	vectorHash      = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	vectorPayload   = `{"erased_payload_hash":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}`
	vectorEventHash = "1de24cf3e82d924ec8cb94c7d56af49adcb8776cd45b32a2e9d29b5c7053a737"
)

func TestElEventoDeSupresionCoincideConElVector(t *testing.T) {
	p, err := Payload(vectorHash)
	if err != nil {
		t.Fatal(err)
	}
	if string(p) != vectorPayload {
		t.Errorf("payload = %s\nwant      %s", p, vectorPayload)
	}
	h, err := EventPayloadHash(vectorHash)
	if err != nil {
		t.Fatal(err)
	}
	if h != vectorEventHash {
		t.Errorf("hash del evento = %s, want %s", h, vectorEventHash)
	}
}

func TestElEventoRechazaLoQueNoEsUnHash(t *testing.T) {
	for _, mal := range []string{
		"",
		strings.ToUpper(vectorHash),
		vectorHash[:63],
		vectorHash + "0",
		strings.Replace(vectorHash, "e", "g", 1),
		`e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b8"x`,
	} {
		if _, err := Payload(mal); err == nil {
			t.Errorf("Payload(%q) no falló", mal)
		}
	}
}

func TestTiposReservados(t *testing.T) {
	for typ, want := range map[string]bool{
		Type:              true,
		"nucleo.otro.v1":  true,
		"sri.factura.v1":  false,
		"ecuador.nucleo":  false,
		"Nucleo.erasure":  false,
		"nucleoledger.v1": false,
	} {
		if got := Reserved(typ); got != want {
			t.Errorf("Reserved(%q) = %v, want %v", typ, got, want)
		}
	}
}
