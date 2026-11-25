package checkpoint

import (
	"errors"
	"strconv"
	"strings"
	"testing"
)

// TestDecodeBase64CanonicalRFC4648 usa los vectores de RFC 4648 §10, escritos aquí desde
// la RFC y no desde encoding/base64.
func TestDecodeBase64CanonicalRFC4648(t *testing.T) {
	for in, want := range map[string]string{
		"Zg==": "f", "Zm8=": "fo", "Zm9v": "foo", "Zm9vYg==": "foob",
		"Zm9vYmE=": "fooba", "Zm9vYmFy": "foobar",
	} {
		got, err := DecodeBase64Canonical(in)
		if err != nil || string(got) != want {
			t.Errorf("%q → %q, %v; want %q", in, got, err, want)
		}
	}
}

// TestDecodeBase64CanonicalRechaza: cada forma no canónica, y en particular las que
// base64.StdEncoding.Strict() aceptaba (\r y \n en cualquier punto).
func TestDecodeBase64CanonicalRechaza(t *testing.T) {
	casos := map[string]string{
		"vacía":                  "",
		"sin relleno":            "Zg",
		"relleno de más":         "Zg===",
		"bits de relleno a uno":  "Zh==",
		"bits de relleno, 1 '='": "Zm9=",
		"'=' en medio":           "Zg==Zm9v",
		"alfabeto URL":           "-_-_",
		"el caso del ci #104":    "00000000000000000000000000000\r00000000000000=",
	}
	for _, ws := range []string{"\r", "\n", " ", "\t", "\f", "\v"} {
		q := strconv.Quote(ws)
		casos["con "+q+" en medio"] = "Zm9v" + ws + "YmFy"
		casos["con "+q+" al final (longitud %4)"] = "Zm9vYmF" + ws
		casos["con "+q+" al principio"] = ws + "Zm9vYmFy"
	}
	for nombre, in := range casos {
		if b, err := DecodeBase64Canonical(in); err == nil || !errors.Is(err, ErrBase64) {
			t.Errorf("%s (%q): aceptado %x, err %v", nombre, in, b, err)
		}
	}
}

// TestCheckSigLines: la línea de firma de una nota pasa por la misma regla antes de
// note.Open, y una línea limpia no se toca.
func TestCheckSigLines(t *testing.T) {
	buena := "cuerpo\n\n— log Zm9vYmFy\n— testigo Zm9vYg==\n"
	if err := CheckSigLines([]byte(buena)); err != nil {
		t.Fatalf("una nota limpia: %v", err)
	}
	// Un \r o un \t: caracteres de control, como dicen TS y PHP (y x/mod después).
	for _, mala := range []string{
		"cuerpo\n\n— log Zm9v\rYmFy\n",
		"cuerpo\n\n— log Zm9v\tYmFy\n",
		"cuer\rpo\n\n— log Zm9vYmFy\n",
	} {
		if err := CheckSigLines([]byte(mala)); !errors.Is(err, ErrFormat) || !strings.Contains(err.Error(), "caracteres de control") {
			t.Errorf("%q: err %v, want caracteres de control", mala, err)
		}
	}
	for _, mala := range []string{
		"cuerpo\n\n— log Zm9vYmFy\n— testigo Zm9v YmFy\n",
		"cuerpo\n\n— log Zm9vY\nmFy\n", // un \n que deja delante «Zm9vY»: no canónico
		"cuerpo\n\n— log Zh==\n",
	} {
		if err := CheckSigLines([]byte(mala)); !errors.Is(err, ErrBase64) || !errors.Is(err, ErrFormat) {
			t.Errorf("%q: err %v, want ErrFormat y ErrBase64", mala, err)
		}
	}
}
