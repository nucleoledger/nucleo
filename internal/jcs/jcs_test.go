package jcs

import "testing"

// Vector de prueba tomado de RFC 8785 §3.2.3.
func TestRFC8785Vector(t *testing.T) {
	var in any
	src := `{"numbers":[333333333.33333329, 1E30, 4.50, 2e-3, 0.000000000000000000000000001],
	"string":"\u20ac$\u000F\u000aA'\u0042\u0022\u005c\\\"\/",
	"literals":[null,true,false]}`
	if err := jsonUnmarshal([]byte(src), &in); err != nil {
		t.Fatal(err)
	}
	got, err := Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],"string":"€$\u000f\nA'B\"\\\\\"/"}`
	if string(got) != want {
		t.Fatalf("\n got: %s\nwant: %s", got, want)
	}
}

// Orden UTF-16: "😀" (surrogates D83D DE00) debe ir ANTES de "\uE000" porque
// D83D < E000, aunque en bytes UTF-8 (F0 9F 98 80 vs EE 80 80) sea al revés.
func TestUTF16KeyOrder(t *testing.T) {
	got, err := Marshal(map[string]any{"😀": 1, "\uE000": 2, "a": 3})
	if err != nil {
		t.Fatal(err)
	}
	want := "{\"a\":3,\"😀\":1,\"\uE000\":2}"
	if string(got) != want {
		t.Fatalf("\n got: %s\nwant: %s", got, want)
	}
}
