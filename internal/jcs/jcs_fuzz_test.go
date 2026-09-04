package jcs

import (
	"bytes"
	"testing"
)

func FuzzMarshal(f *testing.F) {
	f.Add([]byte(`null`))
	f.Add([]byte(`true`))
	f.Add([]byte(`{"b":2,"a":1}`))
	f.Add([]byte(`{"numbers":[333333333.33333329,1E30,4.50,2e-3,0.000000000000000000000000001]}`))
	f.Add([]byte(`{"😀":1,"":2,"a":3}`))
	f.Add([]byte(`[null,true,false,{"nested":["€","\\u000f",0.002]}]`))

	f.Fuzz(func(t *testing.T, data []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("Marshal no debe producir pánico: %v", r)
			}
		}()

		var in any
		if err := jsonUnmarshal(data, &in); err != nil {
			return
		}

		canonical, err := Marshal(in)
		if err != nil {
			return
		}

		var reparsed any
		if err := jsonUnmarshal(canonical, &reparsed); err != nil {
			t.Fatal(err)
		}
		roundTrip, err := Marshal(reparsed)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(roundTrip, canonical) {
			t.Fatalf("JCS no idempotente\n got: %s\nwant: %s", roundTrip, canonical)
		}
	})
}
