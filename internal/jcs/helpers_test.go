package jcs

import (
	"bytes"
	"encoding/json"
)

func jsonUnmarshal(b []byte, v any) error {
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	return d.Decode(v)
}
