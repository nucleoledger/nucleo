package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"unicode/utf8"

	"github.com/nucleoledger/nucleo/internal/store"
)

// La clave de idempotencia (ADR-020 §D).
//
// Un ERP que reintenta tras un timeout no sabe si el sellado anterior llegó a
// escribirse. La clave es lo que le permite preguntarlo sin arriesgarse: con la misma
// clave y el mismo documento, el segundo `seal` no escribe nada y contesta lo que
// contestó el primero.
//
// Vive en log_state, que ADR-009 declaró mutable por diseño, y NO en el header: la
// clave es un detalle del transporte entre el ERP y la CLI, no un hecho sobre el
// documento, y meterla en lo firmado cambiaría el formato de cable y los tres
// verificadores para no demostrar nada.

// maxIdemKey es el tamaño máximo de la clave. 128 bytes dan de sobra para un UUID, un
// número de comprobante o los dos juntos, y acotan lo que entra en un mensaje de error.
const maxIdemKey = 128

// idemPrefix es el espacio de nombres de las claves en log_state.
const idemPrefix = "seal/idempotency/v1/"

// idemRecord es lo que se guarda bajo la clave.
//
// Lleva el tenant y la clave EN CLARO para poder nombrarlos en los errores, y el
// payload_hash y el tipo para poder distinguir un reintento del mismo documento de una
// clave reutilizada para otro, que es la diferencia que importa.
type idemRecord struct {
	Tenant      string `json:"tenant"`
	Key         string `json:"key"`
	Type        string `json:"type"`
	Block       uint64 `json:"block"`
	PayloadHash string `json:"payload_hash"`
	SealedAt    string `json:"sealed_at"`
}

// validarClaveIdem acota la clave: no vacía, no enorme, UTF-8 válido y sin controles.
//
// Los caracteres de control se rechazan porque la clave se imprime en errores y se
// guarda en un valor de texto; una clave con un salto de línea podría fabricar una
// línea de mensaje que parezca de la CLI.
func validarClaveIdem(k string) error {
	if k == "" {
		return errors.New("--idempotency-key no puede estar vacía")
	}
	if len(k) > maxIdemKey {
		return fmt.Errorf("--idempotency-key de %d bytes; el máximo es %d", len(k), maxIdemKey)
	}
	if !utf8.ValidString(k) {
		return errors.New("--idempotency-key no es UTF-8 válido")
	}
	for _, r := range k {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("--idempotency-key lleva un carácter de control (%U)", r)
		}
	}
	return nil
}

// claveIdem deriva la clave de log_state a partir del tenant y de la clave del
// integrador.
//
// Se hashean los dos juntos con un separador que no puede aparecer en el tenant ni en
// la clave (el byte 0x00, que validarClaveIdem prohíbe), así que el par (tenant, clave)
// determina la clave de log_state sin ambigüedad. De ahí sale el ACOTAMIENTO POR
// TENANT que pide ADR-020: dos emisores del mismo despliegue pueden usar
// "factura-001" sin pisarse, porque es un identificador natural en cualquier ERP.
func claveIdem(tenant, key string) string {
	h := sha256.New()
	h.Write([]byte(tenant))
	h.Write([]byte{0x00})
	h.Write([]byte(key))
	return idemPrefix + hex.EncodeToString(h.Sum(nil))
}

// leerIdem devuelve el registro guardado bajo (tenant, key), si lo hay.
func leerIdem(s *store.Store, tenant, key string) (idemRecord, bool, error) {
	v, err := s.State(claveIdem(tenant, key))
	if errors.Is(err, store.ErrNotFound) {
		return idemRecord{}, false, nil
	}
	if err != nil {
		return idemRecord{}, false, err
	}
	var r idemRecord
	if err := json.Unmarshal([]byte(v), &r); err != nil {
		// El registro lo escribe esta CLI en la misma transacción que el bloque. Si no
		// se puede leer, alguien ha tocado el fichero, y eso no es un error de uso.
		return idemRecord{}, false, verifyErr("el registro de idempotencia de %q está ilegible: %v", key, err)
	}
	return r, true, nil
}

// entradaIdem serializa el registro para guardarlo en la transacción del sellado.
func entradaIdem(r idemRecord) (string, string, error) {
	b, err := json.Marshal(r)
	if err != nil {
		return "", "", err
	}
	return claveIdem(r.Tenant, r.Key), string(b), nil
}
