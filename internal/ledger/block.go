// Package ledger define el bloque del log append-only de Núcleo y las reglas
// matemáticas que lo hacen verificable por terceros:
//
//	hash      = SHA-256( JCS(header) )
//	signature = Ed25519.Sign( priv_tenant, hash )
//	header[i].prev_hash == hash[i-1]
//
// Cualquier alteración de un campo del header cambia su forma canónica, por tanto
// su hash, por tanto invalida la firma y rompe el prev_hash del bloque siguiente.
// El hash de cada bloque es además la hoja del árbol de Merkle (ver merkle.go),
// cuya raíz se ancla externamente; esa es la pieza que impide reescribir la cadena.
package ledger

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/nucleoledger/nucleo/internal/jcs"
)

const (
	// GenesisPrevHash es el prev_hash del bloque 0: 32 bytes en cero, en hex.
	GenesisPrevHash = "0000000000000000000000000000000000000000000000000000000000000000"
	// MaxSafeIndex es el mayor índice representable sin pérdida bajo JCS (2^53 - 1).
	MaxSafeIndex = uint64(1<<53 - 1)
	hexHashLen   = sha256.Size * 2
)

var (
	ErrInvalidHeader    = errors.New("ledger: header inválido")
	ErrInvalidKey       = errors.New("ledger: clave privada Ed25519 inválida")
	ErrSignerMismatch   = errors.New("ledger: la clave privada no corresponde a signer_pubkey")
	ErrHashMismatch     = errors.New("ledger: el hash declarado no coincide con SHA-256(JCS(header))")
	ErrBadSignature     = errors.New("ledger: firma Ed25519 inválida")
	ErrIndexSequence    = errors.New("ledger: índice fuera de secuencia")
	ErrPrevHashMismatch = errors.New("ledger: prev_hash no coincide con el hash del bloque anterior")
	ErrTimestampOrder   = errors.New("ledger: timestamp anterior al del bloque previo")
	ErrGenesis          = errors.New("ledger: el bloque 0 debe tener prev_hash de génesis")
	ErrEmptyChain       = errors.New("ledger: cadena vacía")
	ErrUnexpectedSigner = errors.New("ledger: signer_pubkey no es la clave esperada del tenant")
)

// Header es la parte firmada del bloque. Todos los campos son escalares para que
// la canonicalización sea trivial de reproducir en cualquier lenguaje.
type Header struct {
	Index        uint64 `json:"index"`         // posición en el log, 0 = génesis
	PrevHash     string `json:"prev_hash"`     // hex SHA-256 del bloque anterior
	Timestamp    string `json:"timestamp"`     // RFC 3339 con nanosegundos, siempre UTC ("Z")
	Tenant       string `json:"tenant"`        // identificador de la empresa (RUC)
	Type         string `json:"type"`          // tipo de evento, p.ej. "sri.factura.v1"
	PayloadHash  string `json:"payload_hash"`  // hex SHA-256 de los bytes exactos del payload
	PayloadCID   string `json:"payload_cid"`   // referencia al blob cifrado (fuera del log)
	SignerPubKey string `json:"signer_pubkey"` // hex Ed25519 pública del firmante
}

// Block es el header más su hash y la firma del tenant. Hash y Signature quedan
// fuera del header para que el contenido firmado sea inequívoco.
type Block struct {
	Header    Header `json:"header"`
	Hash      string `json:"hash"`      // hex SHA-256(JCS(header))
	Signature string `json:"signature"` // hex Ed25519(hash)
}

// NewHeader construye el header del siguiente bloque a partir del anterior
// (nil para génesis). El payload nunca entra al log: solo su hash.
func NewHeader(prev *Block, tenant, typ string, payload []byte, payloadCID string, signer ed25519.PublicKey, now time.Time) (Header, error) {
	if len(signer) != ed25519.PublicKeySize {
		return Header{}, fmt.Errorf("%w: clave pública de %d bytes", ErrInvalidHeader, len(signer))
	}
	h := Header{
		Index:        0,
		PrevHash:     GenesisPrevHash,
		Timestamp:    now.UTC().Format(time.RFC3339Nano),
		Tenant:       tenant,
		Type:         typ,
		PayloadHash:  hashHex(payload),
		PayloadCID:   payloadCID,
		SignerPubKey: hex.EncodeToString(signer),
	}
	if prev != nil {
		if prev.Header.Index >= MaxSafeIndex {
			return Header{}, fmt.Errorf("%w: índice excede 2^53-1", ErrInvalidHeader)
		}
		h.Index = prev.Header.Index + 1
		h.PrevHash = prev.Hash
	}
	if err := h.Validate(); err != nil {
		return Header{}, err
	}
	return h, nil
}

// Validate revisa forma y rangos; no revisa criptografía ni encadenamiento.
func (h Header) Validate() error {
	switch {
	case h.Index > MaxSafeIndex:
		return fmt.Errorf("%w: index > 2^53-1", ErrInvalidHeader)
	case !isHex(h.PrevHash, hexHashLen):
		return fmt.Errorf("%w: prev_hash no es SHA-256 hex", ErrInvalidHeader)
	case !isHex(h.PayloadHash, hexHashLen):
		return fmt.Errorf("%w: payload_hash no es SHA-256 hex", ErrInvalidHeader)
	case !isHex(h.SignerPubKey, ed25519.PublicKeySize*2):
		return fmt.Errorf("%w: signer_pubkey no es Ed25519 hex", ErrInvalidHeader)
	case strings.TrimSpace(h.Tenant) == "":
		return fmt.Errorf("%w: tenant vacío", ErrInvalidHeader)
	case strings.TrimSpace(h.Type) == "":
		return fmt.Errorf("%w: type vacío", ErrInvalidHeader)
	case h.Index == 0 && h.PrevHash != GenesisPrevHash:
		return ErrGenesis
	case h.Index > 0 && h.PrevHash == GenesisPrevHash:
		return fmt.Errorf("%w: solo el bloque 0 puede apuntar a génesis", ErrInvalidHeader)
	}
	if _, err := h.Time(); err != nil {
		return err
	}
	return nil
}

// Time parsea el timestamp exigiendo UTC explícito.
func (h Header) Time() (time.Time, error) {
	if !strings.HasSuffix(h.Timestamp, "Z") {
		return time.Time{}, fmt.Errorf("%w: timestamp debe ser UTC con sufijo Z", ErrInvalidHeader)
	}
	t, err := time.Parse(time.RFC3339Nano, h.Timestamp)
	if err != nil {
		return time.Time{}, fmt.Errorf("%w: timestamp: %v", ErrInvalidHeader, err)
	}
	return t, nil
}

// Canonical devuelve los bytes JCS del header: es lo que se hashea.
func (h Header) Canonical() ([]byte, error) {
	b, err := jcs.Marshal(h)
	if err != nil {
		return nil, fmt.Errorf("ledger: canonicalización: %w", err)
	}
	return b, nil
}

// Digest calcula SHA-256(JCS(header)).
func (h Header) Digest() ([]byte, error) {
	c, err := h.Canonical()
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(c)
	return sum[:], nil
}

// Seal hashea y firma el header con la clave privada del tenant. Se firma el
// digest (32 bytes) y no el JSON completo: así un verificador que solo conserva
// el hash puede comprobar la firma sin reconstruir el header.
func Seal(h Header, priv ed25519.PrivateKey) (*Block, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, ErrInvalidKey
	}
	if err := h.Validate(); err != nil {
		return nil, err
	}
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok || hex.EncodeToString(pub) != h.SignerPubKey {
		return nil, ErrSignerMismatch
	}
	digest, err := h.Digest()
	if err != nil {
		return nil, err
	}
	sig := ed25519.Sign(priv, digest)
	return &Block{
		Header:    h,
		Hash:      hex.EncodeToString(digest),
		Signature: hex.EncodeToString(sig),
	}, nil
}

// Verify comprueba la integridad interna del bloque: header bien formado,
// hash recomputado igual al declarado y firma válida bajo signer_pubkey.
func (b *Block) Verify() error {
	if b == nil {
		return ErrEmptyChain
	}
	if err := b.Header.Validate(); err != nil {
		return err
	}
	digest, err := b.Header.Digest()
	if err != nil {
		return err
	}
	if hex.EncodeToString(digest) != b.Hash {
		return ErrHashMismatch
	}
	pub, err := hex.DecodeString(b.Header.SignerPubKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: signer_pubkey", ErrInvalidHeader)
	}
	sig, err := hex.DecodeString(b.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return ErrBadSignature
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), digest, sig) {
		return ErrBadSignature
	}
	return nil
}

// VerifyLink comprueba que cur sigue inmediatamente a prev: índice consecutivo,
// prev_hash igual al hash de prev y tiempo no decreciente.
func VerifyLink(prev, cur *Block) error {
	if prev == nil || cur == nil {
		return ErrEmptyChain
	}
	if cur.Header.Index != prev.Header.Index+1 {
		return fmt.Errorf("%w: esperado %d, recibido %d", ErrIndexSequence, prev.Header.Index+1, cur.Header.Index)
	}
	if cur.Header.PrevHash != prev.Hash {
		return ErrPrevHashMismatch
	}
	pt, err := prev.Header.Time()
	if err != nil {
		return err
	}
	ct, err := cur.Header.Time()
	if err != nil {
		return err
	}
	if ct.Before(pt) {
		return ErrTimestampOrder
	}
	return nil
}

// VerifyChain valida una cadena completa desde génesis. Si expectedSigner no es
// nil, exige además que todos los bloques estén firmados por esa clave: sin este
// control, un atacante podría insertar bloques válidos firmados con su propia clave.
func VerifyChain(blocks []*Block, expectedSigner ed25519.PublicKey) error {
	if len(blocks) == 0 {
		return ErrEmptyChain
	}
	if blocks[0].Header.Index != 0 {
		return fmt.Errorf("%w: la cadena no inicia en génesis", ErrIndexSequence)
	}
	expected := ""
	if expectedSigner != nil {
		expected = hex.EncodeToString(expectedSigner)
	}
	for i, b := range blocks {
		if err := b.Verify(); err != nil {
			return fmt.Errorf("bloque %d: %w", i, err)
		}
		if expected != "" && b.Header.SignerPubKey != expected {
			return fmt.Errorf("bloque %d: %w", i, ErrUnexpectedSigner)
		}
		if i > 0 {
			if err := VerifyLink(blocks[i-1], b); err != nil {
				return fmt.Errorf("bloque %d: %w", i, err)
			}
		}
	}
	return nil
}

// HashBytes devuelve el hash del bloque en bytes (hoja de Merkle).
func (b *Block) HashBytes() ([]byte, error) {
	h, err := hex.DecodeString(b.Hash)
	if err != nil || len(h) != sha256.Size {
		return nil, ErrHashMismatch
	}
	return h, nil
}

func hashHex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func isHex(s string, wantLen int) bool {
	if len(s) != wantLen {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}
