package vault

import (
	"errors"
	"fmt"
)

// blobAAD implementa PROTOCOL.md §5: AAD = tenant ‖ payload_hash. Amarra cada
// texto cifrado a su tenant y a su compromiso, de modo que intercambiar dos
// blobs no cuela aunque el atacante controle la base.
func blobAAD(tenant, payloadHash string) []byte {
	aad := make([]byte, 0, len(tenant)+len(payloadHash))
	aad = append(aad, tenant...)
	aad = append(aad, payloadHash...)
	return aad
}

// EncryptBlob cifra un payload sensible bajo la DEK, con el AAD de PROTOCOL §5.
func EncryptBlob(dek []byte, tenant, payloadHash string, plaintext []byte) (ciphertext, nonce []byte, err error) {
	if tenant == "" || payloadHash == "" {
		return nil, nil, errors.New("vault: tenant y payload_hash son obligatorios en el AAD")
	}
	return seal(dek, blobAAD(tenant, payloadHash), plaintext)
}

// DecryptBlob descifra un payload. Solo tiene éxito si el tenant y el
// payload_hash son los mismos con los que se cifró.
func DecryptBlob(dek []byte, tenant, payloadHash string, ciphertext, nonce []byte) ([]byte, error) {
	pt, err := open(dek, blobAAD(tenant, payloadHash), ciphertext, nonce)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDecrypt, err)
	}
	return pt, nil
}

// EncryptBlob cifra bajo la DEK del vault.
func (v *Vault) EncryptBlob(tenant, payloadHash string, plaintext []byte) (ciphertext, nonce []byte, err error) {
	return EncryptBlob(v.dek, tenant, payloadHash, plaintext)
}

// DecryptBlob descifra bajo la DEK del vault.
func (v *Vault) DecryptBlob(tenant, payloadHash string, ciphertext, nonce []byte) ([]byte, error) {
	return DecryptBlob(v.dek, tenant, payloadHash, ciphertext, nonce)
}
