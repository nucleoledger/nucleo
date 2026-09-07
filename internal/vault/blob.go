package vault

import (
	"fmt"
)

// PayloadHashLen es la longitud del payload_hash en el AAD: 64 caracteres, el
// SHA-256 en hexadecimal minúsculo que el header del bloque ya lleva.
const PayloadHashLen = 64

// blobAAD implementa PROTOCOL.md §5: AAD = tenant ‖ payload_hash. Amarra cada
// texto cifrado a su tenant y a su compromiso, de modo que intercambiar dos
// blobs no cuela aunque el atacante controle la base.
//
// La concatenación no lleva separador, así que por sí sola sería ambigua: el
// tenant "A" con el hash "B…" produce los mismos bytes que el tenant "AB" con
// el hash "…". Lo que la desambigua es que el sufijo tiene longitud FIJA —los
// 64 caracteres que validateAAD exige—, de modo que la frontera entre tenant y
// hash está determinada y solo hay una lectura posible. Por eso la validación
// no es una comprobación de higiene que se pueda relajar: es lo que sostiene la
// propiedad. El formato de PROTOCOL §5 queda intacto.
func blobAAD(tenant, payloadHash string) []byte {
	aad := make([]byte, 0, len(tenant)+len(payloadHash))
	aad = append(aad, tenant...)
	aad = append(aad, payloadHash...)
	return aad
}

// validateAAD exige un tenant no vacío y un payload_hash de exactamente 64
// caracteres hexadecimales EN MINÚSCULA.
//
// Las mayúsculas se rechazan aunque denoten el mismo hash: "AB…" y "ab…" son
// bytes distintos y darían AAD distintos, así que un blob cifrado con una grafía
// no se descifraría con la otra. Aceptar ambas convertiría un fallo de
// normalización en un dato irrecuperable, y la forma canónica del proyecto
// —la que va en el header del bloque— es la minúscula.
func validateAAD(tenant, payloadHash string) error {
	if tenant == "" {
		return fmt.Errorf("%w: tenant vacío", ErrAAD)
	}
	if len(payloadHash) != PayloadHashLen {
		return fmt.Errorf("%w: payload_hash de %d caracteres, se esperaban %d",
			ErrAAD, len(payloadHash), PayloadHashLen)
	}
	for i := 0; i < len(payloadHash); i++ {
		c := payloadHash[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return fmt.Errorf("%w: payload_hash con %q en la posición %d, se espera hex en minúscula",
				ErrAAD, string(c), i)
		}
	}
	return nil
}

// EncryptBlob cifra un payload sensible bajo la DEK, con el AAD de PROTOCOL §5.
func EncryptBlob(dek []byte, tenant, payloadHash string, plaintext []byte) (ciphertext, nonce []byte, err error) {
	if err := validateAAD(tenant, payloadHash); err != nil {
		return nil, nil, err
	}
	return seal(dek, blobAAD(tenant, payloadHash), plaintext)
}

// DecryptBlob descifra un payload. Solo tiene éxito si el tenant y el
// payload_hash son los mismos con los que se cifró.
//
// Valida el AAD igual que EncryptBlob, y no por simetría estética: sin esta
// comprobación un atacante podría pedir el descifrado con un par (tenant, hash)
// mal formado que produjera los mismos bytes de AAD que un par legítimo.
func DecryptBlob(dek []byte, tenant, payloadHash string, ciphertext, nonce []byte) ([]byte, error) {
	if err := validateAAD(tenant, payloadHash); err != nil {
		return nil, err
	}
	pt, err := open(dek, blobAAD(tenant, payloadHash), ciphertext, nonce)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrDecrypt, err)
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

// secretAADPrefix separa el dominio del material interno del vault del de los
// payloads de bloque. Sin esa separación, un secreto interno podría descifrarse
// como si fuera un payload, o al revés.
const secretAADPrefix = "nucleo/secret/v1"

// EncryptSecret cifra material interno del vault —claves de firma, por ejemplo—
// bajo la DEK, en un dominio propio identificado por domain.
//
// No se reutiliza EncryptBlob para esto: su AAD es tenant ‖ payload_hash y está
// pensado para atar un texto cifrado a un compromiso del ledger. Un secreto
// interno no tiene compromiso al que atarse, y forzarlo a fingir uno
// convertiría el AAD en un adorno.
func (v *Vault) EncryptSecret(domain string, plaintext []byte) (ciphertext, nonce []byte, err error) {
	if domain == "" {
		return nil, nil, fmt.Errorf("%w: dominio vacío", ErrAAD)
	}
	return seal(v.dek, secretAAD(v.id, domain), plaintext)
}

// DecryptSecret descifra material interno del vault.
func (v *Vault) DecryptSecret(domain string, ciphertext, nonce []byte) ([]byte, error) {
	if domain == "" {
		return nil, fmt.Errorf("%w: dominio vacío", ErrAAD)
	}
	pt, err := open(v.dek, secretAAD(v.id, domain), ciphertext, nonce)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrDecrypt, err)
	}
	return pt, nil
}

// secretAAD ata el secreto a este vault y a su dominio.
func secretAAD(vaultID, domain string) []byte {
	aad := make([]byte, 0, len(secretAADPrefix)+len(vaultID)+len(domain)+2)
	aad = append(aad, secretAADPrefix...)
	aad = append(aad, 0x00)
	aad = append(aad, vaultID...)
	aad = append(aad, 0x00)
	aad = append(aad, domain...)
	return aad
}
