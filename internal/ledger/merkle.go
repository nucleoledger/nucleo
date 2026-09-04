package ledger

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
)

// Árbol de Merkle según RFC 6962 (Certificate Transparency), el mismo esquema
// que usa Sigstore Rekor. Se eligió por dos razones:
//   1. Prefijos de dominio 0x00 (hoja) y 0x01 (nodo) impiden ataques de
//      segunda preimagen donde un nodo interno se hace pasar por hoja.
//   2. La raíz de un log de tamaño n queda determinada aunque n no sea potencia
//      de 2, lo que permite pruebas de consistencia entre raíces ancladas.
//
// Las hojas son los hashes de bloque (32 bytes). La raíz es lo que el daemon
// publica en el servicio de anclaje cada N minutos.

var (
	ErrLeafIndex = errors.New("merkle: índice de hoja fuera de rango")
	ErrBadProof  = errors.New("merkle: prueba de inclusión inválida")
)

// LeafHash = SHA-256(0x00 || data).
func LeafHash(data []byte) []byte {
	h := sha256.New()
	h.Write([]byte{0x00})
	h.Write(data)
	return h.Sum(nil)
}

// nodeHash = SHA-256(0x01 || left || right).
func nodeHash(left, right []byte) []byte {
	h := sha256.New()
	h.Write([]byte{0x01})
	h.Write(left)
	h.Write(right)
	return h.Sum(nil)
}

// largestPowerOfTwoBelow devuelve la mayor potencia de 2 estrictamente menor que n.
func largestPowerOfTwoBelow(n int) int {
	k := 1
	for k*2 < n {
		k *= 2
	}
	return k
}

// Root calcula MTH(D[n]) sobre datos crudos de hoja (aquí, hashes de bloque).
// Un log vacío tiene raíz SHA-256("") por definición de la RFC.
func Root(leaves [][]byte) []byte {
	switch len(leaves) {
	case 0:
		s := sha256.Sum256(nil)
		return s[:]
	case 1:
		return LeafHash(leaves[0])
	}
	k := largestPowerOfTwoBelow(len(leaves))
	return nodeHash(Root(leaves[:k]), Root(leaves[k:]))
}

// InclusionProof devuelve el camino de auditoría PATH(m, D[n]) para la hoja m.
// El auditor solo necesita: la hoja, m, n, este camino y la raíz anclada.
func InclusionProof(leaves [][]byte, m int) ([][]byte, error) {
	if m < 0 || m >= len(leaves) {
		return nil, fmt.Errorf("%w: %d de %d", ErrLeafIndex, m, len(leaves))
	}
	return proofPath(leaves, m), nil
}

func proofPath(leaves [][]byte, m int) [][]byte {
	n := len(leaves)
	if n == 1 {
		return nil
	}
	k := largestPowerOfTwoBelow(n)
	if m < k {
		return append(proofPath(leaves[:k], m), Root(leaves[k:]))
	}
	return append(proofPath(leaves[k:], m-k), Root(leaves[:k]))
}

// VerifyInclusion reconstruye la raíz desde la hoja y el camino, siguiendo el
// algoritmo de RFC 9162 §2.1.3.2, y la compara con la raíz esperada.
func VerifyInclusion(leafData []byte, m, n int, proof [][]byte, root []byte) error {
	if m < 0 || n <= 0 || m >= n {
		return ErrLeafIndex
	}
	fn, sn := m, n-1
	r := LeafHash(leafData)
	for _, p := range proof {
		if sn == 0 {
			return ErrBadProof
		}
		if fn&1 == 1 || fn == sn {
			r = nodeHash(p, r)
			for fn&1 == 0 && fn != 0 {
				fn >>= 1
				sn >>= 1
			}
		} else {
			r = nodeHash(r, p)
		}
		fn >>= 1
		sn >>= 1
	}
	if sn != 0 || !bytes.Equal(r, root) {
		return ErrBadProof
	}
	return nil
}
