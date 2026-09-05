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
	ErrTreeSize  = errors.New("merkle: tamaño de árbol inválido")
	ErrBadProof  = errors.New("merkle: prueba de inclusión inválida")
	// ErrBadConsistency distingue el rechazo de una prueba de consistencia del
	// de una de inclusión: en forense de un ledger importa cuál de las dos
	// falló al rechazar un checkpoint.
	ErrBadConsistency = errors.New("merkle: prueba de consistencia inválida")
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

// ConsistencyProof devuelve PROOF(m, D[n]) de RFC 9162 §2.1.4 para demostrar
// que el árbol de tamaño oldSize es prefijo del árbol actual sin reescritura.
func ConsistencyProof(leaves [][]byte, oldSize int) ([][]byte, error) {
	if oldSize <= 0 || oldSize > len(leaves) {
		return nil, fmt.Errorf("%w: %d de %d", ErrTreeSize, oldSize, len(leaves))
	}
	if oldSize == len(leaves) {
		return nil, nil
	}
	return consistencyPath(leaves, oldSize, true), nil
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

func consistencyPath(leaves [][]byte, m int, complete bool) [][]byte {
	n := len(leaves)
	if m == n {
		if complete {
			return nil
		}
		return [][]byte{Root(leaves)}
	}

	k := largestPowerOfTwoBelow(n)
	if m <= k {
		return append(consistencyPath(leaves[:k], m, complete), Root(leaves[k:]))
	}
	return append(consistencyPath(leaves[k:], m-k, false), Root(leaves[:k]))
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

// VerifyConsistency aplica RFC 9162 §2.1.4.2: reconstruye simultáneamente la
// raíz vieja y la nueva desde la prueba, y acepta solo si ambas coinciden.
func VerifyConsistency(oldSize, newSize int, oldRoot, newRoot []byte, proof [][]byte) error {
	if oldSize <= 0 || newSize < oldSize {
		return ErrTreeSize
	}
	// Fallo cerrado: sin esta guarda, dos raíces vacías o ausentes se
	// comparan como iguales y un checkpoint mal parseado pasaría por
	// consistente cuando oldSize == newSize.
	if len(oldRoot) != sha256.Size || len(newRoot) != sha256.Size {
		return ErrBadConsistency
	}
	if oldSize == newSize {
		if len(proof) == 0 && bytes.Equal(oldRoot, newRoot) {
			return nil
		}
		return ErrBadConsistency
	}

	fn, sn := oldSize-1, newSize-1
	for fn&1 == 1 {
		fn >>= 1
		sn >>= 1
	}

	// fn == 0 tras la normalización equivale a "oldSize es potencia exacta de 2",
	// así que este caso es el "prepend hash_1" del paso 1 de RFC 9162 §2.1.4.2:
	// en vez de anteponerlo a la prueba, se siembra fr y sr con oldRoot.
	var fr, sr []byte
	if fn == 0 {
		fr = oldRoot
		sr = oldRoot
	} else {
		if len(proof) == 0 {
			return ErrBadConsistency
		}
		fr = proof[0]
		sr = proof[0]
		proof = proof[1:]
	}

	for _, p := range proof {
		if sn == 0 {
			return ErrBadConsistency
		}
		if fn&1 == 1 || fn == sn {
			fr = nodeHash(p, fr)
			sr = nodeHash(p, sr)
			for fn&1 == 0 && fn != 0 {
				fn >>= 1
				sn >>= 1
			}
		} else {
			sr = nodeHash(sr, p)
		}
		fn >>= 1
		sn >>= 1
	}

	if sn != 0 || !bytes.Equal(fr, oldRoot) || !bytes.Equal(sr, newRoot) {
		return ErrBadConsistency
	}
	return nil
}
