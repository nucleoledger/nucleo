package ledger

import (
	"errors"
	"testing"
)

func TestConsistencyProofExtendsTree(t *testing.T) {
	leaves := merkleTestLeaves(7)
	oldRoot := Root(leaves[:3])
	newRoot := Root(leaves)

	proof, err := ConsistencyProof(leaves, 3)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyConsistency(3, 7, oldRoot, newRoot, proof); err != nil {
		t.Fatal(err)
	}
}

func TestConsistencyProofRejectsRewrittenHistory(t *testing.T) {
	leaves := merkleTestLeaves(7)
	oldRoot := Root(leaves[:3])

	rewritten := merkleTestLeaves(7)
	rewritten[1] = []byte("rewritten historical leaf")
	newRoot := Root(rewritten)
	proof, err := ConsistencyProof(rewritten, 3)
	if err != nil {
		t.Fatal(err)
	}

	if err := VerifyConsistency(3, 7, oldRoot, newRoot, proof); err == nil {
		t.Fatal("se aceptó una reescritura histórica")
	}
}

func TestConsistencyProofSameSize(t *testing.T) {
	leaves := merkleTestLeaves(3)
	root := Root(leaves)

	proof, err := ConsistencyProof(leaves, len(leaves))
	if err != nil {
		t.Fatal(err)
	}
	if len(proof) != 0 {
		t.Fatalf("proof len = %d, want 0", len(proof))
	}
	if err := VerifyConsistency(3, 3, root, root, proof); err != nil {
		t.Fatal(err)
	}
}

func TestConsistencyProofOldSizeOne(t *testing.T) {
	leaves := merkleTestLeaves(4)
	oldRoot := Root(leaves[:1])
	newRoot := Root(leaves)

	proof, err := ConsistencyProof(leaves, 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyConsistency(1, 4, oldRoot, newRoot, proof); err != nil {
		t.Fatal(err)
	}
}

func merkleTestLeaves(n int) [][]byte {
	leaves := make([][]byte, n)
	for i := range leaves {
		leaves[i] = []byte{byte(i)}
	}
	return leaves
}

// TestConsistencyRoundTripAllSizes recorre todos los tamaños hasta 64 y todos
// los prefijos posibles. Cubre las dos normalizaciones de RFC 9162 §2.1.4.2
// (pasos 3 y 5.3), que los casos puntuales no ejercitan.
func TestConsistencyRoundTripAllSizes(t *testing.T) {
	for n := 1; n <= 64; n++ {
		leaves := merkleTestLeaves(n)
		newRoot := Root(leaves)
		for m := 1; m <= n; m++ {
			proof, err := ConsistencyProof(leaves, m)
			if err != nil {
				t.Fatalf("ConsistencyProof(%d, %d): %v", m, n, err)
			}
			if err := VerifyConsistency(m, n, Root(leaves[:m]), newRoot, proof); err != nil {
				t.Errorf("VerifyConsistency(%d, %d) rechaza prueba honesta: %v", m, n, err)
			}
		}
	}
}

// TestConsistencyNormalizationLoops fija los pares que entran en cada bucle de
// desplazamiento de la RFC: (2,5), (4,5) y (6,8) en el paso 3; (5,6) y (11,12)
// en el paso 5.3. Sirven de centinela si alguien toca esos bucles.
func TestConsistencyNormalizationLoops(t *testing.T) {
	pairs := [][2]int{{2, 5}, {4, 5}, {6, 8}, {5, 6}, {11, 12}}
	for _, p := range pairs {
		m, n := p[0], p[1]
		leaves := merkleTestLeaves(n)
		oldRoot, newRoot := Root(leaves[:m]), Root(leaves)

		proof, err := ConsistencyProof(leaves, m)
		if err != nil {
			t.Fatalf("(%d, %d): %v", m, n, err)
		}
		if err := VerifyConsistency(m, n, oldRoot, newRoot, proof); err != nil {
			t.Errorf("(%d, %d) rechaza prueba honesta: %v", m, n, err)
		}

		// La misma prueba contra una historia reescrita debe fallar.
		rewritten := merkleTestLeaves(n)
		rewritten[m-1] = []byte("rewritten historical leaf")
		if err := VerifyConsistency(m, n, oldRoot, Root(rewritten), proof); err == nil {
			t.Errorf("(%d, %d) acepta una reescritura histórica", m, n)
		}
	}
}

// TestVerifyConsistencyErrorPaths recorre las rutas de rechazo del verificador,
// que ningún caso feliz alcanza.
func TestVerifyConsistencyErrorPaths(t *testing.T) {
	leaves := merkleTestLeaves(8)
	newRoot := Root(leaves)
	oldRoot3 := Root(leaves[:3])
	oldRoot4 := Root(leaves[:4])
	proof3, err := ConsistencyProof(leaves, 3)
	if err != nil {
		t.Fatal(err)
	}
	proof1, err := ConsistencyProof(leaves, 1)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name             string
		oldSize, newSize int
		oldRoot, newRoot []byte
		proof            [][]byte
		want             error
	}{
		{"oldSize cero", 0, 8, oldRoot3, newRoot, proof3, ErrTreeSize},
		{"oldSize negativo", -1, 8, oldRoot3, newRoot, proof3, ErrTreeSize},
		{"newSize menor que oldSize", 8, 4, newRoot, oldRoot4, nil, ErrTreeSize},
		{"tamaños iguales con raíces distintas", 8, 8, oldRoot3, newRoot, nil, ErrBadConsistency},
		{"tamaños iguales con prueba no vacía", 8, 8, newRoot, newRoot, proof3, ErrBadConsistency},
		{"prueba vacía con oldSize no potencia de dos", 3, 8, oldRoot3, newRoot, nil, ErrBadConsistency},
		{"prueba vacía con oldSize potencia de dos", 4, 8, oldRoot4, newRoot, nil, ErrBadConsistency},
		{"prueba de otro par de tamaños", 3, 8, oldRoot3, newRoot, proof1, ErrBadConsistency},
		{"prueba más larga de lo necesario", 1, 4, Root(leaves[:1]), Root(leaves[:4]),
			append(append([][]byte{}, proof1...), make([]byte, 32), make([]byte, 32)), ErrBadConsistency},
		{"raíces nulas con tamaños iguales", 8, 8, nil, nil, nil, ErrBadConsistency},
		{"raíces vacías con tamaños iguales", 8, 8, []byte{}, []byte{}, nil, ErrBadConsistency},
		{"raíz vieja truncada", 3, 8, oldRoot3[:31], newRoot, proof3, ErrBadConsistency},
		{"raíz nueva sobredimensionada", 3, 8, oldRoot3, append(append([]byte{}, newRoot...), 0), proof3, ErrBadConsistency},
	}
	for _, c := range cases {
		err := VerifyConsistency(c.oldSize, c.newSize, c.oldRoot, c.newRoot, c.proof)
		if !errors.Is(err, c.want) {
			t.Errorf("%s: err = %v, want %v", c.name, err, c.want)
		}
	}
}

// TestConsistencyProofErrorPaths cubre el dominio de entrada del generador.
func TestConsistencyProofErrorPaths(t *testing.T) {
	leaves := merkleTestLeaves(4)
	cases := []struct {
		name    string
		leaves  [][]byte
		oldSize int
	}{
		{"oldSize cero", leaves, 0},
		{"oldSize negativo", leaves, -1},
		{"oldSize mayor que el árbol", leaves, 5},
		{"árbol vacío", nil, 1},
	}
	for _, c := range cases {
		if _, err := ConsistencyProof(c.leaves, c.oldSize); !errors.Is(err, ErrTreeSize) {
			t.Errorf("%s: err = %v, want %v", c.name, err, ErrTreeSize)
		}
	}
}

// TestVerifyConsistencyRejectsTamperedProof manipula la prueba de todas las
// formas baratas para un atacante: mutar, quitar, añadir e invertir nodos.
func TestVerifyConsistencyRejectsTamperedProof(t *testing.T) {
	for n := 2; n <= 24; n++ {
		leaves := merkleTestLeaves(n)
		newRoot := Root(leaves)
		for m := 1; m < n; m++ {
			oldRoot := Root(leaves[:m])
			proof, err := ConsistencyProof(leaves, m)
			if err != nil {
				t.Fatal(err)
			}

			for i := range proof {
				mutated := clonePath(proof)
				mutated[i][0] ^= 0xff
				if err := VerifyConsistency(m, n, oldRoot, newRoot, mutated); err == nil {
					t.Errorf("(%d, %d) acepta prueba con el nodo %d mutado", m, n, i)
				}

				truncated := append(clonePath(proof[:i]), clonePath(proof[i+1:])...)
				if err := VerifyConsistency(m, n, oldRoot, newRoot, truncated); err == nil {
					t.Errorf("(%d, %d) acepta prueba sin el nodo %d", m, n, i)
				}
			}

			extended := append(clonePath(proof), make([]byte, 32))
			if err := VerifyConsistency(m, n, oldRoot, newRoot, extended); err == nil {
				t.Errorf("(%d, %d) acepta prueba con un nodo de más", m, n)
			}

			if len(proof) > 1 {
				reversed := clonePath(proof)
				for i, j := 0, len(reversed)-1; i < j; i, j = i+1, j-1 {
					reversed[i], reversed[j] = reversed[j], reversed[i]
				}
				if err := VerifyConsistency(m, n, oldRoot, newRoot, reversed); err == nil {
					t.Errorf("(%d, %d) acepta la prueba en orden invertido", m, n)
				}
			}

			corrupted := append([]byte(nil), oldRoot...)
			corrupted[0] ^= 0xff
			if err := VerifyConsistency(m, n, corrupted, newRoot, proof); err == nil {
				t.Errorf("(%d, %d) acepta una raíz vieja falsificada", m, n)
			}
			corrupted = append([]byte(nil), newRoot...)
			corrupted[0] ^= 0xff
			if err := VerifyConsistency(m, n, oldRoot, corrupted, proof); err == nil {
				t.Errorf("(%d, %d) acepta una raíz nueva falsificada", m, n)
			}
		}
	}
}

// TestConsistencyRejectsRewrittenHistoryExhaustive reescribe cada hoja del
// prefijo y regenera la prueba desde el árbol falso: nunca debe colar.
func TestConsistencyRejectsRewrittenHistoryExhaustive(t *testing.T) {
	for n := 2; n <= 20; n++ {
		original := merkleTestLeaves(n)
		for m := 1; m < n; m++ {
			oldRoot := Root(original[:m])
			for j := 0; j < m; j++ {
				rewritten := merkleTestLeaves(n)
				rewritten[j] = []byte("rewritten historical leaf")
				proof, err := ConsistencyProof(rewritten, m)
				if err != nil {
					t.Fatal(err)
				}
				if err := VerifyConsistency(m, n, oldRoot, Root(rewritten), proof); err == nil {
					t.Errorf("(%d, %d) acepta la reescritura de la hoja %d", m, n, j)
				}
			}
		}
	}
}

// clonePath copia la prueba en profundidad para poder manipularla sin efectos
// laterales sobre la original.
func clonePath(proof [][]byte) [][]byte {
	out := make([][]byte, len(proof))
	for i := range proof {
		out[i] = append([]byte(nil), proof[i]...)
	}
	return out
}

// TestInclusionRoundTripAllSizes recorre todo árbol hasta 64 hojas y toda hoja,
// que es lo que cubre por completo proofPath y el bucle de VerifyInclusion.
func TestInclusionRoundTripAllSizes(t *testing.T) {
	for n := 1; n <= 64; n++ {
		leaves := merkleTestLeaves(n)
		root := Root(leaves)
		for m := 0; m < n; m++ {
			proof, err := InclusionProof(leaves, m)
			if err != nil {
				t.Fatalf("InclusionProof(%d, %d): %v", m, n, err)
			}
			if err := VerifyInclusion(leaves[m], m, n, proof, root); err != nil {
				t.Errorf("VerifyInclusion(%d, %d) rechaza prueba honesta: %v", m, n, err)
			}
		}
	}
}

// TestInclusionIndexOutOfRange cubre el dominio de índices de ambas funciones.
func TestInclusionIndexOutOfRange(t *testing.T) {
	leaves := merkleTestLeaves(4)
	root := Root(leaves)

	for _, m := range []int{-1, 4, 100} {
		if _, err := InclusionProof(leaves, m); !errors.Is(err, ErrLeafIndex) {
			t.Errorf("InclusionProof(m=%d): err = %v, want %v", m, err, ErrLeafIndex)
		}
	}
	if _, err := InclusionProof(nil, 0); !errors.Is(err, ErrLeafIndex) {
		t.Errorf("InclusionProof(árbol vacío): err = %v, want %v", err, ErrLeafIndex)
	}

	proof, err := InclusionProof(leaves, 1)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		m, n int
	}{
		{"índice negativo", -1, 4},
		{"índice igual al tamaño", 4, 4},
		{"índice mayor que el tamaño", 5, 4},
		{"tamaño cero", 0, 0},
		{"tamaño negativo", 0, -1},
	}
	for _, c := range cases {
		if err := VerifyInclusion(leaves[1], c.m, c.n, proof, root); !errors.Is(err, ErrLeafIndex) {
			t.Errorf("VerifyInclusion %s: err = %v, want %v", c.name, err, ErrLeafIndex)
		}
	}
}

// TestVerifyInclusionRejectsTamperedProof manipula el camino de auditoría, la
// hoja y la raíz: ninguna variante debe colar.
func TestVerifyInclusionRejectsTamperedProof(t *testing.T) {
	for n := 2; n <= 24; n++ {
		leaves := merkleTestLeaves(n)
		root := Root(leaves)
		for m := 0; m < n; m++ {
			proof, err := InclusionProof(leaves, m)
			if err != nil {
				t.Fatal(err)
			}

			for i := range proof {
				mutated := clonePath(proof)
				mutated[i][0] ^= 0xff
				if err := VerifyInclusion(leaves[m], m, n, mutated, root); err == nil {
					t.Errorf("(m=%d, n=%d) acepta prueba con el nodo %d mutado", m, n, i)
				}

				truncated := append(clonePath(proof[:i]), clonePath(proof[i+1:])...)
				if err := VerifyInclusion(leaves[m], m, n, truncated, root); err == nil {
					t.Errorf("(m=%d, n=%d) acepta prueba sin el nodo %d", m, n, i)
				}
			}

			extended := append(clonePath(proof), make([]byte, 32))
			if err := VerifyInclusion(leaves[m], m, n, extended, root); err == nil {
				t.Errorf("(m=%d, n=%d) acepta prueba con un nodo de más", m, n)
			}

			if err := VerifyInclusion([]byte("hoja suplantada"), m, n, proof, root); err == nil {
				t.Errorf("(m=%d, n=%d) acepta una hoja suplantada", m, n)
			}

			corrupted := append([]byte(nil), root...)
			corrupted[0] ^= 0xff
			if err := VerifyInclusion(leaves[m], m, n, proof, corrupted); err == nil {
				t.Errorf("(m=%d, n=%d) acepta una raíz falsificada", m, n)
			}

			// El camino de otra hoja del mismo árbol tampoco debe servir.
			for other := 0; other < n; other++ {
				if other == m {
					continue
				}
				otherProof, err := InclusionProof(leaves, other)
				if err != nil {
					t.Fatal(err)
				}
				if err := VerifyInclusion(leaves[m], m, n, otherProof, root); err == nil {
					t.Errorf("(m=%d, n=%d) acepta el camino de la hoja %d", m, n, other)
				}
			}
		}
	}
}
