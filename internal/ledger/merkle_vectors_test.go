package ledger

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// Vectores oficiales RFC 6962 leídos de testdata/vectors/merkle/rfc6962. Son
// la verdad compartida entre el core Go y los verificadores de otros lenguajes:
// si un vector falla, el código está mal, no el vector.
const rfc6962VectorDir = "../../testdata/vectors/merkle/rfc6962"

func loadVector(t *testing.T, name string, dst any) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(rfc6962VectorDir, name))
	if err != nil {
		t.Fatalf("no se pudo leer el vector %s: %v", name, err)
	}
	if err := json.Unmarshal(data, dst); err != nil {
		t.Fatalf("vector %s malformado: %v", name, err)
	}
}

func decodeHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex inválido %q: %v", s, err)
	}
	return b
}

// rfc6962Leaves devuelve las ocho hojas canónicas del vector.
func rfc6962Leaves(t *testing.T) [][]byte {
	t.Helper()
	var v struct {
		LeavesHex []string `json:"leaves_hex"`
	}
	loadVector(t, "leaves.json", &v)
	if len(v.LeavesHex) != 8 {
		t.Fatalf("el vector trae %d hojas, se esperaban 8", len(v.LeavesHex))
	}
	leaves := make([][]byte, len(v.LeavesHex))
	for i, s := range v.LeavesHex {
		leaves[i] = decodeHex(t, s)
	}
	return leaves
}

// TestRFC6962RootVectors comprueba MTH(D[n]) para n = 0..8.
func TestRFC6962RootVectors(t *testing.T) {
	leaves := rfc6962Leaves(t)
	var v struct {
		EmptyRootHex string   `json:"empty_root_hex"`
		RootsHex     []string `json:"roots_hex"`
	}
	loadVector(t, "roots.json", &v)

	if got := hex.EncodeToString(Root(nil)); got != v.EmptyRootHex {
		t.Errorf("Root(vacío) = %s, want %s", got, v.EmptyRootHex)
	}
	if len(v.RootsHex) != len(leaves) {
		t.Fatalf("el vector trae %d raíces para %d hojas", len(v.RootsHex), len(leaves))
	}
	for i, want := range v.RootsHex {
		if got := hex.EncodeToString(Root(leaves[:i+1])); got != want {
			t.Errorf("Root(n=%d) = %s, want %s", i+1, got, want)
		}
	}
}

// TestRFC6962ConsistencyVectors comprueba PROOF(m, D[n]) nodo por nodo y que el
// verificador acepta la prueba canónica.
func TestRFC6962ConsistencyVectors(t *testing.T) {
	leaves := rfc6962Leaves(t)
	var v struct {
		Proofs []struct {
			OldSize  int      `json:"old_size"`
			NewSize  int      `json:"new_size"`
			ProofHex []string `json:"proof_hex"`
		} `json:"proofs"`
	}
	loadVector(t, "consistency.json", &v)
	if len(v.Proofs) == 0 {
		t.Fatal("el vector no trae ninguna prueba de consistencia")
	}

	for _, p := range v.Proofs {
		got, err := ConsistencyProof(leaves[:p.NewSize], p.OldSize)
		if err != nil {
			t.Errorf("ConsistencyProof(%d, %d): %v", p.OldSize, p.NewSize, err)
			continue
		}
		if len(got) != len(p.ProofHex) {
			t.Errorf("PROOF(%d, D[%d]) tiene %d nodos, want %d", p.OldSize, p.NewSize, len(got), len(p.ProofHex))
			continue
		}
		for i, want := range p.ProofHex {
			if h := hex.EncodeToString(got[i]); h != want {
				t.Errorf("PROOF(%d, D[%d])[%d] = %s, want %s", p.OldSize, p.NewSize, i, h, want)
			}
		}

		canonical := make([][]byte, len(p.ProofHex))
		for i, s := range p.ProofHex {
			canonical[i] = decodeHex(t, s)
		}
		oldRoot := Root(leaves[:p.OldSize])
		newRoot := Root(leaves[:p.NewSize])
		if err := VerifyConsistency(p.OldSize, p.NewSize, oldRoot, newRoot, canonical); err != nil {
			t.Errorf("VerifyConsistency(%d, %d) rechaza el vector canónico: %v", p.OldSize, p.NewSize, err)
		}
	}
}

// TestRFC6962InclusionVectors comprueba PATH(m, D[n]) nodo por nodo y que el
// verificador reconstruye la raíz canónica desde el camino del vector.
func TestRFC6962InclusionVectors(t *testing.T) {
	leaves := rfc6962Leaves(t)
	var v struct {
		Proofs []struct {
			LeafIndex int      `json:"leaf_index"`
			TreeSize  int      `json:"tree_size"`
			ProofHex  []string `json:"proof_hex"`
		} `json:"proofs"`
	}
	loadVector(t, "inclusion.json", &v)
	if len(v.Proofs) == 0 {
		t.Fatal("el vector no trae ningún camino de inclusión")
	}

	for _, p := range v.Proofs {
		got, err := InclusionProof(leaves[:p.TreeSize], p.LeafIndex)
		if err != nil {
			t.Errorf("InclusionProof(%d, %d): %v", p.LeafIndex, p.TreeSize, err)
			continue
		}
		if len(got) != len(p.ProofHex) {
			t.Errorf("PATH(%d, D[%d]) tiene %d nodos, want %d", p.LeafIndex, p.TreeSize, len(got), len(p.ProofHex))
			continue
		}
		for i, want := range p.ProofHex {
			if h := hex.EncodeToString(got[i]); h != want {
				t.Errorf("PATH(%d, D[%d])[%d] = %s, want %s", p.LeafIndex, p.TreeSize, i, h, want)
			}
		}

		canonical := make([][]byte, len(p.ProofHex))
		for i, s := range p.ProofHex {
			canonical[i] = decodeHex(t, s)
		}
		root := Root(leaves[:p.TreeSize])
		if err := VerifyInclusion(leaves[p.LeafIndex], p.LeafIndex, p.TreeSize, canonical, root); err != nil {
			t.Errorf("VerifyInclusion(%d, %d) rechaza el vector canónico: %v", p.LeafIndex, p.TreeSize, err)
		}
	}
}
