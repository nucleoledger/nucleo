package ledger

import "testing"

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
