// Benchmarks de la PoC: velocidad de sellado y tamaño real del recibo.
//
// Va en package ledger_test (paquete de test externo) porque mide el recibo, y
// internal/proof importa internal/ledger: desde dentro del paquete habría ciclo.
package ledger_test

import (
	"crypto/ed25519"
	"fmt"
	"testing"
	"time"

	"github.com/nucleoledger/nucleo/internal/checkpoint"
	"github.com/nucleoledger/nucleo/internal/keys"
	"github.com/nucleoledger/nucleo/internal/ledger"
	"github.com/nucleoledger/nucleo/internal/proof"
	"github.com/nucleoledger/nucleo/internal/witness"
)

const benchTenant = "1790012345001"

func benchSeed(b byte) []byte {
	s := make([]byte, ed25519.SeedSize)
	for i := range s {
		s[i] = b + byte(i)
	}
	return s
}

// BenchmarkSeal mide el sellado completo de un bloque: canonicalización JCS,
// digest SHA-256 y firma Ed25519. Reporta bloques por segundo.
func BenchmarkSeal(b *testing.B) {
	pub, priv, err := keys.Generate()
	if err != nil {
		b.Fatal(err)
	}
	payload := []byte(`<?xml version="1.0"?><autorizacion><numeroAutorizacion>2908202601179001234500110010010000000011234567811</numeroAutorizacion></autorizacion>`)
	t0 := time.Date(2026, 9, 4, 15, 0, 0, 0, time.UTC)

	header, err := ledger.NewHeader(nil, benchTenant, "sri.factura.v1", payload, "blob://c4f3", pub, t0)
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := ledger.Seal(header, priv); err != nil {
			b.Fatal(err)
		}
	}
	b.StopTimer()
	b.ReportMetric(float64(b.N)/b.Elapsed().Seconds(), "bloques/s")
}

// BenchmarkRoot mide el cálculo de la raíz de Merkle sobre árboles grandes.
func BenchmarkRoot(b *testing.B) {
	for _, n := range []int{1_000, 100_000} {
		leaves := benchLeaves(n)
		b.Run(fmt.Sprintf("hojas=%d", n), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				ledger.Root(leaves)
			}
		})
	}
}

// BenchmarkReceipt mide la emisión de un recibo completo y, sobre todo, su
// TAMAÑO en bytes: es la cifra que decide si un recibo cabe en un correo, en un
// PDF o detrás de un QR.
func BenchmarkReceipt(b *testing.B) {
	for _, n := range []int{1_000, 100_000} {
		b.Run(fmt.Sprintf("hojas=%d", n), func(b *testing.B) {
			leaves := benchLeaves(n)
			encoded, path := buildReceipt(b, leaves, n/2)

			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := proof.Parse(encoded); err != nil {
					b.Fatal(err)
				}
			}
			b.StopTimer()
			b.ReportMetric(float64(len(encoded)), "bytes/recibo")
			b.ReportMetric(float64(len(path)), "nodos")
		})
	}
}

// benchLeaves genera hojas de 32 bytes, como los hashes de bloque reales.
func benchLeaves(n int) [][]byte {
	leaves := make([][]byte, n)
	for i := range leaves {
		leaves[i] = ledger.LeafHash([]byte(fmt.Sprintf("bloque-%d", i)))
	}
	return leaves
}

// buildReceipt emite un recibo real: checkpoint firmado, cosignado por un
// testigo, con el camino de inclusión de la entrada index.
func buildReceipt(b *testing.B, leaves [][]byte, index int) ([]byte, [][]byte) {
	b.Helper()
	const origin = "nucleoledger.com/poc"
	const witnessName = "witness.nucleoledger.com/w1"

	logPriv := ed25519.NewKeyFromSeed(benchSeed(0))
	logSigner, err := checkpoint.NewSigner(origin, logPriv)
	if err != nil {
		b.Fatal(err)
	}
	note, err := checkpoint.Sign(checkpoint.Checkpoint{
		Origin: origin, Size: uint64(len(leaves)), RootHash: ledger.Root(leaves),
	}, logSigner)
	if err != nil {
		b.Fatal(err)
	}

	witPriv := ed25519.NewKeyFromSeed(benchSeed(100))
	w, err := witness.New(witnessName, witPriv, func() time.Time { return time.Unix(1_800_000_000, 0) })
	if err != nil {
		b.Fatal(err)
	}
	if err := w.AddLog(origin, logPriv.Public().(ed25519.PublicKey)); err != nil {
		b.Fatal(err)
	}
	cosigned, err := w.Cosign(note, nil)
	if err != nil {
		b.Fatal(err)
	}

	path, err := ledger.InclusionProof(leaves, index)
	if err != nil {
		b.Fatal(err)
	}
	encoded, err := proof.Format(proof.Receipt{
		Index: uint64(index), InclusionProof: path, CheckpointNote: cosigned,
	})
	if err != nil {
		b.Fatal(err)
	}
	return encoded, path
}
