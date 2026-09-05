package store

import (
	"path/filepath"
	"testing"

	"github.com/nucleoledger/nucleo/internal/ledger"
)

// bulkSeed llena la base saltándose AppendBlock, con todas las inserciones en
// una sola transacción. Es legítimo aquí porque lo que se mide es Open, no la
// escritura: con synchronous=FULL cada AppendBlock es un fsync y montar 10^5
// bloques uno a uno tardaría minutos sin aportar nada a la cifra buscada.
func bulkSeed(b *testing.B, path string, blocks []*ledger.Block) {
	b.Helper()
	s, err := Open(path)
	if err != nil {
		b.Fatal(err)
	}
	defer s.Close()

	tx, err := s.db.Begin()
	if err != nil {
		b.Fatal(err)
	}
	stmt, err := tx.Prepare(`INSERT INTO blocks (idx, hash, header_json, signature) VALUES (?, ?, ?, ?)`)
	if err != nil {
		b.Fatal(err)
	}
	for _, blk := range blocks {
		canonical, err := blk.Header.Canonical()
		if err != nil {
			b.Fatal(err)
		}
		if _, err := stmt.Exec(int64(blk.Header.Index), blk.Hash, string(canonical), blk.Signature); err != nil {
			b.Fatal(err)
		}
	}
	if err := stmt.Close(); err != nil {
		b.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		b.Fatal(err)
	}
}

// benchChain sella n bloques encadenados.
func benchChain(b *testing.B, n int) []*ledger.Block {
	b.Helper()
	t := &testing.T{}
	return chain(t, n, 0)
}

// BenchmarkOpen mide la apertura completa, incluida la verificación de
// integridad de todos los bloques y la reconstrucción de la raíz de Merkle.
//
// Es la cifra que decide si hace falta la caché de subárboles diferida en
// ADR-009: el umbral escrito es 5 s en hardware objetivo.
func BenchmarkOpen(b *testing.B) {
	for _, n := range []int{1_000, 10_000, 100_000} {
		blocks := benchChain(b, n)
		b.Run(sizeName(n), func(b *testing.B) {
			path := filepath.Join(b.TempDir(), "nucleo.db")
			bulkSeed(b, path, blocks)

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				s, err := Open(path)
				if err != nil {
					b.Fatal(err)
				}
				if err := s.Close(); err != nil {
					b.Fatal(err)
				}
			}
			b.StopTimer()
			b.ReportMetric(float64(n), "bloques")
		})
	}
}

// BenchmarkAppendBlock mide el sellado DURABLE: con synchronous=FULL cada
// append es un fsync, así que esta cifra —muy por debajo del sellado en
// memoria— es la que manda para dimensionar un caso real.
func BenchmarkAppendBlock(b *testing.B) {
	blocks := benchChain(b, b.N+1)
	s, err := Open(filepath.Join(b.TempDir(), "nucleo.db"))
	if err != nil {
		b.Fatal(err)
	}
	defer s.Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := s.AppendBlock(blocks[i]); err != nil {
			b.Fatal(err)
		}
	}
	b.StopTimer()
	b.ReportMetric(float64(b.N)/b.Elapsed().Seconds(), "bloques/s")
}

// BenchmarkRootReconstruction aísla el coste de recomponer la raíz, sin la
// verificación de firmas, para saber cuál de los dos domina.
func BenchmarkRootReconstruction(b *testing.B) {
	for _, n := range []int{1_000, 100_000} {
		blocks := benchChain(b, n)
		b.Run(sizeName(n), func(b *testing.B) {
			path := filepath.Join(b.TempDir(), "nucleo.db")
			bulkSeed(b, path, blocks)
			s, err := Open(path)
			if err != nil {
				b.Fatal(err)
			}
			defer s.Close()

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := s.Root(); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func sizeName(n int) string {
	switch n {
	case 1_000:
		return "bloques=1e3"
	case 10_000:
		return "bloques=1e4"
	case 100_000:
		return "bloques=1e5"
	}
	return "bloques"
}
