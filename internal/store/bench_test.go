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
//
// Con cosigned, además guarda un checkpoint cosignado sobre TODOS los bloques:
// es el estado en régimen de un ledger con testigo, y el que activa el atajo de
// la enmienda de ADR-009.
func bulkSeed(b *testing.B, path string, blocks []*ledger.Block, cosigned bool) {
	b.Helper()
	s, _, err := Open(path)
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
	if !cosigned {
		return
	}

	leaves := make([][]byte, 0, len(blocks))
	for _, blk := range blocks {
		hb, err := blk.LeafData()
		if err != nil {
			b.Fatal(err)
		}
		leaves = append(leaves, hb)
	}
	_, logPriv := testKeys(b, 7)
	if err := s.PutCheckpoint(cosign(b, uint64(len(blocks)), ledger.Root(leaves), logPriv)); err != nil {
		b.Fatal(err)
	}
}

// benchChain sella n bloques encadenados.
func benchChain(b *testing.B, n int) []*ledger.Block {
	b.Helper()
	return chain(b, n, 0)
}

// BenchmarkOpen mide la apertura de un ledger con testigo: árbol completo
// reconstruido y firmas Ed25519 solo por encima del último checkpoint cosignado,
// que aquí cubre todos los bloques. Es la apertura del caso normal.
//
// La cifra que motivó la enmienda de ADR-009 es la del mismo escenario SIN
// checkpoint cosignado, que mide BenchmarkOpenUnattested.
func BenchmarkOpen(b *testing.B) {
	benchOpen(b, true)
}

// BenchmarkOpenUnattested mide la apertura sin testigo, que verifica todas las
// firmas. Es el camino anterior a la enmienda, y sigue siendo el que se recorre
// mientras nadie haya cosignado.
func BenchmarkOpenUnattested(b *testing.B) {
	benchOpen(b, false)
}

func benchOpen(b *testing.B, cosigned bool) {
	for _, n := range []int{1_000, 10_000, 100_000} {
		blocks := benchChain(b, n)
		b.Run(sizeName(n), func(b *testing.B) {
			path := filepath.Join(b.TempDir(), "nucleo.db")
			bulkSeed(b, path, blocks, cosigned)

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				s, _, err := Open(path)
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
	s, _, err := Open(filepath.Join(b.TempDir(), "nucleo.db"))
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
			bulkSeed(b, path, blocks, false)
			s, _, err := Open(path)
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

// BenchmarkVerifyFull mide la auditoría exhaustiva sobre una base ya abierta:
// es el precio de no aceptar el atajo, y la referencia contra la que se lee la
// mejora de BenchmarkOpen.
func BenchmarkVerifyFull(b *testing.B) {
	for _, n := range []int{1_000, 100_000} {
		blocks := benchChain(b, n)
		b.Run(sizeName(n), func(b *testing.B) {
			path := filepath.Join(b.TempDir(), "nucleo.db")
			bulkSeed(b, path, blocks, true)
			s, _, err := Open(path)
			if err != nil {
				b.Fatal(err)
			}
			defer s.Close()

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := s.VerifyFull(); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
