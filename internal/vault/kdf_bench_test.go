package vault

import (
	"bytes"
	"testing"
)

// Benchmarks de la derivación de la passphrase, que es TODO el coste de abrir un
// vault: lo demás —desenvolver la DEK con XChaCha20-Poly1305— son microsegundos.
//
// Existen porque la decisión de ADR-005 (hosting compartido) y los parámetros del
// vault (64 MiB × 4 lanes) se contradicen, y una contradicción así no se resuelve
// opinando: se mide. `go test -bench=KDF -benchmem ./internal/vault` da el tiempo
// y, sobre todo, la memoria, que es la cifra que decide si un plan compartido
// mata el proceso.
//
//	go test -bench=KDF -benchmem ./internal/vault

func benchProfile(b *testing.B, profile KDFProfile) {
	b.Helper()
	pass := []byte("correcta caballo bateria grapa")
	salt := bytes.Repeat([]byte{9}, SaltLen)
	p, err := ParamsFor(profile, salt)
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for b.Loop() {
		kek, err := DeriveKEK(pass, p)
		if err != nil {
			b.Fatal(err)
		}
		zero(kek)
	}
}

func BenchmarkKDFDefault(b *testing.B)     { benchProfile(b, ProfileDefault) }
func BenchmarkKDFConstrained(b *testing.B) { benchProfile(b, ProfileConstrained) }

// BenchmarkKDFUnlockCompleto mide la operación que de verdad hace la CLI en cada
// invocación que toca el vault: abrir. Es la cifra que alguien nota al teclear.
func benchUnlock(b *testing.B, profile KDFProfile) {
	b.Helper()
	pass := []byte("correcta caballo bateria grapa")
	ms := newMemStore()
	v, err := CreateWithProfile(ms, "log/bench", pass, profile)
	if err != nil {
		b.Fatal(err)
	}
	v.Close()
	b.ResetTimer()
	for b.Loop() {
		u, err := Unlock(ms, pass)
		if err != nil {
			b.Fatal(err)
		}
		u.Close()
	}
}

func BenchmarkUnlockDefault(b *testing.B)     { benchUnlock(b, ProfileDefault) }
func BenchmarkUnlockConstrained(b *testing.B) { benchUnlock(b, ProfileConstrained) }
