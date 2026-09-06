package vault

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

// testKEK deriva una KEK real con los parámetros de esta versión. No se inventa
// una clave de 32 bytes cualquiera: lo que hay que respaldar es lo que el vault
// produce.
func testKEK(t *testing.T, passphrase string) []byte {
	t.Helper()
	salt := bytes.Repeat([]byte{0x5a}, SaltLen)
	kek, err := DeriveKEK([]byte(passphrase), DefaultParams(salt))
	if err != nil {
		t.Fatal(err)
	}
	return kek
}

// TestBackupRestoreRoundTrip cubre el camino feliz en su capa final: los shares
// restauran la KEK EXACTA y con ella se desenvuelve una DEK de verdad. Que
// vuelvan 32 bytes no basta; tienen que ser los 32 bytes que abren el vault.
func TestBackupRestoreRoundTrip(t *testing.T) {
	for _, c := range []struct{ n, k int }{{3, 2}, {5, 3}} {
		t.Run(sharesName(c.n, c.k), func(t *testing.T) {
			kek := testKEK(t, "una passphrase larga y aburrida")
			dek := bytes.Repeat([]byte{0x11}, DEKLen)
			const vaultID = "vault-de-prueba"

			wrapped, err := WrapDEK(kek, dek, vaultID)
			if err != nil {
				t.Fatal(err)
			}

			shares, err := BackupKEK(kek, c.n, c.k)
			if err != nil {
				t.Fatal(err)
			}
			if len(shares) != c.n {
				t.Fatalf("BackupKEK devolvió %d shares, want %d", len(shares), c.n)
			}

			// Cualquier subconjunto de tamaño k sirve, no solo el primero.
			for _, subset := range subsets(c.n, c.k) {
				pick := make([]string, 0, c.k)
				for _, i := range subset {
					pick = append(pick, shares[i])
				}
				restored, err := RestoreKEK(pick)
				if err != nil {
					t.Fatalf("shares %v: %v", subset, err)
				}
				if !bytes.Equal(restored, kek) {
					t.Fatalf("shares %v: KEK restaurada = %x, want %x", subset, restored, kek)
				}
				got, err := UnwrapDEK(restored, wrapped, vaultID)
				if err != nil {
					t.Fatalf("shares %v: la KEK restaurada no desenvuelve la DEK: %v", subset, err)
				}
				if !bytes.Equal(got, dek) {
					t.Fatalf("shares %v: DEK = %x, want %x", subset, got, dek)
				}
			}
		})
	}
}

// TestRestoreRejectsMutatedWord es la lección de la semilla silenciosa en su
// capa final: una sola palabra cambiada tiene que FALLAR, nunca devolver otra
// KEK. Con Ed25519 una semilla corrupta produce otra identidad sin avisar; aquí
// el checksum RS1024 de SLIP-0039 lo impide, y se prueba palabra por palabra.
func TestRestoreRejectsMutatedWord(t *testing.T) {
	kek := testKEK(t, "otra passphrase")
	shares, err := BackupKEK(kek, 3, 2)
	if err != nil {
		t.Fatal(err)
	}
	vocabulary := wordsOf(shares)

	words := strings.Fields(shares[0])
	if len(words) < 20 {
		t.Fatalf("el share tiene %d palabras: un mnemónico SLIP-0039 de 256 bits tiene 33", len(words))
	}
	for i := range words {
		mutated := append([]string{}, words...)
		mutated[i] = otherWord(vocabulary, words[i])
		if mutated[i] == words[i] {
			t.Fatalf("no se encontró otra palabra válida para la posición %d", i)
		}

		got, err := RestoreKEK([]string{strings.Join(mutated, " "), shares[1]})
		if err == nil {
			t.Fatalf("palabra %d mutada: RestoreKEK devolvió una KEK (%x) en vez de fallar", i, got)
		}
		if !errors.Is(err, ErrRestore) {
			t.Fatalf("palabra %d mutada: err = %v, want que envuelva a ErrRestore", i, err)
		}
		if got != nil {
			t.Fatalf("palabra %d mutada: se devolvió material además del error: %x", i, got)
		}
	}
}

// TestRestoreRejectsSharesFromDifferentBackups: dos respaldos de la MISMA KEK
// producen shares con identificadores distintos, y mezclarlos no reconstruye
// nada. Es lo que impide que un share viejo, guardado en otro sitio, se cuele en
// una recuperación creyendo que "también vale".
func TestRestoreRejectsSharesFromDifferentBackups(t *testing.T) {
	kek := testKEK(t, "la misma passphrase de siempre")
	first, err := BackupKEK(kek, 3, 2)
	if err != nil {
		t.Fatal(err)
	}
	second, err := BackupKEK(kek, 3, 2)
	if err != nil {
		t.Fatal(err)
	}
	if first[0] == second[0] {
		t.Fatal("dos respaldos produjeron el mismo share: el identificador no es aleatorio")
	}

	got, err := RestoreKEK([]string{first[0], second[1]})
	if err == nil {
		t.Fatalf("se reconstruyó algo (%x) mezclando shares de dos respaldos", got)
	}
	if !errors.Is(err, ErrRestore) {
		t.Errorf("err = %v, want que envuelva a ErrRestore", err)
	}
}

// TestRestoreRejectsInsufficientShares: con k-1 shares no hay reconstrucción.
// Si la hubiera, el umbral sería decorativo.
func TestRestoreRejectsInsufficientShares(t *testing.T) {
	kek := testKEK(t, "passphrase para el umbral")
	shares, err := BackupKEK(kek, 5, 3)
	if err != nil {
		t.Fatal(err)
	}
	for _, pick := range [][]string{
		{shares[0]},
		{shares[0], shares[1]},
		{shares[2], shares[4]},
	} {
		got, err := RestoreKEK(pick)
		if err == nil {
			t.Fatalf("%d shares de 3 reconstruyeron una KEK (%x)", len(pick), got)
		}
		if !errors.Is(err, ErrRestore) {
			t.Errorf("%d shares: err = %v, want que envuelva a ErrRestore", len(pick), err)
		}
	}
	if _, err := RestoreKEK(nil); !errors.Is(err, ErrRestore) {
		t.Errorf("sin shares: err = %v, want ErrRestore", err)
	}
}

// TestBackupRejectsBadParameters cubre las combinaciones que SLIP-0039 no
// admite, incluida la trampa del umbral 1: repartir cinco copias del secreto
// creyendo repartir fragmentos.
func TestBackupRejectsBadParameters(t *testing.T) {
	kek := testKEK(t, "passphrase")
	for _, c := range []struct {
		name string
		n, k int
		want error
	}{
		{"n = 0", 0, 0, ErrShareCount},
		{"n por encima del máximo", 17, 2, ErrShareCount},
		{"k mayor que n", 3, 4, ErrShareCount},
		{"k = 0", 3, 0, ErrShareCount},
		{"umbral 1 con varios shares", 5, 1, ErrShareCount},
	} {
		t.Run(c.name, func(t *testing.T) {
			if _, err := BackupKEK(kek, c.n, c.k); !errors.Is(err, c.want) {
				t.Errorf("err = %v, want %v", err, c.want)
			}
		})
	}
	if _, err := BackupKEK(kek[:16], 3, 2); !errors.Is(err, ErrKeySize) {
		t.Errorf("KEK corta: err = %v, want ErrKeySize", err)
	}
}

// wordsOf recoge el vocabulario que aparece en los shares, para poder sustituir
// una palabra por otra VÁLIDA. Cambiarla por texto cualquiera probaría menos:
// lo que interesa es que el checksum detecte un error plausible de transcripción.
func wordsOf(shares []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range shares {
		for _, w := range strings.Fields(s) {
			if !seen[w] {
				seen[w] = true
				out = append(out, w)
			}
		}
	}
	return out
}

func otherWord(vocabulary []string, current string) string {
	for _, w := range vocabulary {
		if w != current {
			return w
		}
	}
	return current
}

// subsets devuelve todas las combinaciones de k índices de entre n.
func subsets(n, k int) [][]int {
	var out [][]int
	var rec func(start int, acc []int)
	rec = func(start int, acc []int) {
		if len(acc) == k {
			out = append(out, append([]int{}, acc...))
			return
		}
		for i := start; i < n; i++ {
			rec(i+1, append(acc, i))
		}
	}
	rec(0, nil)
	return out
}

func sharesName(n, k int) string {
	return string(rune('0'+k)) + "-de-" + string(rune('0'+n))
}

// TestRestoreKEKProvesConsistencyNotOwnership documenta el contrato completo de
// la restauración, que es el hallazgo BAJO de la auditoría externa.
//
// RestoreKEK prueba la consistencia interna del conjunto de shares, no su
// pertenencia a este vault: un respaldo válido de OTRA KEK se restaura sin un
// solo error, y debe hacerlo, porque matemáticamente es un secreto correcto y
// SLIP-0039 no sabe a qué vault pertenecía. Quien pare ahí y confunda
// "restauró" con "restauró la mía" cifrará bajo una clave equivocada.
//
// El segundo paso es el que prueba la identidad, y falla ruidosamente: el
// envoltorio de la DEK es autenticado y su AAD lleva el identificador del vault.
func TestRestoreKEKProvesConsistencyNotOwnership(t *testing.T) {
	const vaultID = "vault-del-cliente"
	mine := testKEK(t, "la passphrase de este vault")
	other := testKEK(t, "la passphrase de otro vault distinto")
	if bytes.Equal(mine, other) {
		t.Fatal("las dos KEK salieron iguales: el test no probaría nada")
	}

	dek := bytes.Repeat([]byte{0x77}, DEKLen)
	wrapped, err := WrapDEK(mine, dek, vaultID)
	if err != nil {
		t.Fatal(err)
	}

	// Paso 1 con los shares EQUIVOCADOS: restaura sin error, como debe.
	foreign, err := BackupKEK(other, 3, 2)
	if err != nil {
		t.Fatal(err)
	}
	restoredForeign, err := RestoreKEK(foreign[:2])
	if err != nil {
		t.Fatalf("un respaldo válido de otra KEK debe restaurarse sin error: %v", err)
	}
	if !bytes.Equal(restoredForeign, other) {
		t.Fatal("la KEK restaurada no es la que se respaldó")
	}

	// Paso 2: aquí se acaba la ambigüedad.
	if _, err := UnwrapDEK(restoredForeign, wrapped, vaultID); !errors.Is(err, ErrUnwrap) {
		t.Fatalf("la KEK de otro vault desenvolvió la DEK: err = %v, want %v", err, ErrUnwrap)
	}

	// Y el control positivo: los shares correctos superan los dos pasos.
	ours, err := BackupKEK(mine, 3, 2)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := RestoreKEK(ours[:2])
	if err != nil {
		t.Fatal(err)
	}
	got, err := UnwrapDEK(restored, wrapped, vaultID)
	if err != nil {
		t.Fatalf("los shares correctos no desenvolvieron la DEK: %v", err)
	}
	if !bytes.Equal(got, dek) {
		t.Errorf("DEK = %x, want %x", got, dek)
	}

	// La misma KEK tampoco vale para OTRO vault: el AAD lleva el identificador.
	if _, err := UnwrapDEK(restored, wrapped, "otro-vault"); !errors.Is(err, ErrUnwrap) {
		t.Errorf("la DEK se desenvolvió bajo otro identificador de vault: %v", err)
	}
}
