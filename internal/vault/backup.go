package vault

import (
	"errors"
	"fmt"

	slip39 "github.com/shurlinet/go-slip39"
)

// ESTE ES EL ÚNICO FICHERO DEL REPOSITORIO QUE IMPORTA LA BIBLIOTECA SLIP-0039.
//
// La condición con la que se aprobó la dependencia (ADR-010) es el aislamiento:
// el resto del proyecto ve BackupKEK y RestoreKEK, nunca los tipos de la
// biblioteca. Si mañana hay que reemplazarla —es una v0.1.0, y su autor declara
// código generado por IA con revisión humana— se reescribe este fichero y nada
// más. TestSlip39StaysBehindTheVault vigila que siga siendo verdad.

// MaxShares es el máximo de shares por grupo que admite SLIP-0039.
const MaxShares = 16

var (
	// ErrShareCount indica una combinación (n, k) que SLIP-0039 no admite.
	ErrShareCount = errors.New("vault: número de shares inválido")
	// ErrBackup indica que no se pudo generar el respaldo.
	ErrBackup = errors.New("vault: no se pudo respaldar la KEK")
	// ErrRestore indica que los shares no reconstruyen una KEK. Nunca devuelve
	// "otra" clave: el checksum RS1024 y el digest de SLIP-0039 fallan ruidosamente.
	ErrRestore = errors.New("vault: no se pudo restaurar la KEK")
)

// BackupKEK parte la KEK en n mnemónicos de los que hacen falta k para
// reconstruirla (SLIP-0039, un solo grupo).
//
// No lleva passphrase. Añadirle una devolvería al respaldo el punto único de
// fallo que el reparto existe para eliminar: quien pierde la passphrase pierde
// la KEK aunque conserve los n shares. La protección aquí es el umbral, y el
// secreto son los propios mnemónicos.
//
// Cada llamada produce shares DISTINTOS aunque la KEK sea la misma: el
// identificador y los coeficientes del polinomio son aleatorios. Shares de dos
// respaldos distintos no se combinan entre sí, y eso es deliberado.
func BackupKEK(kek []byte, n, k int) ([]string, error) {
	if len(kek) != int(KeyLen) {
		return nil, fmt.Errorf("%w: KEK de %d bytes, se esperaban %d", ErrKeySize, len(kek), KeyLen)
	}
	if n < 1 || n > MaxShares {
		return nil, fmt.Errorf("%w: n = %d, debe estar entre 1 y %d", ErrShareCount, n, MaxShares)
	}
	if k < 1 || k > n {
		return nil, fmt.Errorf("%w: k = %d con n = %d", ErrShareCount, k, n)
	}
	// Regla del propio SLIP-0039: con umbral 1 no hay reparto que valga, así
	// que solo se admite un share. Permitir 1-de-5 repartiría cinco copias del
	// secreto creyendo estar repartiendo fragmentos.
	if k == 1 && n > 1 {
		return nil, fmt.Errorf("%w: un umbral de 1 exige un solo share, se pidieron %d", ErrShareCount, n)
	}

	groups, err := slip39.Split(kek, nil,
		slip39.WithGroupThreshold(1),
		slip39.WithGroups([]slip39.Group{{Threshold: k, Count: n}}),
	)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBackup, err)
	}
	if len(groups) != 1 || len(groups[0]) != n {
		return nil, fmt.Errorf("%w: se pidieron %d shares en 1 grupo y salieron %d grupos",
			ErrBackup, n, len(groups))
	}
	return groups[0], nil
}

// RestoreKEK reconstruye la KEK desde k mnemónicos del mismo respaldo.
//
// Falla ruidosamente ante cualquier desviación —una palabra cambiada, shares de
// respaldos distintos, menos de k— porque SLIP-0039 lleva checksum RS1024 en
// cada mnemónico y un digest sobre el secreto reconstruido. Es la misma lección
// que UnwrapDEK: un respaldo corrupto tiene que gritar, no entregar otra clave
// con la que se cifrarían datos irrecuperables.
func RestoreKEK(mnemonics []string) ([]byte, error) {
	if len(mnemonics) == 0 {
		return nil, fmt.Errorf("%w: no se dieron shares", ErrRestore)
	}
	kek, err := slip39.Combine(mnemonics, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrRestore, err)
	}
	if len(kek) != int(KeyLen) {
		slip39.ZeroBytes(kek)
		return nil, fmt.Errorf("%w: el secreto recuperado mide %d bytes, la KEK mide %d",
			ErrRestore, len(kek), KeyLen)
	}
	return kek, nil
}
