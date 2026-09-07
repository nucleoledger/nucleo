package vault

import (
	"crypto/subtle"
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
		return nil, fmt.Errorf("%w: %w", ErrBackup, err)
	}
	if len(groups) != 1 || len(groups[0]) != n {
		return nil, fmt.Errorf("%w: se pidieron %d shares en 1 grupo y salieron %d grupos",
			ErrBackup, n, len(groups))
	}

	// Condición 1 de ADR-010: no se entregan tarjetas sin verificar.
	if err := verifyRoundTrip(kek, groups[0], k); err != nil {
		return nil, err
	}
	return groups[0], nil
}

// verifyRoundTrip recombina los shares recién generados y comprueba que
// devuelven la KEK original, ANTES de que nadie los vea.
//
// El motivo no es desconfiar de la aritmética de Shamir, es el orden de los
// acontecimientos: estos mnemónicos se imprimen en tarjetas, se reparten entre
// personas y se guardan en cajones durante años. El día que hagan falta, el
// vault ya no se abre por otros medios. Un fallo detectado aquí es un error en
// pantalla; el mismo fallo detectado el día de la recuperación es la KEK
// perdida para siempre. El respaldo se hace una vez por tenant, así que el
// coste de comprobarlo es irrelevante frente a lo que evita.
//
// Se prueban n ventanas de k shares consecutivas y circulares, de modo que
// CADA share participa en al menos una reconstrucción. Verificar un solo
// subconjunto dejaría fuera a los shares que no estuvieran en él: un share
// corrupto entre los no probados pasaría el control y reaparecería años
// después, que es exactamente el fallo que esto existe para impedir.
func verifyRoundTrip(kek []byte, shares []string, k int) error {
	for start := range shares {
		subset := make([]string, 0, k)
		for j := 0; j < k; j++ {
			subset = append(subset, shares[(start+j)%len(shares)])
		}
		got, err := slip39.Combine(subset, nil)
		if err != nil {
			return fmt.Errorf("%w: los shares %d..%d no recombinan: %w",
				ErrBackup, start, start+k-1, err)
		}
		ok := subtle.ConstantTimeCompare(got, kek) == 1
		slip39.ZeroBytes(got)
		if !ok {
			return fmt.Errorf("%w: los shares %d..%d recombinan en OTRA clave",
				ErrBackup, start, start+k-1)
		}
	}
	return nil
}

// RestoreKEK reconstruye la KEK desde k mnemónicos del mismo respaldo.
//
// CONTRATO: RestoreKEK prueba la consistencia INTERNA del conjunto de shares,
// no su pertenencia a este vault. La identidad se prueba desenvolviendo la DEK.
//
// Un conjunto válido de shares de OTRA KEK se restaura sin un solo error, y
// debe hacerlo: matemáticamente es un secreto correcto, y SLIP-0039 no tiene
// forma de saber a qué vault pertenecía. Quien confunda "restauró" con
// "restauró la mía" acabará cifrando bajo una clave equivocada. La restauración
// completa son dos pasos y el segundo no es opcional: RestoreKEK y después
// UnwrapDEK contra la DEK envuelta de este vault, que sí falla ruidosamente
// porque el envoltorio es autenticado y su AAD lleva el identificador del vault.
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
		return nil, fmt.Errorf("%w: %w", ErrRestore, err)
	}
	if len(kek) != int(KeyLen) {
		slip39.ZeroBytes(kek)
		return nil, fmt.Errorf("%w: el secreto recuperado mide %d bytes, la KEK mide %d",
			ErrRestore, len(kek), KeyLen)
	}
	return kek, nil
}
