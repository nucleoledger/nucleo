//go:build testhooks

package store

// SetMetaTxHook fija el gancho que ReplaceMeta llama dentro de su transacción, tras
// cada escritura. Solo existe en un binario de pruebas: la CLI con `testhooks` lo usa
// para matar el proceso a medias de un cambio de passphrase (ADR-029 §C).
func SetMetaTxHook(f func(clave string)) { hookMetaTx = f }
