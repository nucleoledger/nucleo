package main

// usageText es la ayuda. Se escribe a mano y en español porque es lo primero
// que ve quien no conoce el programa.
func usageText() string {
	return `nucleo — registro con integridad demostrable

USO
  nucleo [--dir D] [--json] <subcomando> [opciones]

SUBCOMANDOS
  init        crea el vault y el ledger, y entrega las tarjetas de respaldo
  seal        sella un registro en el ledger
  status      muestra el estado del ledger y si está atestiguado
  verify      verifica la integridad del ledger  (--full para la exhaustiva)
  receipt     emite el recibo de un bloque para un destinatario
  reconcile   coteja el sistema vivo contra lo sellado
  sync        pide atestación a un testigo
  witness     witness serve — levanta un testigo
  backup      vuelve a emitir las tarjetas SLIP-0039 de la KEK
  restore     reconstruye la KEK desde las tarjetas

BANDERAS GLOBALES
  --dir D     directorio del despliegue (por defecto, el actual)
  --json      salida para máquinas en vez de para personas

CÓDIGOS DE SALIDA
  0  todo correcto
  1  error de uso o de entrada
  2  la verificación falló: hay una alteración o una discrepancia
  3  la sincronización con el testigo falló (incidente operativo)

La passphrase se pide por terminal sin eco. Nunca se pasa por argumento: los
argumentos son visibles en la lista de procesos de toda la máquina.
`
}
