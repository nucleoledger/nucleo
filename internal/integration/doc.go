// Package integration contiene únicamente tests que cruzan varios paquetes del
// núcleo: ledger, store, vault, checkpoint, witness y proof.
//
// Existe separado porque ninguno de esos paquetes debe depender de los demás
// solo para probarse, y porque la propiedad que aquí se comprueba —que el
// registro sobrevive a un reinicio y sigue siendo demostrablemente el mismo— no
// pertenece a ninguno de ellos en particular, sino a su composición.
package integration
