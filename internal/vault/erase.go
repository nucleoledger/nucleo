package vault

// BlobEraser es lo que EraseBlob necesita de la persistencia.
type BlobEraser interface {
	DeleteBlob(payloadHash string) error
}

// EraseBlob borra un payload cifrado y deja el ledger intacto.
//
// Esto ES el cumplimiento de la LOPDP por construcción, no una función de
// conveniencia: el dato personal desaparece del disco, mientras el compromiso
// que prueba qué se selló y cuándo permanece en la cadena. Tras el borrado, la
// cadena sigue verificando y el recibo de ese bloque sigue siendo válido, porque
// nada de lo que demuestran dependía del contenido en claro.
func EraseBlob(be BlobEraser, payloadHash string) error {
	return be.DeleteBlob(payloadHash)
}
