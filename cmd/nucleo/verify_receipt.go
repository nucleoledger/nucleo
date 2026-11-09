package main

import (
	"errors"
	"flag"
	"fmt"
	"strings"
	"time"

	"github.com/nucleoledger/nucleo/internal/proof"
	"github.com/nucleoledger/nucleo/internal/receipt"
)

// verify-receipt verifica un recibo AJENO, offline (ADR-034, decisión 8): no abre ningún
// ledger, no pide passphrase y no usa la red. Es internal/receipt —Parse y Verify— con la
// política del fichero, el mismo código con el que `receipt` se autoverifica.
//
// Es el sitio donde una contraparte comprueba la firma post-cuántica del log: con una
// política que fija logMLDSAKey, el resultado es "verified" o el recibo no vale. Los SDK
// de TypeScript y de PHP y la página no implementan ML-DSA-44 (ADR-034, decisión 5).

// maxReceiptSize es el tamaño máximo del fichero del recibo. Un recibo con cien líneas de
// firma ML-DSA-44 —el máximo de PROTOCOL §3.3— mide unos 330 KB; un mebibyte deja margen
// sin dejar que un fichero cualquiera se lea entero en memoria.
const maxReceiptSize = 1 << 20

func cmdVerifyReceipt(e *env, args []string) error {
	fs := flag.NewFlagSet("verify-receipt", flag.ContinueOnError)
	fs.SetOutput(e.stderr)
	recibo := fs.String("receipt", "", "fichero con el recibo")
	politica := &optString{}
	fs.Var(politica, "policy-file", "fichero JSON con la política del emisor (origin, logKey, signerKey, witnesses, quorum, y logMLDSAKey si la fija)")
	if err := fs.Parse(args); err != nil {
		return usageErr("%v", err)
	}
	if fs.NArg() > 0 {
		return usageErr("verify-receipt no admite argumentos sueltos (%q): el recibo va en --receipt", fs.Arg(0))
	}
	if *recibo == "" {
		return usageErr("verify-receipt necesita --receipt FICHERO")
	}
	if !politica.set || politica.v == "" {
		return usageErr("verify-receipt necesita --policy-file POLITICA: sin la política no hay contra qué\n" +
			"  verificar —qué log, qué emisor, qué testigos—. Te la da el emisor, por un medio en el que\n" +
			"  confíes (ADR-017)")
	}
	f, err := loadPolicyFile(e, politica.v)
	if err != nil {
		return err
	}
	pol := f.ProofPolicy()
	if err := pol.RequireSignerKey(); err != nil {
		return usageErr("la política %q no trae signerKey, la clave del emisor: sin ella el recibo podría ser\n"+
			"  de cualquiera (ADR-017). Pídesela al emisor: `nucleo sync` la imprime en su política", politica.v)
	}
	data, err := readLimited(*recibo, maxReceiptSize, "el recibo")
	if err != nil {
		return err
	}

	r, err := receipt.Parse(data, pol)
	var res proof.Result
	if err == nil {
		res, err = r.Verify(pol)
	}
	if err != nil {
		motivo := motivoDeRecibo(err)
		e.out(map[string]any{
			"ok":                      false,
			"valid":                   false,
			"reasons":                 []string{motivo},
			"error":                   err.Error(),
			"logMLDSA":                nil,
			"declaredTime":            nil,
			"provableTime":            nil,
			"blockIndex":              nil,
			"recipient":               nil,
			"signerPubKey":            nil,
			"cosigners":               []string{},
			"ignoredSignatures":       []string{},
			"logAdditionalSignatures": 0,
			"checkpoint":              nil,
		}, func() {
			e.printf("✘ el recibo NO vale: %s\n", motivo)
			e.printf("  detalle técnico: %v\n", err)
		})
		return &exitError{code: exitVerify, err: fmt.Errorf("el recibo no vale: %w", err), reported: true}
	}

	var provable any
	if len(res.Cosigners) > 0 {
		provable = res.ProvableTime.UTC().Format(time.RFC3339)
	}
	cosigners := res.Cosigners
	if cosigners == nil {
		cosigners = []string{}
	}
	ignoradas := res.IgnoredSigs
	if ignoradas == nil {
		ignoradas = []string{}
	}
	e.out(map[string]any{
		"valid":                   true,
		"reasons":                 []string{},
		"logMLDSA":                res.LogMLDSA,
		"declaredTime":            r.Header.Timestamp,
		"provableTime":            provable,
		"blockIndex":              r.Header.Index,
		"recipient":               r.Recipient,
		"signerPubKey":            r.Header.SignerPubKey,
		"cosigners":               cosigners,
		"ignoredSignatures":       ignoradas,
		"logAdditionalSignatures": len(res.LogExtraSigs),
		"checkpoint": map[string]any{
			"origin":   res.Checkpoint.Origin,
			"size":     res.Checkpoint.Size,
			"rootHash": fmt.Sprintf("%x", res.Checkpoint.RootHash),
		},
	}, func() {
		e.printf("✔ el recibo vale\n")
		e.printf("  registro          : bloque %d del log %s (tipo %s)\n", r.Header.Index, res.Checkpoint.Origin, r.Header.Type)
		e.printf("  destinatario      : %s (lo escribe y lo firma el emisor; no prueba la entrega)\n", r.Recipient)
		e.printf("  tiempo declarado  : %s (lo pone el emisor; no prueba nada)\n", r.Header.Timestamp)
		if provable != nil {
			e.printf("  tiempo demostrable: %s (testigos: %s)\n", provable, strings.Join(res.Cosigners, ", "))
		}
		e.printf("  firma ML-DSA-44   : %s\n", textoLogMLDSA(res.LogMLDSA))
	})
	return nil
}

// textoLogMLDSA dice qué se sabe de la firma post-cuántica del log, con el motivo cuando
// no se verificó (ADR-034 §D).
func textoLogMLDSA(estado string) string {
	switch estado {
	case proof.LogMLDSAVerified:
		return "verificada con la clave de la política (la firma post-cuántica del log)"
	case proof.LogMLDSAPresentUnverified:
		return "presente, NO verificada (la política no fija su clave: logMLDSAKey)"
	default:
		return "ausente (el checkpoint no la trae)"
	}
}

// motivoDeRecibo traduce el error de la verificación a una frase para quien no es
// criptógrafo: qué significa que no valga, no qué función falló (la regla de los
// mensajes). El detalle técnico va aparte.
func motivoDeRecibo(err error) string {
	switch {
	case errors.Is(err, proof.ErrMLDSAMissing):
		return "tu política exige la firma post-cuántica del log (logMLDSAKey) y el recibo no la trae"
	case errors.Is(err, proof.ErrMLDSASignature):
		return "la firma post-cuántica del log no es la de la clave que fija tu política: el resumen del log que respalda el recibo se alteró, o lo firmó otro"
	case errors.Is(err, receipt.ErrUnexpectedSigner):
		return "el registro lo firmó una clave distinta de la del emisor que fija tu política: no es de quien crees"
	case errors.Is(err, receipt.ErrTextMismatch):
		return "el texto del recibo no coincide con lo que demuestra: alguien lo editó después de emitirlo"
	case errors.Is(err, receipt.ErrReceiptSignature), errors.Is(err, receipt.ErrNoReceiptSignature):
		return "la firma del emisor sobre el recibo no verifica: el recibo se modificó después de firmarlo (por ejemplo, el destinatario)"
	case errors.Is(err, receipt.ErrBlockSignature):
		return "la firma del registro no verifica: lo sellado se modificó"
	case errors.Is(err, proof.ErrInclusion), errors.Is(err, proof.ErrIndex), errors.Is(err, receipt.ErrIndexMismatch):
		return "el registro no está donde el recibo dice dentro del log: el recibo se alteró o mezcla dos registros"
	case errors.Is(err, proof.ErrQuorum):
		return "no lo avalan suficientes testigos de tu política: falta la prueba de que un tercero vio el log"
	case errors.Is(err, proof.ErrSignature):
		return "una firma de una clave de tu política no verifica: el recibo se alteró"
	case errors.Is(err, proof.ErrOrigin):
		return "el recibo es de otro log, o el log no lo firmó con la clave de tu política"
	case errors.Is(err, proof.ErrPolicy):
		return "la política no sirve para verificar este recibo"
	case errors.Is(err, receipt.ErrFormat), errors.Is(err, proof.ErrFormat):
		return "el fichero no es un recibo de Núcleo entero: está cortado, editado o es otra cosa"
	}
	return "el recibo no verifica con tu política: alguna de sus pruebas no cuadra"
}
