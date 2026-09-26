package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/url"
	"runtime"
	"strings"

	"github.com/nucleoledger/nucleo/internal/witness"
)

// Los fallos del testigo, dichos para un operador.
//
// Del ensayo de operación del Sprint 10, escenario 3: nueve formas de que un testigo se
// porte mal —caído, URL con typo, 404, 500, basura, la conexión cortada a medias, sin
// contestar—. Todas terminaban con el código correcto (3) y dejaban el sistema utilizable,
// que era lo importante. Lo que no estaba bien era el mensaje:
//
//	error: witness: checkpoint de "nucleoledger.com/mi-empresa": Get "http://127.0.0.1:
//	18999/c65397b04d875cc205ed905c64c7dddf5a29d9505d799f168825499c37b1aab1/checkpoint":
//	dial tcp 127.0.0.1:18999: connect: connection refused
//
// Ahí hay un hash de 64 caracteres, la forma de un error de la biblioteca de red de Go y
// ni una palabra sobre qué mirar. Y el peor de los nueve era el typo más común —olvidar
// el http:// — que contestaba "first path segment in URL cannot contain colon" y salía
// con 3, como si el testigo tuviera la culpa de una errata nuestra.
//
// Esto no reescribe el error: le pone delante una frase que dice qué pasó y qué hacer, y
// deja el detalle técnico debajo, que es donde sirve.

// validaURLDeTestigo comprueba la URL ANTES de tocar la red.
//
// Devuelve un error de USO (código 1) porque una URL mal escrita es una errata de quien
// invoca, no un incidente del testigo, y mezclarlas hace que un cron que reintenta ante
// el código 3 reintente para siempre una URL que nunca va a funcionar.
func validaURLDeTestigo(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return usageErr("la URL del testigo no se entiende: %q.\n"+
			"  Tiene que ser una URL completa, con esquema: http://host:puerto o https://host", raw)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		falta := ""
		if u.Scheme == "" || !strings.Contains(raw, "//") {
			falta = "\n  Parece que falta el http:// del principio."
		}
		return usageErr("la URL del testigo tiene que empezar por http:// o https://, y esta es %q.%s", raw, falta)
	}
	if u.Host == "" {
		return usageErr("la URL del testigo no trae host: %q", raw)
	}
	return nil
}

// errorDeTestigo traduce el fallo a algo accionable, conservando el detalle.
func errorDeTestigo(u string, err error) *exitError {
	frase, consejo, clase := clasificaFalloDeTestigo(u, err)
	if frase == "" {
		return syncErr("%v", err)
	}
	return syncErr("%s\n  %s\n  Detalle técnico: %v", frase, consejo, err).conClase(clase)
}

// clasificaFalloDeTestigo devuelve la frase, el consejo y la clase (ADR-027), o
// "" si no sabe clasificarlo.
//
// La clase no se deduce del código de salida y aquí se ve por qué: los nueve
// fallos del ensayo salen todos con 3, y la mitad se arreglan esperando mientras
// la otra mitad no se arreglan nunca sin que alguien cambie algo. Un cron que
// reintenta ante un 3 reintentaría para siempre contra un testigo cuya clave no
// es la de la política.
func clasificaFalloDeTestigo(u string, err error) (frase, consejo, clase string) {
	// 1. El testigo contestó, pero con un código que no esperábamos.
	var he *witness.HTTPError
	if errors.As(err, &he) {
		switch {
		case he.Status == 404:
			return fmt.Sprintf("el testigo %s contestó 404: ahí no hay lo que se le pidió", u),
				"Comprueba la URL, y que ESE testigo sirva a ESTE log: un testigo solo responde por los origins que tiene configurados.",
				claseEntorno
		case he.Status == 401 || he.Status == 403:
			return fmt.Sprintf("el testigo %s rechazó la petición (HTTP %d)", u, he.Status),
				"El testigo pide autorización o no acepta a este log. Es cosa de quien lo opera.",
				claseEntorno
		case he.Status == 429:
			return fmt.Sprintf("el testigo %s dice que le estás pidiendo demasiado (HTTP 429)", u),
				"Espacia las sincronizaciones; con una por hora sobra para un despliegue normal.",
				claseTransitoria
		case he.Status >= 500:
			return fmt.Sprintf("el testigo %s tuvo un error interno (HTTP %d)", u, he.Status),
				"No es problema de este ledger ni de este fichero: reintenta más tarde, y si sigue, avisa a quien opera el testigo.",
				claseTransitoria
		default:
			return fmt.Sprintf("el testigo %s contestó HTTP %d, que no es una respuesta del protocolo", u, he.Status),
				"Comprueba que la URL apunta a un testigo de Núcleo y no a otra cosa —un proxy, un portal cautivo, una web—.",
				claseEntorno
		}
	}

	// 1b. Contestó, y su certificado TLS no se acepta. Va ANTES que los fallos de red:
	// el error de TLS también es un *net.OpError y caería en "no se pudo conectar", con un
	// consejo —el cortafuegos, que esté levantado— que no tiene nada que ver. Salió al
	// comprobar la guía de operación con el testigo detrás de Caddy (Sprint 12).
	if frase, consejo, ok := falloDeCertificado(u, err); ok {
		return frase, consejo, claseEntorno
	}

	// 2. No contestó a tiempo.
	if errors.Is(err, context.DeadlineExceeded) || esTimeout(err) {
		return fmt.Sprintf("el testigo %s no contestó dentro del tiempo de espera", u),
			"Si tarda siempre, súbelo con --timeout; si no debería tardar, mira la red y la carga del testigo. No se escribió nada.",
			claseTransitoria
	}

	// 3. No se pudo llegar.
	var oe *net.OpError
	var de *net.DNSError
	switch {
	case errors.As(err, &de):
		return fmt.Sprintf("no se encontró el host del testigo %s", u),
			"Comprueba el nombre en la URL y el DNS de esta máquina.",
			claseEntorno
	case errors.As(err, &oe):
		return fmt.Sprintf("no se pudo conectar con el testigo %s", u),
			"Comprueba que está levantado, que el puerto es ese y que ningún cortafuegos lo tapa.",
			claseTransitoria
	}

	// 4. Contestó algo, pero no era una nota firmada.
	if strings.Contains(err.Error(), "cosignature") || strings.Contains(err.Error(), "malformed note") {
		return fmt.Sprintf("lo que contestó %s no es una cosignature válida de ese testigo", u),
			"O la URL no es de un testigo de Núcleo, o la clave que traes en la política no es la suya. Esto NO se arregla reintentando.",
			claseEntorno
	}

	// 5. Cortó la conexión a medias.
	if errors.Is(err, net.ErrClosed) || strings.Contains(err.Error(), "EOF") {
		return fmt.Sprintf("el testigo %s cortó la conexión antes de terminar de contestar", u),
			"Suele ser el testigo reiniciándose o un proxy en medio. No se escribió nada: reintenta.",
			claseTransitoria
	}
	return "", "", ""
}

// esTimeout reconoce los tiempos agotados de la biblioteca de red.
func esTimeout(err error) bool {
	var t interface{ Timeout() bool }
	return errors.As(err, &t) && t.Timeout()
}

// falloDeCertificado reconoce un certificado TLS del testigo que esta máquina no acepta.
//
// Es de entorno y no transitorio: reintentar da lo mismo hasta que alguien toque la
// configuración de uno de los dos lados.
func falloDeCertificado(u string, err error) (frase, consejo string, ok bool) {
	var (
		desconocida x509.UnknownAuthorityError
		nombre      x509.HostnameError
		invalido    x509.CertificateInvalidError
		verif       *tls.CertificateVerificationError
	)
	switch {
	case errors.As(err, &nombre):
		return fmt.Sprintf("el certificado TLS del testigo %s es de otro nombre", u),
			"La URL tiene que usar el nombre para el que se emitió el certificado; comprueba el host de --witness y el de la política.",
			true
	case errors.As(err, &invalido) && invalido.Reason == x509.Expired:
		return fmt.Sprintf("el certificado TLS del testigo %s está caducado o todavía no es válido", u),
			"Mira la hora de esta máquina —un reloj desplazado hace inválido un certificado bueno— y, si está bien, la renovación del certificado del testigo.",
			true
	case errors.As(err, &desconocida) ||
		errors.As(err, &invalido) ||
		(errors.As(err, &verif) && verif != nil):
		return fmt.Sprintf("el certificado TLS del testigo %s lo firmó una autoridad que esta máquina no reconoce", u),
			consejoDeAutoridad(),
			true
	}
	return "", "", false
}

// consejoDeAutoridad depende del sistema, porque cada uno busca las raíces en un sitio y
// un consejo que no funciona donde se imprime es peor que ninguno (CLAUDE.md).
func consejoDeAutoridad() string {
	switch runtime.GOOS {
	case "linux":
		// SSL_CERT_FILE: comprobado en la guía de operación con la CA interna de Caddy.
		return "Si el testigo usa un certificado de una CA propia, apunta SSL_CERT_FILE al certificado raíz de esa CA al ejecutar nucleo, o añádelo al almacén del sistema (update-ca-certificates). Si es de una CA pública, al almacén de esta máquina le faltan raíces: instala o actualiza el paquete ca-certificates."
	default:
		return "Si el testigo usa un certificado de una CA propia, añade su certificado raíz al almacén de certificados del sistema. Si es de una CA pública, el almacén de esta máquina está incompleto o desactualizado."
	}
}
