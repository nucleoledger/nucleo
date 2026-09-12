package store

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/nucleoledger/nucleo/internal/checkpoint"
	"github.com/nucleoledger/nucleo/internal/ledger"
	"github.com/nucleoledger/nucleo/internal/proof"
)

// ErrIntegrity indica que la base no es coherente consigo misma.
var ErrIntegrity = errors.New("store: verificación de integridad fallida")

// IntegrityError nombra el bloque implicado y la fase en que se detectó el
// problema. Nombrar el bloque no es un lujo: cuando alguien manipula el fichero,
// lo primero que hay que saber es DÓNDE se rompió la historia.
type IntegrityError struct {
	// Stage describe qué comprobación falló.
	Stage string
	// Index es el bloque implicado, o -1 si el fallo no es de un bloque concreto.
	Index int64
	// Err es la causa.
	Err error
}

func (e *IntegrityError) Error() string {
	if e.Index < 0 {
		return fmt.Sprintf("%v: %s: %v", ErrIntegrity, e.Stage, e.Err)
	}
	return fmt.Sprintf("%v: %s: bloque %d: %v", ErrIntegrity, e.Stage, e.Index, e.Err)
}

// Is permite compararlo con ErrIntegrity mediante errors.Is.
func (e *IntegrityError) Is(target error) bool { return target == ErrIntegrity }

// Unwrap expone la causa concreta.
func (e *IntegrityError) Unwrap() error { return e.Err }

// verifyMode elige cuánta criptografía se recomputa al recorrer la base.
type verifyMode int

const (
	// modeAttested verifica las firmas Ed25519 solo de los bloques posteriores
	// al último checkpoint cosignado. Es el modo de la apertura.
	modeAttested verifyMode = iota
	// modeFull verifica la firma de todos los bloques. Es el modo de auditoría.
	modeFull
)

// OpenResult describe qué respalda la historia que se acaba de verificar.
//
// Existe porque "la base abrió bien" son dos afirmaciones muy distintas según
// haya o no un testigo detrás, y confundirlas es peligroso. Una cadena
// localmente válida puede ser un PREFIJO de la historia real: quien controle el
// fichero puede borrar los disparadores, borrar la tabla de checkpoints y
// truncar los bloques a un prefijo que encadena y verifica perfectamente. Nada
// dentro del fichero puede desmentirlo, porque el fichero entero es suyo. Lo
// único que lo desmiente es la memoria de un testigo que cosignó una raíz más
// grande.
//
// Por eso Attested viaja en el resultado de Open en vez de quedarse implícito:
// una apertura NO atestiguada es legítima —un ledger recién creado lo es— pero
// quien la reciba tiene que poder decirlo en voz alta.
type OpenResult struct {
	// TreeSize es el número de bloques persistidos.
	TreeSize uint64
	// Attestation dice qué respalda la historia. Ver Attestation.
	Attestation Attestation
	// AttestedSize es el tamaño de árbol que cubre el checkpoint considerado, o 0
	// si no hay ninguno. Con Attestation == AttestationUnverified es lo que el
	// checkpoint AFIRMA, no lo que se ha comprobado.
	AttestedSize uint64
	// Reason explica, cuando Attestation no es Verified pero había un checkpoint,
	// por qué no se pudo verificar: sin política, o política que no cuadra.
	Reason string
	// Signer dice qué se sabe del firmante de los bloques (ADR-017).
	Signer SignerState
	// SignerKey es la clave, en hex, que firma TODA la cadena (la del bloque 0; la
	// continuidad garantiza que es la misma en todos). Vacía si no hay bloques.
	SignerKey string
}

// SignerState es lo que la apertura puede afirmar del firmante de bloques.
//
// La continuidad —todos los bloques firmados por la MISMA clave— se comprueba
// siempre y no es un estado: si falla, la apertura falla. Lo que varía es la
// identidad: si esa clave única es la que quien abre esperaba.
type SignerState int

const (
	// SignerNone: no hay bloques, no hay firmante.
	SignerNone SignerState = iota
	// SignerUnverified: la cadena la firma una sola clave, pero nadie aportó una
	// política que diga cuál tenía que ser. Una cadena reescrita ENTERA por otra
	// clave, autoconsistente, está exactamente en este estado.
	SignerUnverified
	// SignerVerified: la clave única coincide con la que fija la política.
	SignerVerified
)

// String nombra el estado, también para --json.
func (st SignerState) String() string {
	switch st {
	case SignerVerified:
		return "verified"
	case SignerUnverified:
		return "unverified"
	default:
		return "none"
	}
}

// ErrSignerContinuity indica que la cadena cambia de firmante: un bloque no está
// firmado por la misma clave que los anteriores. No hay rotación de la clave del
// tenant, así que solo tiene una lectura.
var ErrSignerContinuity = errors.New("store: la cadena cambia de firmante")

// ErrSignerMismatch indica que la clave que firma la cadena no es la que la
// política espera: una reescritura total autoconsistente, o una política de otro
// ledger.
var ErrSignerMismatch = errors.New("store: el firmante de la cadena no es el que la política espera")

// ErrLogKeyMismatch indica que la clave del log de la política no es la que
// vault_meta declara: alguien sustituyó una de las dos.
var ErrLogKeyMismatch = errors.New("store: la clave del log de la política no coincide con la que declara el ledger")

// Attestation es el estado de la atestación al abrir (ADR-016).
//
// Era un booleano, y el booleano mentía: "hay una nota con una línea de 76 bytes"
// se reportaba como "un tercero avala esta historia", y la auditoría adversarial
// escribió esa nota a mano. Ahora hay tres estados, y solo el tercero autoriza el
// atajo de ADR-009.
type Attestation int

const (
	// AttestationNone: no hay ningún checkpoint con forma de cosignado.
	AttestationNone Attestation = iota
	// AttestationUnverified: hay un checkpoint cosignado, su firma de log verifica
	// con la clave de vault_meta, pero NO se aportó política de testigos (o la que
	// se aportó no cuadra). No se sabe si un tercero lo avala. Sin atajo.
	AttestationUnverified
	// AttestationVerified: firma de log Y cosignatures verificadas bajo la política
	// que aportó quien abre. Es la única lectura que autoriza el atajo.
	AttestationVerified
)

// String nombra el estado, también para --json.
func (a Attestation) String() string {
	switch a {
	case AttestationVerified:
		return "verified"
	case AttestationUnverified:
		return "unverified"
	default:
		return "none"
	}
}

// Attested dice si la historia está atestiguada, en el único sentido que ahora
// tiene esa palabra: VERIFICADA.
func (r OpenResult) Attested() bool { return r.Attestation == AttestationVerified }

// String describe el estado en una línea, para logs y CLI.
func (r OpenResult) String() string {
	switch r.Attestation {
	case AttestationVerified:
		return fmt.Sprintf("historia atestiguada hasta %d de %d bloques", r.AttestedSize, r.TreeSize)
	case AttestationUnverified:
		return fmt.Sprintf("checkpoint presente (%d bloques) pero NO verificado: %s", r.AttestedSize, r.Reason)
	default:
		return fmt.Sprintf("SIN ATESTIGUAR: %d bloques, cadena localmente válida, historia completa no garantizada", r.TreeSize)
	}
}

// WitnessPolicy es lo que quien abre aporta desde FUERA del fichero: qué testigos
// acepta y cuántos hacen falta. El origin y la clave del log los pone el propio
// almacén desde vault_meta; ver ADR-016 sobre por qué eso solo no basta.
type WitnessPolicy struct {
	Witnesses map[string]ed25519.PublicKey
	Quorum    int
	// SignerKey es la clave esperada del firmante de bloques (ADR-017). Opcional al
	// abrir: sin ella la continuidad se comprueba igual, pero la IDENTIDAD del
	// firmante queda "no verificada" y el resultado lo dice.
	SignerKey ed25519.PublicKey
	// LogKey, si se aporta, tiene que coincidir con la que vault_meta declara. Es
	// la capa que detecta la sustitución de la clave del log que ADR-016 describió.
	LogKey ed25519.PublicKey
}

// ErrPolicy indica una política de apertura que no puede verificar nada.
var ErrPolicy = errors.New("store: política de testigos inválida")

// validate rechaza una política que no exige NINGUNA cosignature. Es la frontera
// que la segunda auditoría adversarial encontró abierta: OpenWithWitnesses con
// WitnessPolicy{} —o con testigos y quórum 0— devolvía "verified" sobre un
// ledger forjado, porque proof.Policy admite quórum 0 (correcto para un recibo
// sin tiempo demostrable) y el almacén lo heredó sin preguntarse qué significa
// aquí. Aquí significa conceder el atajo de ADR-009 sin que ningún tercero haya
// firmado nada. Una política que no puede verificar nada no es una política: es
// un error de quien llama, y se le dice.
func (wp WitnessPolicy) validate() error {
	switch {
	case len(wp.Witnesses) == 0:
		return fmt.Errorf("%w: sin testigos no hay nada que verificar; usa Open si no tienes política", ErrPolicy)
	case wp.Quorum < 1:
		return fmt.Errorf("%w: quórum %d; una atestación verificada exige al menos una cosignature", ErrPolicy, wp.Quorum)
	case wp.Quorum > len(wp.Witnesses):
		return fmt.Errorf("%w: quórum %d con %d testigos", ErrPolicy, wp.Quorum, len(wp.Witnesses))
	}
	for name, pub := range wp.Witnesses {
		if name == "" || len(pub) != ed25519.PublicKeySize {
			return fmt.Errorf("%w: testigo %q con clave de %d bytes", ErrPolicy, name, len(pub))
		}
	}
	return nil
}

// Claves de vault_meta donde init deja, EN CLARO, la identidad pública del log.
// Son públicas: verificar un recibo o abrir el ledger no debe exigir la
// passphrase.
const (
	MetaLogPubKey = "log/pubkey/v1"
	MetaOriginKey = "log/origin/v1"
	// MetaSignerPubKey es la clave pública del tenant que firma los bloques, en
	// claro, para que status la publique y una política pueda construirse sin
	// abrir el vault. Fuente de comparación, nunca raíz de confianza (ADR-017).
	MetaSignerPubKey = "log/signer-pubkey/v1"
)

// ErrCheckpointSignature indica que un checkpoint almacenado no está firmado por
// la clave del log que este mismo ledger declara. No hay rotación de la clave del
// log, así que solo tiene una lectura: alguien escribió en la base.
var ErrCheckpointSignature = errors.New("store: un checkpoint almacenado no está firmado por la clave del log")

// VerifyIntegrity recorre la base y comprueba que sigue contando la misma
// historia. Es lo que ejecuta Open.
//
// Reconstruye el árbol de Merkle COMPLETO y exige que la raíz iguale la del
// último checkpoint cosignado persistido; las firmas Ed25519 se recomputan solo
// para los bloques posteriores a ese checkpoint. Si no hay ningún checkpoint
// cosignado, se verifican todas: sin testigo no hay atajo (enmienda de ADR-009).
//
// El motivo es que los bytes cubiertos por una raíz cosignada ya están
// atestiguados por un tercero que conserva su copia, y sus firmas se
// verificaron al sellar. Lo que la raíz NO cubre es la columna signature, que
// vive fuera del header: corromper la firma de un bloque histórico no lo detecta
// este camino, lo detecta VerifyFull.
//
// No exige una clave de firmante concreta: el almacén no la conoce. Comprueba
// que cada bloque esté firmado por la clave que él mismo declara y que la cadena
// sea consistente; contrastar esa clave contra la identidad esperada del tenant
// es trabajo de quien abre el ledger, con ledger.VerifyChain.
func (s *Store) VerifyIntegrity() (OpenResult, error) { return s.verify(modeAttested) }

// VerifyFull recomputa TODAS las firmas Ed25519 de la base, sin apoyarse en
// ningún checkpoint. Es la operación de auditoría, y la que hay que llamar ante
// una sospecha: cuesta lo que la apertura costaba antes de la enmienda de
// ADR-009 y a cambio no concede nada.
func (s *Store) VerifyFull() (OpenResult, error) { return s.verify(modeFull) }

func (s *Store) verify(mode verifyMode) (OpenResult, error) {
	if s.db == nil {
		return OpenResult{}, &IntegrityError{Stage: "lectura", Index: -1, Err: ErrClosed}
	}
	n, err := s.Count()
	if err != nil {
		return OpenResult{}, &IntegrityError{Stage: "lectura", Index: -1, Err: err}
	}

	// attested es el checkpoint cosignado que respalda la historia. En modo
	// completo también se busca, aunque no se use para saltarse firmas: el
	// estado atestiguado es un hecho de la base, no del modo de verificación.
	// signedFrom es el primer bloque cuya firma se recomputa.
	attested, err := s.attestedCheckpoint(n)
	if err != nil {
		return OpenResult{}, err
	}

	// El atajo de ADR-009 solo se toma con atestación VERIFICADA (ADR-016). Antes
	// bastaba una nota con forma de cosignada, y la auditoría adversarial
	// escribió una a mano: el atacante no se saltaba la frontera, la dibujaba.
	state := AttestationNone
	reason := ""
	var signedFrom uint64
	if attested != nil {
		state, reason = s.attestationState(attested)
		if mode == modeAttested && state == AttestationVerified {
			signedFrom = attested.size
		}
	}

	leaves, signer, err := s.walk(signedFrom)
	if err != nil {
		return OpenResult{}, err
	}
	if err := s.verifyAgainstCheckpoints(leaves, attested); err != nil {
		return OpenResult{}, err
	}

	// IDENTIDAD del firmante (ADR-017): la continuidad ya garantizó que toda la
	// cadena la firma UNA clave; aquí se decide si es la esperada. Con política y
	// clave del firmante, una discrepancia es integridad rota: una cadena reescrita
	// ENTERA por otra clave es autoconsistente y solo esto la distingue. Sin ella,
	// el estado lo dice honesto en vez de dar por bueno lo que no se ha mirado.
	signerState := SignerNone
	if len(leaves) > 0 {
		signerState = SignerUnverified
		if s.witnesses != nil && len(s.witnesses.SignerKey) > 0 {
			if want := hex.EncodeToString(s.witnesses.SignerKey); want != signer {
				return OpenResult{}, &IntegrityError{Stage: "firmante", Index: -1,
					Err: fmt.Errorf("%w: la cadena la firma %s… y la política espera %s…",
						ErrSignerMismatch, signer[:16], want[:16])}
			}
			signerState = SignerVerified
		}
	}

	res := OpenResult{TreeSize: uint64(len(leaves)), Attestation: state, Reason: reason,
		Signer: signerState, SignerKey: signer}
	if attested != nil {
		// Llegar aquí significa que verifyAgainstCheckpoints contrastó la raíz
		// de este checkpoint contra el árbol reconstruido y cuadró.
		res.AttestedSize = attested.size
	}
	return res, nil
}

// attestationState decide qué es un checkpoint cosignado guardado: verificado,
// o presente sin verificar. Nunca decide "atestiguado" por la forma de la nota.
func (s *Store) attestationState(c *storedCheckpoint) (Attestation, string) {
	if s.witnesses == nil {
		return AttestationUnverified, "no se aportó ninguna política de testigos al abrir"
	}
	pol, err := s.logPolicy(c)
	if err != nil {
		return AttestationUnverified, err.Error()
	}
	pol.Witnesses = s.witnesses.Witnesses
	pol.Quorum = s.witnesses.Quorum
	if _, err := proof.VerifyNote(c.note, pol); err != nil {
		return AttestationUnverified, err.Error()
	}
	return AttestationVerified, ""
}

// logPolicy arma la política del log —origin y clave pública— desde vault_meta.
// Sin testigos: eso lo aporta quien abre.
func (s *Store) logPolicy(c *storedCheckpoint) (proof.Policy, error) {
	pub, err := s.GetMeta(MetaLogPubKey)
	if err != nil {
		return proof.Policy{}, fmt.Errorf("la base tiene checkpoints pero no declara la clave pública del log: %w", err)
	}
	// Si quien abre trae la clave del log, tiene que ser la que el ledger declara.
	// Es la capa que detecta la sustitución de clave que ADR-016 describió y no
	// tenía código: vault_meta es fuente de comparación, la política es la verdad.
	if s.witnesses != nil && len(s.witnesses.LogKey) > 0 && !bytes.Equal(s.witnesses.LogKey, pub) {
		return proof.Policy{}, fmt.Errorf("%w: el ledger declara %s… y la política trae %s…",
			ErrLogKeyMismatch, hex.EncodeToString(pub)[:16], hex.EncodeToString(s.witnesses.LogKey)[:16])
	}
	origin := c.origin
	if raw, err := s.GetMeta(MetaOriginKey); err == nil {
		origin = string(raw)
	}
	return proof.Policy{Origin: origin, LogKey: pub}, nil
}

// verifyLogSignature exige que la nota esté firmada por la clave del log que ESTE
// ledger declara en vault_meta. Es la comprobación (a) de ADR-016.
//
// Sube el listón solo un peldaño —quien escribe en la base puede sustituir la
// clave con un UPDATE más— pero es el peldaño que hace ruidoso el ataque: una
// clave sustituida la delatan los recibos ya emitidos, el testigo y quien haya
// anotado la clave que status publica. Lo que no puede pasar es lo que pasaba:
// que una nota firmada por NADIE contara como atestación.
func (s *Store) verifyLogSignature(c *storedCheckpoint) error {
	pol, err := s.logPolicy(c)
	if err != nil {
		return &IntegrityError{Stage: "checkpoint", Index: -1, Err: err}
	}
	v, err := checkpoint.NewVerifier(pol.Origin, pol.LogKey)
	if err != nil {
		return &IntegrityError{Stage: "checkpoint", Index: -1, Err: err}
	}
	if _, _, err := checkpoint.Verify(c.note, v); err != nil {
		return &IntegrityError{Stage: "checkpoint", Index: -1,
			Err: fmt.Errorf("%w (tamaño %d): %w", ErrCheckpointSignature, c.size, err)}
	}
	return nil
}

// storedCheckpoint es una nota guardada junto a lo que dice de sí misma.
type storedCheckpoint struct {
	note   []byte
	origin string
	size   uint64
	root   []byte
}

// walk recorre la tabla de bloques UNA vez y devuelve las hojas del árbol.
//
// Por debajo de signedFrom el trabajo por bloque es un SHA-256 sobre los bytes
// que hay guardados; a partir de ahí se reconstruye el bloque y se verifican su
// firma Ed25519 y su encadenamiento.
func (s *Store) walk(signedFrom uint64) ([][]byte, string, error) {
	rows, err := s.db.Query(`SELECT idx, hash, header_json, signature FROM blocks ORDER BY idx`)
	if err != nil {
		return nil, "", &IntegrityError{Stage: "lectura", Index: -1, Err: err}
	}
	defer rows.Close()

	var (
		leaves [][]byte
		prev   *ledger.Block
		i      int64
		// signer es la clave del bloque 0. La CONTINUIDAD exige que todos los
		// demás la compartan, y se comprueba siempre, con o sin atajo (ADR-017).
		signer string
	)
	for rows.Next() {
		var (
			idx        int64
			hash       string
			headerJSON string
			signature  string
		)
		if err := rows.Scan(&idx, &hash, &headerJSON, &signature); err != nil {
			return nil, "", &IntegrityError{Stage: "lectura", Index: i, Err: err}
		}
		if idx != i {
			return nil, "", &IntegrityError{
				Stage: "secuencia", Index: i,
				Err: fmt.Errorf("%w: la fila %d contiene el bloque %d", ledger.ErrIndexSequence, i, idx),
			}
		}
		// La atadura header↔hash se comprueba SIEMPRE, y sobre los bytes
		// almacenados en vez de recanonicalizarlos. Es más barato y es más
		// estricto: el header_json guardado ES la forma canónica JCS —lo que se
		// firmó—, así que si dejara de serlo esto lo delata en lugar de
		// normalizarlo por lo bajo. Sin esta comprobación el árbol se
		// reconstruiría desde una columna hash que nadie ató a su contenido, y
		// el header_json sería sustituible a voluntad.
		if sha256Hex(headerJSON) != hash {
			return nil, "", &IntegrityError{Stage: "bloque", Index: idx, Err: ledger.ErrHashMismatch}
		}
		rawHash, err := decodeHash(hash)
		if err != nil {
			return nil, "", &IntegrityError{Stage: "bloque", Index: idx, Err: err}
		}
		rawSig, err := hex.DecodeString(signature)
		if err != nil {
			return nil, "", &IntegrityError{Stage: "bloque", Index: idx, Err: err}
		}
		// La hoja es hash ‖ signature (leaf/v2, PROTOCOL.md §2.1). Aquí está el
		// cambio que da valor a ADR-014: bajo leaf/v1 esta pasada solo ataba
		// header↔hash, así que la columna signature no entraba en la raíz y alguien
		// con escritura en la base podía destrozarla sin que la apertura lo notara
		// —lo cazaba `verify --full`, que nadie ejecuta—. Ahora la firma entra en la
		// hoja, así que la MISMA comprobación que ya se hacía al abrir la cubre,
		// incluso por debajo del último checkpoint cosignado, donde las
		// verificaciones Ed25519 se saltan a propósito por coste.
		leaf, err := ledger.LeafData(rawHash, rawSig)
		if err != nil {
			return nil, "", &IntegrityError{Stage: "bloque", Index: idx, Err: err}
		}
		leaves = append(leaves, leaf)

		// Continuidad del firmante, SIEMPRE, también por debajo del atajo. Es lo que
		// cierra el exploit de la segunda auditoría tal cual se ejecutó: los
		// bloques 1-4 re-firmados con otra clave, autoconsistentes, y nadie
		// comparaba el signer_pubkey de un bloque con el del anterior. Se lee del
		// header_json almacenado, cuyo hash ya se ató arriba.
		sp, err := signerOf(headerJSON)
		if err != nil {
			return nil, "", &IntegrityError{Stage: "bloque", Index: idx, Err: err}
		}
		if idx == 0 {
			signer = sp
		} else if sp != signer {
			return nil, "", &IntegrityError{Stage: "firmante", Index: idx,
				Err: fmt.Errorf("%w: el bloque 0 lo firma %s… y el bloque %d lo firma %s…",
					ErrSignerContinuity, signer[:16], idx, sp[:16])}
		}

		// El último bloque cubierto por el checkpoint también se reconstruye,
		// para poder comprobar el encadenamiento con el primero que no lo está.
		if uint64(idx)+1 < signedFrom {
			i++
			continue
		}
		b, err := decodeBlock(idx, hash, headerJSON, signature)
		if err != nil {
			return nil, "", &IntegrityError{Stage: "bloque", Index: idx, Err: err}
		}
		if uint64(idx) >= signedFrom {
			if err := b.Verify(); err != nil {
				return nil, "", &IntegrityError{Stage: "bloque", Index: idx, Err: err}
			}
			if prev != nil {
				if err := ledger.VerifyLink(prev, b); err != nil {
					return nil, "", &IntegrityError{Stage: "encadenamiento", Index: idx, Err: err}
				}
			}
		}
		prev = b
		i++
	}
	if err := rows.Err(); err != nil {
		return nil, "", &IntegrityError{Stage: "lectura", Index: -1, Err: err}
	}
	return leaves, signer, nil
}

// signerOf saca signer_pubkey del header canónico almacenado sin reconstruir el
// bloque entero: es lo que permite comprobar la continuidad también por debajo
// del atajo, donde los bloques no se decodifican.
func signerOf(headerJSON string) (string, error) {
	var h struct {
		SignerPubKey string `json:"signer_pubkey"`
	}
	if err := json.Unmarshal([]byte(headerJSON), &h); err != nil {
		return "", fmt.Errorf("header ilegible: %w", err)
	}
	if len(h.SignerPubKey) != 2*ed25519.PublicKeySize {
		return "", fmt.Errorf("%w: signer_pubkey de %d caracteres", ledger.ErrInvalidHeader, len(h.SignerPubKey))
	}
	return h.SignerPubKey, nil
}

// sha256Hex devuelve el SHA-256 en hexadecimal de la cadena dada.
func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// decodeBlock reconstruye el bloque desde sus columnas.
func decodeBlock(idx int64, hash, headerJSON, signature string) (*ledger.Block, error) {
	var h ledger.Header
	if err := json.Unmarshal([]byte(headerJSON), &h); err != nil {
		return nil, fmt.Errorf("store: header del bloque %d ilegible: %w", idx, err)
	}
	return &ledger.Block{Header: h, Hash: hash, Signature: signature}, nil
}

// attestedCheckpoint devuelve el último checkpoint cosignado persistido, o nil
// si no hay ninguno. Un checkpoint que promete más bloques de los que hay es un
// fallo de integridad aquí mismo: no puede respaldar ningún atajo.
func (s *Store) attestedCheckpoint(n int) (*storedCheckpoint, error) {
	note, err := s.LastCosignedCheckpoint()
	if errors.Is(err, ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, &IntegrityError{Stage: "checkpoint", Index: -1, Err: err}
	}
	c, err := checkpoint.ParseNote(note)
	if err != nil {
		return nil, &IntegrityError{Stage: "checkpoint", Index: -1, Err: err}
	}
	if c.Size > uint64(n) {
		return nil, missingHistory(c.Size, n)
	}
	sc := &storedCheckpoint{note: note, origin: c.Origin, size: c.Size, root: c.RootHash}
	// Firma del log SIEMPRE, se aporte o no política de testigos. Una nota que no
	// está firmada por este log no es "sin verificar": es manipulación.
	if err := s.verifyLogSignature(sc); err != nil {
		return nil, err
	}
	return sc, nil
}

// verifyAgainstCheckpoints contrasta la raíz reconstruida con la que prometió el
// último checkpoint y, si es otro, con la del último cosignado.
//
// Se comprueban los dos porque cumplen papeles distintos: el último es la
// promesa más reciente del log, y el cosignado es el que respalda el atajo de
// firmas. Saltarse el segundo dejaría el atajo sin fundamento.
func (s *Store) verifyAgainstCheckpoints(leaves [][]byte, attested *storedCheckpoint) error {
	note, err := s.LastCheckpoint()
	if errors.Is(err, ErrNotFound) {
		return nil // un ledger sin checkpoints todavía no prometió nada
	}
	if err != nil {
		return &IntegrityError{Stage: "checkpoint", Index: -1, Err: err}
	}
	last, err := checkpoint.ParseNote(note)
	if err != nil {
		return &IntegrityError{Stage: "checkpoint", Index: -1, Err: err}
	}
	// El último checkpoint también tiene que estar firmado por este log. Es la
	// otra nota que la apertura usa —para contrastar la raíz— y una nota ajena
	// ahí es tan manipulación como en la atestada.
	if err := s.verifyLogSignature(&storedCheckpoint{
		note: note, origin: last.Origin, size: last.Size, root: last.RootHash,
	}); err != nil {
		return err
	}
	if err := verifyRootAt(leaves, last); err != nil {
		return err
	}
	if attested != nil && attested.size != last.Size {
		return verifyRootAt(leaves, checkpoint.Checkpoint{
			Origin: attested.origin, Size: attested.size, RootHash: attested.root,
		})
	}
	return nil
}

// verifyRootAt reconstruye la raíz de las primeras c.Size hojas y la compara con
// la que el checkpoint firmó.
func verifyRootAt(leaves [][]byte, c checkpoint.Checkpoint) error {
	if c.Size > uint64(len(leaves)) {
		return missingHistory(c.Size, len(leaves))
	}
	if root := ledger.Root(leaves[:c.Size]); !bytes.Equal(root, c.RootHash) {
		return &IntegrityError{
			Stage: "checkpoint", Index: -1,
			Err: fmt.Errorf("la raíz reconstruida de %d bloques es %s y el checkpoint firmó %s",
				c.Size, hex.EncodeToString(root), hex.EncodeToString(c.RootHash)),
		}
	}
	return nil
}

func missingHistory(promised uint64, have int) error {
	return &IntegrityError{
		Stage: "checkpoint", Index: -1,
		Err: fmt.Errorf("el checkpoint promete %d bloques y solo hay %d: falta historia", promised, have),
	}
}

// Root devuelve la raíz de Merkle del ledger completo, reconstruida en memoria
// desde los hashes de bloque.
//
// No se cachean subárboles: la reconstrucción son 119 ms con 10^5 bloques,
// medidos. La caché quedó DESCARTADA como remedio de la apertura en la enmienda
// de ADR-009, porque el coste que había que atacar eran las verificaciones
// Ed25519, no el árbol.
func (s *Store) Root() ([]byte, error) {
	leaves, err := s.LeafData()
	if err != nil {
		return nil, err
	}
	return ledger.Root(leaves), nil
}

// MetaLeafRuleKey es la clave de vault_meta donde el log registra con qué REGLA DE
// HOJA se creó (PROTOCOL.md §2.1).
const MetaLeafRuleKey = "log/leaf-rule/v1"

// ErrLeafRule indica que el log se creó con una regla de hoja distinta de la que
// implementa este binario.
var ErrLeafRule = errors.New("store: el log usa otra regla de hoja")

// checkLeafRule registra la regla de hoja en un log nuevo y la comprueba en uno
// existente.
//
// Es lo que convierte la regla de hoja de PROTOCOL.md §2.1 en algo que una máquina
// comprueba, en vez de un párrafo que alguien debería haber leído. Sin esto, abrir
// un log de leaf/v1 con un binario de leaf/v2 daría un error de raíz que no cuadra
// —cierto pero inútil— y quien lo viera buscaría corrupción donde hay un cambio de
// versión.
//
// Un log SIN la marca y CON bloques es de leaf/v1 por definición: la marca se
// escribe desde que existe. Se rechaza, y la única ruta que PROTOCOL contempla es
// la de segmentos: cerrar el viejo y empezar otro.
func (s *Store) checkLeafRule() error {
	stored, err := s.GetMeta(MetaLeafRuleKey)
	switch {
	case err == nil:
		if string(stored) != ledger.LeafRule {
			return fmt.Errorf("%w: el log se creó con %q y este binario implementa %q. "+
				"No hay conversión: la migración pasa por cerrar el segmento y abrir otro "+
				"(PROTOCOL.md §2.1, ADR-006)", ErrLeafRule, stored, ledger.LeafRule)
		}
		return nil
	case !errors.Is(err, ErrNotFound):
		return err
	}

	// Sin marca: o el log es nuevo, o viene de antes de que la marca existiera.
	size, err := s.Count()
	if err != nil {
		return err
	}
	if size > 0 {
		return fmt.Errorf("%w: el log no declara regla de hoja y tiene %d bloques, "+
			"así que es de %q; este binario implementa %q (PROTOCOL.md §2.1, ADR-014)",
			ErrLeafRule, size, ledger.LeafRuleV1, ledger.LeafRule)
	}
	return s.PutMeta(MetaLeafRuleKey, []byte(ledger.LeafRule))
}

// LeafRule devuelve la regla de hoja con la que se creó este log.
func (s *Store) LeafRule() (string, error) {
	raw, err := s.GetMeta(MetaLeafRuleKey)
	if errors.Is(err, ErrNotFound) {
		return ledger.LeafRuleV1, nil
	}
	if err != nil {
		return "", err
	}
	return string(raw), nil
}
