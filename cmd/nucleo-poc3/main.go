// nucleo-poc3: el testigo como parte separada, hablando por HTTP.
//
//	go run ./cmd/nucleo-poc3
//
// Los dos primeros PoC tenían al testigo dentro del mismo proceso que el log, y
// eso escondía lo esencial: lo que da valor a la firma de un testigo es que su
// memoria esté FUERA del alcance de quien controla el ledger. Aquí son dos
// procesos lógicos, cada uno con su base de datos y su clave, que solo se hablan
// por HTTP siguiendo c2sp.org/tlog-witness (ADR-011).
//
// La demostración: se sella una historia, se cosigna por HTTP, se reinicia el
// log, y después se simula el ataque que la auditoría externa describió —borrar
// los disparadores, vaciar los checkpoints y truncar los bloques—. El fichero
// truncado abre sin una queja. La sincronización con el testigo lo delata.
package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/nucleoledger/nucleo/internal/checkpoint"
	"github.com/nucleoledger/nucleo/internal/keys"
	"github.com/nucleoledger/nucleo/internal/ledger"
	"github.com/nucleoledger/nucleo/internal/logsync"
	"github.com/nucleoledger/nucleo/internal/proof"
	"github.com/nucleoledger/nucleo/internal/receipt"
	"github.com/nucleoledger/nucleo/internal/reconcile"
	"github.com/nucleoledger/nucleo/internal/store"
	"github.com/nucleoledger/nucleo/internal/witness"
	_ "modernc.org/sqlite"
)

const (
	origin      = "nucleoledger.com/poc3"
	witnessName = "witness.nucleoledger.com/w1"
	tenant      = "1790012345001"

	tenantSeedHex  = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	logSeedHex     = "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
	witnessSeedHex = "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f"
	// Semilla ML-DSA-44 del log: la segunda firma de ADR-007.
	logPQSeedHex = "2a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40414243444546474849"
)

var base = time.Date(2026, 9, 6, 9, 0, 0, 0, time.UTC)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "ERROR:", err)
		os.Exit(1)
	}
}

func run() error {
	dir, err := os.MkdirTemp("", "nucleo-poc3-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	logDB := filepath.Join(dir, "nucleo.db")
	witnessDB := filepath.Join(dir, "witness.db")

	tenantPriv, err := keys.PrivateKeyFromSeedHex(tenantSeedHex)
	if err != nil {
		return err
	}
	logPriv, err := keys.PrivateKeyFromSeedHex(logSeedHex)
	if err != nil {
		return err
	}
	witnessPriv, err := keys.PrivateKeyFromSeedHex(witnessSeedHex)
	if err != nil {
		return err
	}

	// ---- El testigo, en su propio "proceso" -------------------------------
	url, stop, err := startWitness(witnessDB, witnessPriv, logPriv.Public().(ed25519.PublicKey))
	if err != nil {
		return err
	}
	defer stop()

	fmt.Println("== Dos partes separadas ==")
	fmt.Println("  LOG     :", origin)
	fmt.Println("    base  :", logDB)
	fmt.Println("  TESTIGO :", witnessName)
	fmt.Println("    base  :", witnessDB, "  (otra base, otra clave)")
	fmt.Println("    HTTP  :", url)
	fmt.Println()
	fmt.Println("  El testigo NO comparte memoria con el log. Se hablan por HTTP")
	fmt.Println("  siguiendo c2sp.org/tlog-witness. Esa separación es el punto:")
	fmt.Println("  quien controle el fichero del log no puede tocar la del testigo.")

	// El cliente va atado a la identidad del testigo: sin su clave no podría
	// distinguir una cosignature de una cadena de bytes con la forma correcta.
	client, err := witness.NewClient(url, witnessName, witnessPriv.Public().(ed25519.PublicKey))
	if err != nil {
		return err
	}
	ctx := context.Background()

	// ---- Sesión 1: sellar y cosignar por HTTP -----------------------------
	fmt.Println("\n== Sesión 1: sellar 8 bloques y cosignarlos por HTTP ==")
	s, openState, err := store.Open(logDB)
	if err != nil {
		return err
	}
	printState(openState)
	if err := sealBlocks(s, tenantPriv, 0, 8); err != nil {
		return err
	}
	fmt.Println("✔ 8 bloques sellados")

	adapter, err := newAdapter(s, logPriv)
	if err != nil {
		return err
	}
	res, err := logsync.SyncWithWitness(ctx, adapter, client)
	if err != nil {
		return err
	}
	fmt.Printf("✔ POST /add-checkpoint → 200; el testigo cosignó un árbol de %d\n", res.LocalSize)
	fmt.Println("  (era su primer checkpoint de este log: tamaño anterior 0, sin prueba)")
	fmt.Println("  firmas en el checkpoint:")
	if err := printSignatures(res.Cosigned); err != nil {
		return err
	}
	fmt.Println("    Un verificador que solo conozca la Ed25519 ignora la ML-DSA-44")
	fmt.Println("    y verifica exactamente igual: por eso se puede añadir hoy.")
	if err := s.Close(); err != nil {
		return err
	}
	fmt.Println("✔ base del log CERRADA")

	// ---- Sesión 2: reabrir y extender -------------------------------------
	fmt.Println("\n== Sesión 2: reabrir en frío y extender a 12 ==")
	s2, openState2, err := store.Open(logDB)
	if err != nil {
		return err
	}
	printState(openState2)
	if err := sealBlocks(s2, tenantPriv, 8, 4); err != nil {
		return err
	}
	adapter2, err := newAdapter(s2, logPriv)
	if err != nil {
		return err
	}
	res2, err := logsync.SyncWithWitness(ctx, adapter2, client)
	if err != nil {
		return err
	}
	fmt.Printf("✔ extensión de %d a %d aceptada, con prueba de consistencia\n", res2.WitnessSize, res2.LocalSize)

	// ---- Un recibo entregable ---------------------------------------------
	fmt.Println("\n== Recibo del bloque 3, con los dos relojes ==")
	if err := printReceipt(s2, logPriv.Public().(ed25519.PublicKey), witnessPriv.Public().(ed25519.PublicKey)); err != nil {
		return err
	}

	// ---- La reconciliación: el vigilante ----------------------------------
	fmt.Println("\n== Reconciliación: lo que el sistema vivo dice HOY ==")
	if err := reconcileDemo(s2); err != nil {
		return err
	}

	if err := s2.Close(); err != nil {
		return err
	}

	// ---- El ataque ---------------------------------------------------------
	fmt.Println("\n== El ataque: alguien con acceso al fichero del log ==")
	if err := truncateLedger(logDB, 6); err != nil {
		return err
	}
	fmt.Println("  · DROP de los disparadores de append-only")
	fmt.Println("  · DELETE FROM checkpoints   (borra la promesa que se contradice)")
	fmt.Println("  · DELETE FROM blocks WHERE idx >= 6   (la historia vuelve a ayer)")

	s3, openState3, err := store.Open(logDB)
	if err != nil {
		return fmt.Errorf("el prefijo truncado no abrió: %w", err)
	}
	defer s3.Close()
	fmt.Println("\n  Y el fichero ABRE sin una queja:")
	printState(openState3)
	fmt.Println("  Desde dentro del fichero es una historia impecable: encadena, las")
	fmt.Println("  firmas verifican y no queda ningún checkpoint que la contradiga.")
	fmt.Println("  Ninguna comprobación local puede desmentirla, porque cualquier")
	fmt.Println("  prueba que viviera en ese fichero también sería del atacante.")

	// ---- La detección ------------------------------------------------------
	fmt.Println("\n== La detección: preguntarle al que no perdió la memoria ==")
	adapter3, err := newAdapter(s3, logPriv)
	if err != nil {
		return err
	}
	_, err = logsync.SyncWithWitness(ctx, adapter3, client)
	var rb *logsync.RollbackError
	if !errors.As(err, &rb) {
		return fmt.Errorf("la sincronización NO detectó el truncamiento: %v", err)
	}
	fmt.Println("✘ ROLLBACK LOCAL DETECTADO")
	fmt.Printf("    en disco          : %d bloques\n", rb.LocalSize)
	fmt.Printf("    el testigo cosignó: %d bloques\n", rb.WitnessSize)
	fmt.Printf("    faltan            : %d bloques\n", rb.WitnessSize-rb.LocalSize)
	fmt.Println()
	fmt.Println("  El testigo conserva su cosignature de un árbol de 12. El fichero")
	fmt.Println("  local dice 6. Una de las dos cosas es mentira, y la que está")
	fmt.Println("  firmada por un tercero no es la que se puede reescribir con SQL.")
	return nil
}

// startWitness levanta el testigo en su propio servidor HTTP, con su propia base.
func startWitness(dbPath string, priv ed25519.PrivateKey, logPub ed25519.PublicKey) (string, func(), error) {
	st, err := witness.OpenState(dbPath)
	if err != nil {
		return "", nil, err
	}
	clock := base
	w, err := witness.NewWithState(witnessName, priv, func() time.Time {
		clock = clock.Add(time.Second)
		return clock
	}, st)
	if err != nil {
		st.Close()
		return "", nil, err
	}
	if err := w.AddLog(origin, logPub); err != nil {
		st.Close()
		return "", nil, err
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		st.Close()
		return "", nil, err
	}
	srv := &http.Server{Handler: witness.NewServer(w).Handler()}
	go srv.Serve(ln)
	stop := func() {
		srv.Close()
		st.Close()
	}
	return "http://" + ln.Addr().String(), stop, nil
}

// newAdapter conecta el ledger y el emisor de checkpoints con la sincronización.
//
// El log firma con DOS claves: la Ed25519 de siempre y la ML-DSA-44 de ADR-007.
// Quien no entienda la segunda ignora su línea de firma y verifica igual.
func newAdapter(s *store.Store, logPriv ed25519.PrivateKey) (*logsync.StoreLog, error) {
	signer, err := checkpoint.NewSigner(origin, logPriv)
	if err != nil {
		return nil, err
	}
	lg, err := checkpoint.NewLog(origin, signer)
	if err != nil {
		return nil, err
	}
	pq, err := logPQSigner()
	if err != nil {
		return nil, err
	}
	if err := lg.AddSigner(pq); err != nil {
		return nil, err
	}
	return logsync.NewStoreLog(s, lg)
}

// logPQSigner construye el firmante post-cuántico del log.
func logPQSigner() (*checkpoint.MLDSASigner, error) {
	seed, err := hex.DecodeString(logPQSeedHex)
	if err != nil {
		return nil, err
	}
	return checkpoint.NewMLDSASigner(origin, seed)
}

// printSignatures desglosa las firmas de un checkpoint real.
func printSignatures(msg []byte) error {
	pq, err := logPQSigner()
	if err != nil {
		return err
	}
	i := bytes.LastIndex(msg, []byte("\n\n"))
	if i < 0 {
		return fmt.Errorf("la nota no separa cuerpo y firmas")
	}
	for _, line := range strings.Split(strings.TrimRight(string(msg[i+2:]), "\n"), "\n") {
		j := strings.LastIndex(line, " ")
		blob, err := base64.StdEncoding.DecodeString(line[j+1:])
		if err != nil {
			return err
		}
		name := strings.TrimPrefix(line[:j], "— ")
		switch len(blob) - 4 {
		case ed25519.SignatureSize:
			fmt.Printf("    · Ed25519      %4d bytes  %s\n", len(blob)-4, name)
		case checkpoint.MLDSASignatureSize:
			fmt.Printf("    · ML-DSA-44   %5d bytes  %s  (key ID %08x, extensión 0xff)\n",
				len(blob)-4, name, pq.KeyHash())
		default:
			fmt.Printf("    · cosignature %5d bytes  %s\n", len(blob)-4, name)
		}
	}
	return nil
}

// sealBlocks sella n bloques a partir del índice from.
func sealBlocks(s *store.Store, priv ed25519.PrivateKey, from, n int) error {
	pub := priv.Public().(ed25519.PublicKey)
	var prev *ledger.Block
	if from > 0 {
		last, err := s.LastBlock()
		if err != nil {
			return err
		}
		prev = last
	}
	for i := from; i < from+n; i++ {
		h, err := ledger.NewHeader(prev, tenant, "sri.factura.v1",
			[]byte(fmt.Sprintf(`{"factura":%d}`, i)), "blob://x", pub,
			base.Add(time.Duration(i)*time.Minute))
		if err != nil {
			return err
		}
		b, err := ledger.Seal(h, priv)
		if err != nil {
			return err
		}
		if err := s.AppendBlock(b); err != nil {
			return err
		}
		prev = b
	}
	return nil
}

// truncateLedger es el atacante: SQL directo sobre el fichero del log.
func truncateLedger(path string, keep int) error {
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		return err
	}
	defer db.Close()
	for _, stmt := range []string{
		`DROP TRIGGER IF EXISTS blocks_no_delete`,
		`DROP TRIGGER IF EXISTS blocks_no_update`,
		`DROP TRIGGER IF EXISTS checkpoints_no_delete`,
		`DROP TRIGGER IF EXISTS checkpoints_no_update`,
		`DELETE FROM checkpoints`,
		fmt.Sprintf(`DELETE FROM blocks WHERE idx >= %d`, keep),
	} {
		if _, err := db.Exec(stmt); err != nil {
			return fmt.Errorf("%s: %w", stmt, err)
		}
	}
	return nil
}

// printState dice en voz alta qué respalda la historia recién abierta.
func printState(r store.OpenResult) {
	switch {
	case r.TreeSize == 0:
		fmt.Println("· ESTADO: base nueva, todavía sin historia que atestiguar")
	case r.Attested:
		fmt.Printf("✔ ESTADO: historia atestiguada hasta %d de %d bloques\n", r.AttestedSize, r.TreeSize)
	default:
		fmt.Printf("⚠ ESTADO: SIN ATESTIGUAR (%d bloques) — localmente válida,\n", r.TreeSize)
		fmt.Println("  pero que esté COMPLETA no está garantizado")
	}
}

// printReceipt emite un recibo y lo enseña como lo vería quien lo recibe.
func printReceipt(s *store.Store, logPub, witnessPub ed25519.PublicKey) error {
	r, err := receipt.Issue(s, "María Pérez (cédula 1712345678)", 3)
	if err != nil {
		return err
	}
	data, err := receipt.Format(r)
	if err != nil {
		return err
	}
	for _, line := range strings.Split(receipt.Text(data), "\n") {
		fmt.Println("  " + line)
	}

	// El destinatario verifica con SU política, sin pedirle nada al emisor.
	policy := proof.Policy{
		Origin: origin, LogKey: logPub,
		Witnesses: map[string]ed25519.PublicKey{witnessName: witnessPub},
		Quorum:    1,
	}
	parsed, err := receipt.Parse(data)
	if err != nil {
		return err
	}
	res, err := parsed.Verify(policy)
	if err != nil {
		return err
	}
	fmt.Println()
	fmt.Printf("  ✔ verificado sin acceso al ledger (%d bytes, %d cosignatario)\n", len(data), len(res.Cosigners))
	fmt.Println("    El tiempo DECLARADO lo puso el emisor y podría mentir.")
	fmt.Println("    El tiempo DEMOSTRABLE lo firmó un tercero que vio ese árbol.")
	fmt.Println("    El recibo enseña los dos y no los confunde nunca.")
	return nil
}

// reconcileDemo cuenta la historia que da sentido al proyecto.
func reconcileDemo(s *store.Store) error {
	blocks, err := s.Blocks(0, 12)
	if err != nil {
		return err
	}

	// El sistema vivo devuelve hoy lo mismo que se selló... salvo la factura 4,
	// a la que alguien le cambió el importe con un UPDATE.
	const alterada = `{"factura":4,"importe":"1000.00"}`
	records := make([]reconcile.Record, 0, len(blocks))
	for i := range blocks {
		payload := fmt.Sprintf(`{"factura":%d}`, i)
		if i == 4 {
			payload = alterada
		}
		records = append(records, reconcile.Record{Index: uint64(i), Payload: []byte(payload)})
	}

	fmt.Println("  El ledger selló 12 registros. La base operativa devuelve 12.")
	fmt.Println("  A simple vista, todo cuadra.")

	rep, err := reconcile.Reconcile(s, reconcile.FromSlice(records), reconcile.Options{
		IncludeFullVerify: true,
	})
	if err != nil {
		return err
	}
	fmt.Printf("\n  comparados : %d\n", rep.Checked)
	fmt.Printf("  coinciden  : %d\n", rep.Verified)
	fmt.Printf("  discrepan  : %d\n", len(rep.Altered()))
	if rep.FullVerify != nil {
		fmt.Printf("  verificación exhaustiva del ledger: %v\n", rep.FullVerify.OK)
	}

	for _, f := range rep.Altered() {
		fmt.Println("\n  ✘ REGISTRO ALTERADO DESPUÉS DE SELLARSE")
		fmt.Printf("      bloque              : %d\n", f.Index)
		fmt.Printf("      emisor (tenant)     : %s\n", f.Tenant)
		fmt.Printf("      sellado el          : %s  (tiempo declarado)\n", f.SealedAt)
		fmt.Printf("      hash sellado        : %s\n", f.SealedHash)
		fmt.Printf("      hash actual         : %s\n", f.CurrentHash)
		fmt.Printf("      el sistema vivo dice: %s\n", alterada)
	}

	fmt.Println("\n  Núcleo NO impidió el UPDATE: nadie puede, la base operativa no es suya.")
	fmt.Println("  Lo que hizo fue recordar exactamente qué decía ese registro cuando se")
	fmt.Println("  selló, y desde cuándo. La alteración deja de ser invisible, que es lo")
	fmt.Println("  único que se puede prometer de verdad — y es suficiente.")
	return nil
}
