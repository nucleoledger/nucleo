package reconcile

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/nucleoledger/nucleo/internal/erasure"
	"github.com/nucleoledger/nucleo/internal/ledger"
)

// Las claves de la rotación de los tests de este fichero: la actual es claveSupresion
// (supresion_test.go); estas dos, otras.
var (
	claveRetirada = ed25519.NewKeyFromSeed([]byte("clave de supresion ya retirada.."))
	claveAjena    = ed25519.NewKeyFromSeed([]byte("clave que la politica no lista.."))
)

func hexDe(k ed25519.PrivateKey) string { return hex.EncodeToString(k.Public().(ed25519.PublicKey)) }

// conRetirada es la autoridad de una política con la erasureKey de los tests y la clave
// retirada con el corte dado.
func conRetirada(corte uint64) erasure.Authority {
	a := autoridad
	a.Retired = map[string]uint64{hexDe(claveRetirada): corte}
	return a
}

// TestClaveRetiradaDespuesDelCorteNoCuenta (ADR-033 §C): la prueba de que retirar una
// clave sirve. Con las piezas internas —sin pasar por `erase`— se sella en el bloque 2 un
// evento autorizado con la clave retirada. Con corte 2 cuenta (el corte es incluido); con
// corte 1, el evento es posterior a su corte: es un hallazgo que dice por qué, y el
// registro sigue faltando.
func TestClaveRetiradaDespuesDelCorteNoCuenta(t *testing.T) {
	a := []byte(`{"venta":"001","importe":"10000.00"}`)
	b := []byte(`{"venta":"002","importe":"75.00"}`)
	ha := hashOf(string(a))
	s, err := openLedger(t)
	if err != nil {
		t.Fatal(err)
	}
	apila(t, s, factura(a), factura(b), evento(t, ha, autoriza(t, claveRetirada, testOrigin, ha, 0)))
	vivos := FromSlice([]Record{{Index: 1, Payload: b}})

	rep, err := Reconcile(s, vivos, Options{Erasure: conRetirada(2)})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Findings) != 0 || len(rep.Erased) != 1 || rep.Erased[0].ErasedBy != 2 {
		t.Fatalf("dentro del corte: hallazgos %+v, suprimidos %+v", rep.Findings, rep.Erased)
	}
	if x := rep.Erased[0]; x.AuthorizedBy != "retiredErasureKeys" || x.ErasureKey != hexDe(claveRetirada) || x.Cutoff == nil || *x.Cutoff != 2 {
		t.Errorf("la entrada no dice qué clave la autorizó: %+v", x.Autoria)
	}

	rep, err = Reconcile(s, vivos, Options{Erasure: conRetirada(1)})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Erased) != 0 {
		t.Errorf("después del corte, suprimidos = %+v", rep.Erased)
	}
	if f := hallazgo(rep, 0); f == nil || f.Status != StatusMissing {
		t.Errorf("el bloque 0 no sale como faltante: %+v", rep.Findings)
	}
	f := hallazgo(rep, 2)
	if f == nil || f.Status != StatusUnauthorizedErasure || !strings.Contains(f.Reason, "después de su corte 1") {
		t.Errorf("el evento no sale como supresión no autorizada por el corte: %+v", f)
	}
}

// TestSupresionNoAutorizadaRegularizada (ADR-033, decisión 4): un evento no autorizado E
// queda regularizado por un R posterior, autorizado, del mismo contenido, cuyo through
// cubre la última copia anterior a E. Y cada condición que falta deja E como hallazgo.
func TestSupresionNoAutorizadaRegularizada(t *testing.T) {
	x := []byte(`{"factura":"001","cliente":"Ana"}`)
	y := []byte(`{"factura":"002","cliente":"Luis"}`)
	relleno := []byte(`{"factura":"003"}`)
	hx, hy := hashOf(string(x)), hashOf(string(y))
	ajena := func(h string, k uint64) sellado { return evento(t, h, autoriza(t, claveAjena, testOrigin, h, k)) }
	buena := func(h string, k uint64) sellado { return evento(t, h, autoriza(t, claveSupresion, testOrigin, h, k)) }

	type esperado struct {
		hallazgos   []uint64 // los eventos no autorizados que quedan como hallazgo
		faltantes   []uint64
		suprimidos  [][2]uint64 // {bloque, suprimido por}
		regularizad [][2]uint64 // {evento, regularizado por}
	}
	for _, c := range []struct {
		nombre string
		cadena []sellado
		vivos  []Record
		want   esperado
	}{
		{"regulariza: X en 0, E ajena en 2, R en 3 con through 0",
			[]sellado{factura(x), factura(relleno), ajena(hx, 0), buena(hx, 0)},
			[]Record{{Index: 1, Payload: relleno}},
			esperado{suprimidos: [][2]uint64{{0, 3}}, regularizad: [][2]uint64{{2, 3}}}},
		{"condición 1: R tampoco autorizado",
			[]sellado{factura(x), factura(relleno), ajena(hx, 0), ajena(hx, 0)},
			[]Record{{Index: 1, Payload: relleno}},
			esperado{hallazgos: []uint64{2, 3}, faltantes: []uint64{0}}},
		{"condición 2: R anterior a E",
			[]sellado{factura(x), factura(relleno), buena(hx, 0), ajena(hx, 0)},
			[]Record{{Index: 1, Payload: relleno}},
			esperado{hallazgos: []uint64{3}, suprimidos: [][2]uint64{{0, 2}}}},
		{"condición 3: R suprime otro contenido",
			[]sellado{factura(x), factura(y), ajena(hx, 0), buena(hy, 1)},
			nil,
			esperado{hallazgos: []uint64{2}, faltantes: []uint64{0}, suprimidos: [][2]uint64{{1, 3}}}},
		{"condición 4: X sellado dos veces, R cubre solo la primera copia",
			[]sellado{factura(x), factura(x), ajena(hx, 1), buena(hx, 0)},
			nil,
			esperado{hallazgos: []uint64{2}, faltantes: []uint64{1}, suprimidos: [][2]uint64{{0, 3}}}},
		{"X sellado dos veces, R cubre las dos",
			[]sellado{factura(x), factura(x), ajena(hx, 1), buena(hx, 1)},
			nil,
			esperado{suprimidos: [][2]uint64{{0, 3}, {1, 3}}, regularizad: [][2]uint64{{2, 3}}}},
		{"E no suprime ningún contenido anterior",
			[]sellado{factura(relleno), ajena(hx, 0), factura(x), buena(hx, 2)},
			[]Record{{Index: 0, Payload: relleno}},
			esperado{hallazgos: []uint64{1}, suprimidos: [][2]uint64{{2, 3}}}},
		{"varios R: se nombra el de menor índice",
			[]sellado{factura(x), ajena(hx, 0), buena(hx, 0), buena(hx, 0)},
			nil,
			esperado{suprimidos: [][2]uint64{{0, 2}}, regularizad: [][2]uint64{{1, 2}}}},
	} {
		t.Run(c.nombre, func(t *testing.T) {
			s, err := openLedger(t)
			if err != nil {
				t.Fatal(err)
			}
			apila(t, s, c.cadena...)
			rep, err := Reconcile(s, FromSlice(c.vivos), Options{Erasure: autoridad})
			if err != nil {
				t.Fatal(err)
			}
			compara(t, rep, c.want.hallazgos, c.want.faltantes, c.want.suprimidos, c.want.regularizad)
			for _, r := range rep.Regularized {
				if r.Reason == "" || r.AuthorizedBy != "erasureKey" || r.ErasureKey != hexDe(claveSupresion) {
					t.Errorf("regularizada sin motivo o sin la clave de R: %+v", r)
				}
			}
		})
	}
}

// compara coteja el informe con lo esperado: los eventos que son hallazgo, los bloques que
// faltan, los suprimidos y los regularizados, cada lista en su orden.
func compara(t *testing.T, rep *Report, hallazgos, faltantes []uint64, suprimidos, regularizados [][2]uint64) {
	t.Helper()
	var gh, gf []uint64
	for _, f := range rep.Findings {
		switch f.Status {
		case StatusUnauthorizedErasure:
			gh = append(gh, f.Index)
		case StatusMissing:
			gf = append(gf, f.Index)
		default:
			t.Errorf("hallazgo inesperado: %+v", f)
		}
	}
	var gs, gr [][2]uint64
	for _, x := range rep.Erased {
		gs = append(gs, [2]uint64{x.Index, x.ErasedBy})
	}
	for _, r := range rep.Regularized {
		gr = append(gr, [2]uint64{r.Index, r.RegularizedBy})
	}
	if !slices.Equal(gh, hallazgos) || !slices.Equal(gf, faltantes) || !slices.Equal(gs, suprimidos) || !slices.Equal(gr, regularizados) {
		t.Errorf("hallazgos %v (want %v), faltantes %v (want %v), suprimidos %v (want %v), regularizados %v (want %v)\n%+v",
			gh, hallazgos, gf, faltantes, gs, suprimidos, gr, regularizados, rep.Findings)
	}
	if rep.Regularized == nil {
		t.Error("regularized es nil: en el JSON saldría null")
	}
}

// ledgerEnMemoria es una cadena de bloques en memoria. Reconcile no comprueba firmas ni
// encadenamiento —eso es de la apertura—, así que basta con los headers.
type ledgerEnMemoria []*ledger.Block

func (l ledgerEnMemoria) Count() (int, error) { return len(l), nil }
func (l ledgerEnMemoria) Blocks(from, to uint64) ([]*ledger.Block, error) {
	return l[from:to], nil
}

// TestRotacionVector: testdata/vectors/erasure/rotacion.json, de punta a punta. Cada caso
// es una cadena dispersa; los índices que no trae se rellenan con registros propios que el
// sistema vivo conserva. Lo que el vector no tiene vivo falta o está suprimido, y el
// informe tiene que decir exactamente lo que el vector escribió a mano.
func TestRotacionVector(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "vectors", "erasure", "rotacion.json"))
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Origin string `json:"origin"`
		Cases  []struct {
			Name   string `json:"name"`
			Policy struct {
				ErasureKey         string            `json:"erasureKey"`
				RetiredErasureKeys map[string]uint64 `json:"retiredErasureKeys"`
			} `json:"policy"`
			Blocks []struct {
				Index       uint64 `json:"index"`
				Type        string `json:"type"`
				PayloadHash string `json:"payload_hash"`
				PayloadCID  string `json:"payload_cid"`
			} `json:"blocks"`
			Expected struct {
				Events []struct {
					Index uint64  `json:"index"`
					Key   *string `json:"key"`
				} `json:"events"`
				Erased []struct {
					Index    uint64 `json:"index"`
					ErasedBy uint64 `json:"erased_by"`
				} `json:"erased"`
				Missing     []uint64 `json:"missing"`
				Findings    []uint64 `json:"findings"`
				Regularized []struct {
					Index         uint64 `json:"index"`
					RegularizedBy uint64 `json:"regularized_by"`
				} `json:"regularized"`
			} `json:"expected"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	if len(v.Cases) < 10 {
		t.Fatalf("rotacion.json trae %d casos", len(v.Cases))
	}
	for _, c := range v.Cases {
		t.Run(c.Name, func(t *testing.T) {
			auth := erasure.Authority{Origin: v.Origin, Retired: c.Policy.RetiredErasureKeys}
			if c.Policy.ErasureKey != "" {
				k, _ := hex.DecodeString(c.Policy.ErasureKey)
				auth.Key = k
			}
			ultimo := c.Blocks[len(c.Blocks)-1].Index
			cadena := make(ledgerEnMemoria, ultimo+1)
			var vivos []Record
			for i := range cadena {
				p := []byte(fmt.Sprintf(`{"relleno":%d}`, i))
				sum := sha256.Sum256(p)
				cadena[i] = &ledger.Block{Header: ledger.Header{Index: uint64(i), Type: "relleno", PayloadHash: hex.EncodeToString(sum[:])}}
				vivos = append(vivos, Record{Index: uint64(i), Payload: p})
			}
			for _, b := range c.Blocks {
				cadena[b.Index] = &ledger.Block{Header: ledger.Header{Index: b.Index, Type: b.Type, PayloadHash: b.PayloadHash, PayloadCID: b.PayloadCID}}
				vivos = slices.DeleteFunc(vivos, func(r Record) bool { return r.Index == b.Index })
			}
			rep, err := Reconcile(cadena, FromSlice(vivos), Options{Erasure: auth})
			if err != nil {
				t.Fatal(err)
			}
			var sup, reg [][2]uint64
			for _, x := range c.Expected.Erased {
				sup = append(sup, [2]uint64{x.Index, x.ErasedBy})
			}
			for _, x := range c.Expected.Regularized {
				reg = append(reg, [2]uint64{x.Index, x.RegularizedBy})
			}
			compara(t, rep, c.Expected.Findings, c.Expected.Missing, sup, reg)

			// La clave de cada suprimido y de cada regularizado es la de su evento.
			clave := map[uint64]string{}
			for _, e := range c.Expected.Events {
				if e.Key != nil {
					clave[e.Index] = *e.Key
				}
			}
			for _, x := range rep.Erased {
				if x.ErasureKey != clave[x.ErasedBy] {
					t.Errorf("suprimido %d: clave %s, y su evento %d lo autorizó %s", x.Index, x.ErasureKey, x.ErasedBy, clave[x.ErasedBy])
				}
			}
			for _, r := range rep.Regularized {
				if r.ErasureKey != clave[r.RegularizedBy] {
					t.Errorf("regularizado %d: clave %s, y su evento %d lo autorizó %s", r.Index, r.ErasureKey, r.RegularizedBy, clave[r.RegularizedBy])
				}
			}
		})
	}
}
