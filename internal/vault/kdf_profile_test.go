package vault

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"
)

// Los perfiles de KDF existen por un hallazgo de la revisión externa que es una
// contradicción interna del proyecto, no un detalle de ajuste: ADR-005 eligió la
// CLI porque en hosting compartido no caben los daemons, y a la vez el vault pide
// 64 MiB × 4 lanes de Argon2id, que es lo que un plan compartido mata primero.
//
// Lo que se prueba aquí es lo que hace utilizable el perfil: que los parámetros
// se GUARDEN y que Unlock use los guardados, no las constantes del código. Sin
// eso, un vault creado con el perfil reducido sería imposible de abrir con una
// versión futura que hubiera subido los valores por omisión.

func TestParamsForPerfiles(t *testing.T) {
	salt := bytes.Repeat([]byte{7}, SaltLen)

	// Los números NO se comparan contra las constantes del paquete: se escriben
	// literales, tomados de las guías. Compararlos con las constantes sería
	// comparar el código consigo mismo.
	for _, c := range []struct {
		profile            KDFProfile
		time               uint32
		memoryKiB          uint32
		threads            uint8
		nombre             string
		fuenteDeLosNumeros string
	}{
		{ProfileDefault, 3, 65536, 4, "default",
			"RFC 9106 §4, segunda opción recomendada: t=3, p=4, m=2^16 (64 MiB)"},
		{ProfileConstrained, 2, 19456, 1, "constrained",
			"OWASP Password Storage Cheat Sheet, mínimo: 19 MiB, t=2, p=1"},
	} {
		t.Run(c.nombre, func(t *testing.T) {
			p, err := ParamsFor(c.profile, salt)
			if err != nil {
				t.Fatal(err)
			}
			if p.Time != c.time || p.Memory != c.memoryKiB || p.Threads != c.threads {
				t.Errorf("t=%d m=%d p=%d; se esperaba t=%d m=%d p=%d (%s)",
					p.Time, p.Memory, p.Threads, c.time, c.memoryKiB, c.threads, c.fuenteDeLosNumeros)
			}
			if p.Profile() != c.nombre {
				t.Errorf("Profile() = %q, want %q", p.Profile(), c.nombre)
			}
			if err := p.Validate(); err != nil {
				t.Errorf("los parámetros del perfil no validan: %v", err)
			}
		})
	}

	// El perfil vacío es el por omisión: una configuración sin rellenar no debe
	// producir un vault sin cifrado utilizable ni un error oscuro.
	if p, err := ParamsFor("", salt); err != nil || p.Profile() != string(ProfileDefault) {
		t.Errorf("perfil vacío → %v, %v; se esperaba el por omisión", p.Profile(), err)
	}
	if _, err := ParamsFor("barato", salt); !errors.Is(err, ErrProfile) {
		t.Errorf("err = %v, want ErrProfile", err)
	}
}

func TestUnlockHonraLosParametrosGuardados(t *testing.T) {
	pass := []byte("correcta caballo bateria grapa")

	t.Run("un vault constrained se abre con los suyos", func(t *testing.T) {
		ms := newMemStore()
		v, err := CreateWithProfile(ms, "log/uno", pass, ProfileConstrained)
		if err != nil {
			t.Fatal(err)
		}
		dek := append([]byte(nil), v.dek...)
		v.Close()

		// Lo que quedó guardado es el perfil reducido, no el por omisión.
		var stored Params
		raw, err := ms.GetMeta(MetaParamsKey)
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(raw, &stored); err != nil {
			t.Fatal(err)
		}
		if stored.Profile() != string(ProfileConstrained) {
			t.Fatalf("se guardó %q, want constrained", stored.Profile())
		}

		again, err := Unlock(ms, pass)
		if err != nil {
			t.Fatalf("un vault creado con el perfil reducido no se pudo abrir: %v", err)
		}
		defer again.Close()
		if !bytes.Equal(dek, again.dek) {
			t.Error("la DEK recuperada no es la misma")
		}
	})

	t.Run("si se cambian los parámetros guardados, Unlock FALLA", func(t *testing.T) {
		// Este es el test que de verdad demuestra que Unlock usa lo guardado.
		// Que un vault constrained se abra podría explicarse por casualidad si
		// Unlock usara las constantes y estas coincidieran; aquí se sustituyen los
		// parámetros por otros válidos y el resultado tiene que ser un fallo: con
		// otros parámetros sale otra KEK, y la DEK envuelta no se desenvuelve.
		ms := newMemStore()
		v, err := CreateWithProfile(ms, "log/dos", pass, ProfileConstrained)
		if err != nil {
			t.Fatal(err)
		}
		v.Close()

		var stored Params
		raw, _ := ms.GetMeta(MetaParamsKey)
		if err := json.Unmarshal(raw, &stored); err != nil {
			t.Fatal(err)
		}
		suplantado := DefaultParams(stored.Salt) // mismo salt, otros costes
		encoded, err := json.Marshal(suplantado)
		if err != nil {
			t.Fatal(err)
		}
		if err := ms.PutMeta(MetaParamsKey, encoded); err != nil {
			t.Fatal(err)
		}
		if _, err := Unlock(ms, pass); err == nil {
			t.Fatal("Unlock abrió el vault con parámetros distintos de los de creación: " +
				"eso significaría que no está usando los guardados")
		}
	})
}

// TestPerfilPersonalizadoSeNombraComoTal: un vault con parámetros que no
// coinciden con ningún perfil no se etiqueta con el nombre del más parecido.
// Decirle "default" a algo que no lo es sería mentir en la salida de init.
func TestPerfilPersonalizadoSeNombraComoTal(t *testing.T) {
	p := Params{Time: 5, Memory: 32 * 1024, Threads: 2, KeyLen: KeyLen, Salt: bytes.Repeat([]byte{1}, SaltLen)}
	if got := p.Profile(); got != "personalizado" {
		t.Errorf("Profile() = %q, want \"personalizado\"", got)
	}
}
