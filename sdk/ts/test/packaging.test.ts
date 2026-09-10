import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

// El paquete 0.1.0-alpha.0 se publicó a mano con --provenance=false, porque la
// procedencia exige un token OIDC que solo tiene el CI y porque la
// configuración de trusted publisher de npm no se puede crear antes de que el
// paquete exista.
//
// Esa excepción ya se gastó. Desde ahora se publica desde
// .github/workflows/publish-npm.yml, y este test es lo que impide que
// publishConfig.provenance vuelva a perderse sin que nadie se entere: quitarlo
// no rompería ninguna compilación ni ningún verificador, solo haría que la
// siguiente versión saliera sin cadena hacia el commit que la produjo, y eso no
// se nota mirando el paquete.

const raw = readFileSync(fileURLToPath(new URL("../package.json", import.meta.url)), "utf8");
const pkg = JSON.parse(raw) as {
  name: string;
  dependencies?: Record<string, string>;
  publishConfig?: { access?: string; provenance?: boolean };
  repository?: { url?: string };
};

describe("package.json sostiene lo que el paquete promete", () => {
  it("publishConfig.provenance sigue en true", () => {
    expect(pkg.publishConfig?.provenance).toBe(true);
  });

  it("el scope se publica público, no restringido", () => {
    // Un paquete con scope es privado por omisión en npm: sin esto, el publish
    // falla con 402 en una cuenta sin plan pago.
    expect(pkg.publishConfig?.access).toBe("public");
  });

  it("la URL del repositorio es la que npm exige para la procedencia", () => {
    // npm compara esta URL con el repositorio que publica, y distingue
    // mayúsculas. Si no coincide, rechaza la atestación.
    expect(pkg.repository?.url).toBe("git+https://github.com/nucleoledger/nucleo.git");
  });

  it("cero dependencias de runtime", () => {
    // Es la primera línea del README y la razón por la que el verificador puede
    // auditarse leyéndolo. Un `npm install` distraído la borraría.
    expect(Object.keys(pkg.dependencies ?? {})).toEqual([]);
  });
});
