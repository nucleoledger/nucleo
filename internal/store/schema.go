package store

// schemaSQL es el esquema congelado en docs/adr/ADR-009-store-schema.md.
// Cualquier cambio exige un ADR nuevo: hay ficheros de clientes en juego.
const schemaSQL = `
CREATE TABLE IF NOT EXISTS blocks (
    idx         INTEGER PRIMARY KEY,
    hash        TEXT UNIQUE NOT NULL CHECK(length(hash) = 64),
    header_json TEXT NOT NULL,
    signature   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS blobs (
    payload_hash TEXT PRIMARY KEY CHECK(length(payload_hash) = 64),
    ciphertext   BLOB NOT NULL,
    nonce        BLOB NOT NULL,
    created_at   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS checkpoints (
    tree_size INTEGER PRIMARY KEY,
    note      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS vault_meta (
    k TEXT PRIMARY KEY,
    v BLOB NOT NULL
);

-- El ledger es append-only. Estos disparadores son una barandilla contra el
-- error y el atacante perezoso; la frontera de seguridad son los testigos.
CREATE TRIGGER IF NOT EXISTS blocks_no_update
BEFORE UPDATE ON blocks
BEGIN
    SELECT RAISE(ABORT, 'nucleo: ledger append-only');
END;

CREATE TRIGGER IF NOT EXISTS blocks_no_delete
BEFORE DELETE ON blocks
BEGIN
    SELECT RAISE(ABORT, 'nucleo: ledger append-only');
END;

CREATE TRIGGER IF NOT EXISTS checkpoints_no_update
BEFORE UPDATE ON checkpoints
BEGIN
    SELECT RAISE(ABORT, 'nucleo: ledger append-only');
END;

CREATE TRIGGER IF NOT EXISTS checkpoints_no_delete
BEFORE DELETE ON checkpoints
BEGIN
    SELECT RAISE(ABORT, 'nucleo: ledger append-only');
END;

-- blobs SÍ admite DELETE: es el borrado de datos personales de la LOPDP. Lo que
-- no admite es UPDATE, porque sustituir un texto cifrado por otro bajo el mismo
-- payload_hash sería reescribir el contenido sin tocar el ledger.
CREATE TRIGGER IF NOT EXISTS blobs_no_update
BEFORE UPDATE ON blobs
BEGIN
    SELECT RAISE(ABORT, 'nucleo: ledger append-only');
END;
`
