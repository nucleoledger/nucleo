// @nucleoledger/verify — verificador offline de recibos de Núcleo.
//
// Sin dependencias de runtime: Ed25519 y SHA-256 salen de WebCrypto.

export { verifyReceipt, parseReceipt, receiptText, MAGIC, SEPARATOR, NO_PROVABLE_TIME } from "./receipt.js";
export type { Policy, Result, BlockHeader } from "./receipt.js";
export { parseNote, keyId, ALG_ED25519, ALG_COSIGNATURE_V1 } from "./note.js";
export type { Note, Sig } from "./note.js";
export { parseCheckpoint } from "./checkpoint.js";
export type { Checkpoint } from "./checkpoint.js";
export { parseProof } from "./proof.js";
export type { TlogProof } from "./proof.js";
export { verifyInclusion, leafHash, nodeHash } from "./merkle.js";
export { sha256, verifyEd25519, ed25519Available } from "./crypto.js";
export { fromHex, toHex, fromBase64, toBase64, utf8, equal } from "./bytes.js";
