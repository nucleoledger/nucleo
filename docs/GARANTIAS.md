# Garantías y límites de Núcleo

Qué afirma Núcleo, quién lo decidió y qué lo comprueba; y qué **no** afirma. Escrito en el
Sprint 16 (2026-10-10) a partir del README, de PROTOCOL.md, de CONCEPTO §6 y de los propios
tests, no de memoria. El mapa de cómo funciona por dentro es `docs/ARQUITECTURA.md`.

**Cómo se cita**, igual que en ARQUITECTURA: `ruta` o `ruta#Nombre`, sin números de línea.
`cmd/nucleo/mapa_test.go#TestElMapaNoCitaNadaQueNoExista` falla si algo citado aquí no existe.
Los tests de TypeScript son bloques `it(...)` y se citan por fichero; los de PHP, por fichero de
`sdk/php/test/`.

**«—» en la columna del ADR** significa que ningún ADR lo decide: lo fija PROTOCOL.md, el CONCEPTO
o RELEASING, como se indica.

**«Sin test»** significa exactamente eso: la afirmación está escrita, pero ningún test ni ensayo
del repositorio la fija. Este documento no añade tests; los señala.

---

## 1. Garantías

| # | lo que se afirma | dónde se afirma | lo decide | lo fija |
|---|---|---|---|---|
| G1 | La canonicalización es RFC 8785 (JCS), con los vectores oficiales | README «What works today»; PROTOCOL §1 | PROTOCOL §1 | `internal/jcs/jcs_test.go#TestVectors`; `sdk/ts/test/jcs.test.ts` |
| G2 | Cada bloque va firmado (Ed25519 sobre SHA-256) y encadenado; alterar uno rompe la cadena | README «What works today» | PROTOCOL §1 | `internal/ledger/block_test.go#TestVerifyChain`, `internal/ledger/block_test.go#TestSabotagesFromDemo` |
| G3 | Árbol de Merkle RFC 6962, con pruebas de inclusión y consistencia RFC 9162, contra los vectores oficiales | README «What works today»; PROTOCOL §2 | PROTOCOL §2 | `internal/ledger/merkle_vectors_test.go#TestRFC6962InclusionVectors`, `internal/ledger/merkle_vectors_test.go#TestRFC6962ConsistencyVectors`; `sdk/ts/test/merkle.test.ts` |
| G4 | La firma del bloque va dentro de la hoja (`leaf/v2`): una raíz cosignada fija todas las firmas | README «Security & audits»; PROTOCOL §2.1 | ADR-014 | `internal/ledger/leaf_test.go#TestLeafV2Vectors`, `internal/store/attested_test.go#TestVerifyFullCazaUnaFirmaInvalidaYaATESTIGUADA` |
| G5 | Las tablas de la historia son append-only (triggers que abortan UPDATE y DELETE) | README «What works today»; PROTOCOL §8 | ADR-009 | `internal/store/schema_test.go#TestAppendOnlyTriggers` |
| G6 | Una atestación solo cuenta si **verifica** contra claves que vienen de fuera del fichero | README «Limits we document» | ADR-016 | `internal/store/exploit_test.go#TestExploitAuditoriaCheckpointFalsificado`, `internal/store/attested_test.go#TestAttestedOpenDetectsHistoricalRewrite` |
| G7 | La política es la única raíz de confianza; con ella se rechaza una reescritura total autofirmada, y una política que no verifica nada se rechaza | README «Limits we document» | ADR-017 | `internal/store/exploit2_test.go#TestExploit2ReescrituraTotal`, `internal/store/policy_test.go#TestOpenWithWitnessesRechazaPoliticaQueNoVerificaNada`, `cmd/nucleo/cadena_ajena_test.go#TestCadenaMixtaAcusaAlIntrusoConPolitica` |
| G8 | La política es un formato de cable estricto, con la misma gramática en Go, TypeScript y PHP | README «Limits we document»; PROTOCOL §3.2 | ADR-018 | `internal/policy/vectors_test.go#TestVectoresDePolitica`, `cmd/nucleo/policy_test.go#TestPolicyFileEsFormatoDeCable`, `sdk/ts/test/policy.test.ts`, el diferencial de políticas `internal/receipt/diferencial_politica_test.go` |
| G9 | El testigo no cosigna una historia reescrita | README «Trust model» | ADR-011 | `internal/witness/witness_test.go#TestWitnessRejectsRewrittenHistory` |
| G10 | Restaurar un respaldo viejo del ledger se detecta en el siguiente `sync`, y la alarma no se olvida | README «Status» | ADR-009, ADR-011 | `internal/logsync/logsync_test.go#TestSyncDetectsLocalRollback`, `cmd/nucleo/operacion_test.go#TestElRollbackDetectadoNoSeOlvida`, `scripts/ensayo-testigo-mutuo.sh` |
| G11 | El log nunca firma dos raíces para el mismo tamaño, tampoco si muere entre firmar y cosignar | README «Security & audits» | ADR-009 | `internal/checkpoint/checkpoint_test.go#TestLogRefusesRollback`, `internal/logsync/durable_lock_test.go#TestLockSurvivesDeathBetweenSignAndCosign` |
| G12 | El testigo recuerda lo que cosignó tras reiniciarse | README «What works today» | ADR-011 | `internal/witness/http_test.go#TestWitnessRemembersAcrossRestart` |
| G13 | Los recibos se verifican sin red, con tres verificadores independientes que dan el mismo veredicto | README «What works today» | ADR-021 | `internal/receipt/vectors_export_test.go#TestVectoresGoldenDicenLaVerdad`, `sdk/ts/test/receipt.test.ts`, `sdk/php/test/run.php`, y el diferencial `sdk/ts/scripts/diferencial.mjs` sobre `internal/receipt/diferencial_test.go#TestDiferencialGeneraCatalogo` |
| G14 | Dos relojes: el declarado y el demostrable, que es el menor timestamp de las cosignatures aceptadas; sin testigo aceptado, el recibo dice «SIN TIEMPO DEMOSTRABLE» | README «Two clocks»; PROTOCOL §4 | ADR-002 | `internal/receipt/receipt_test.go#TestReceiptShowsBothClocks`, `internal/receipt/receipt_test.go#TestReceiptWithoutCosignatures`, `internal/receipt/receipt_test.go#TestUntrustedCosignatureGivesNoProvableTime` |
| G15 | El emisor firma el recibo entero, destinatario incluido | README «Limits we document» | ADR-015 | `internal/receipt/receipt_test.go#TestRecipientEstaCubiertoPorLaFirmaDelEmisor`, `internal/receipt/destinatario_test.go#TestDestinatarioQueImitaUnaLineaDeFirma` |
| G16 | El tiempo firmado tiene resolución de segundo | README «Security & audits» | ADR-019 | `internal/ledger/block_test.go#TestResolucionTemporal` |
| G17 | Sellar es idempotente con una clave y atómico: todo o nada, también con dos procesos a la vez | README «The CLI»; `cmd/nucleo/usage.go` | ADR-020 | `cmd/nucleo/idempotency_test.go#TestClaveDeIdempotenciaNoDuplicaElReintento`, `internal/store/record_test.go#TestAppendRecordEscribeTodoODaNada`, `cmd/nucleo/operacion_test.go#TestDosWorkersSellanALaVez` |
| G18 | Los campos adivinables que declara un perfil van como compromisos HMAC, inútiles sin la clave | README «Trust model» | ADR-003 | `internal/commit/commit_test.go#TestDictionaryIsUselessWithoutTheKey`, `cmd/nucleo/profile_test.go#TestSealProfileJSONLlevaCompromisos` |
| G19 | El contenido va cifrado (XChaCha20-Poly1305) con el AAD atado al tenant y al `payload_hash` | README «What works today»; PROTOCOL §5 | PROTOCOL §5 | `internal/vault/blob_test.go#TestBlobAADBinding` |
| G20 | La passphrase deriva la KEK con Argon2id, y una DEK envuelta corrupta o ajena falla ruidosamente | README «What works today»; PROTOCOL §6 | PROTOCOL §6 | `internal/vault/keys_test.go#TestArgon2idGolden`, `internal/vault/keys_test.go#TestWrappedDEKFailsLoudlyWhenCorrupt` |
| G21 | El respaldo SLIP-0039 se comprueba antes de enseñar las tarjetas | README «What works today» | ADR-004, ADR-010 | `internal/vault/backup_test.go#TestBackupVerifiesRoundTripBeforeReturning`, `internal/vault/slip39_vectors_test.go#TestSlip39OfficialVectors` |
| G22 | Borrar un contenido no rompe la cadena ni sus recibos | README «What works today»; PROTOCOL §5 | PROTOCOL §5 | `internal/vault/erase_test.go#TestEraseBlobLeavesLedgerProvable` —en la biblioteca: ningún comando de la CLI la llama (ver L18)— |
| G23 | ML-DSA-44 va como firma **adicional** en la nota del log, compatible con los verificadores C2SP | README «What works today» | ADR-007 | `internal/checkpoint/mldsa_test.go#TestMLDSAIsBackwardCompatible`, `internal/checkpoint/mldsa_test.go#TestLogEmitsBothSignatures` |
| G24 | Una comparación que no se puede hacer no se da por buena | README «Security & audits» | ADR-022 | `internal/store/h7_test.go#TestH7NoPoderCompararNoEsCompararBien` |
| G25 | La salida `--json` es un formato de cable, y todo error lleva su clase | README «The CLI»; `docs/CLI-JSON.md` | ADR-025, ADR-027 | `cmd/nucleo/clijson_vectors_test.go#TestVectoresCLIJSON`, `cmd/nucleo/clase_error_test.go#TestTodoObjetoDeErrorTraeSuClase`, `sdk/ts/test/contract.test.ts`, `sdk/php/test/contrato.php` |
| G26 | La alarma de frescura queda en el ledger y dura hasta que un `sync` la cierra; `seal` sella igual | README «Status» | ADR-028 | `cmd/nucleo/alarma_test.go#TestConElTestigoApagadoSeSellaYLaAlarmaQuedaRegistrada`, `internal/store/record_test.go#TestAlarmaDeFrescuraDuraHastaQueSeCierra` |
| G27 | Con política, la frescura sale de la cosignature verificada, nunca del registro local | README «Limits we document» | ADR-016 | `cmd/nucleo/freshness_test.go#TestFrescuraConPoliticaNoCaeAlRegistroLocal`, `cmd/nucleo/freshness_test.go#TestFrescuraVerificadaSaleDeLaCosignature` |
| G28 | Con dos tarjetas se fija una passphrase nueva, y morir a medias nunca deja el vault sin abrir | README «The CLI» | ADR-029 | `cmd/nucleo/restore_test.go#TestRestoreFijaPassphraseNueva`, `cmd/nucleo/restore_test.go#TestRestoreInterrumpidoNuncaDejaElVaultSinAbrir`, `internal/store/replacemeta_test.go#TestReplaceMetaMuertoAMediasNoDejaNada` |
| G29 | Un testigo atiende varios logs sin que se pisen la memoria; un log retirado deja de cosignarse, se recuerda y se publica; su clave comprueba su memoria | README «The CLI» | ADR-030 | `internal/witness/varios_test.go#TestVariosLogsNoSePisanLaMemoria`, `internal/witness/varios_test.go#TestLogRetiradoNoSeCosignaYConservaSuMemoria`, `internal/witness/varios_test.go#TestRetirarConOtraClaveSeRechaza`, `cmd/nucleo/testigo_varios_test.go#TestTestigoDeVariosLogs` |
| G30 | Dos instalaciones se pueden atestiguar mutuamente, y el rollback de una lo detecta el testigo de la otra | `docs/OPERACION.md` §1 | ADR-030 | `scripts/ensayo-testigo-mutuo.sh` (job `testigo-mutuo` del CI) |
| G31 | La reconciliación detecta un registro alterado en el sistema vivo | README «Status»; CONCEPTO §6 | — (CONCEPTO §3.1) | `internal/reconcile/reconcile_test.go#TestReconcileDetectsTheAlteredInvoice` |
| G32 | El perfil de Ecuador valida la clave de acceso con su dígito verificador | README «What works today» | — | `profiles/ecuador/ecuador_test.go#TestDigitoVerificadorGolden`, `cmd/nucleo/profile_test.go#TestSealProfileRechazaDigitoVerificador` |
| G33 | El SDK de TypeScript no tiene dependencias de runtime | README «What works today» | — | `sdk/ts/test/packaging.test.ts` |
| G34 | El binario publicado no contiene el código de los ganchos de prueba y rechaza sus variables | `docs/RELEASING.md` | — | `cmd/nucleo/hooks_test.go#TestProductionBinaryRefusesHooks` |
| G35 | El binario publicado se recompila byte a byte desde su tag | `docs/RELEASING.md` | — | **sin test**: comprobación a mano en cada release, registrada en la tabla de RELEASING |
| G36 | Los artefactos del release van firmados con cosign keyless | `docs/RELEASING.md` | — | **sin test** en el repositorio: lo hace `release.yml` y se comprueba a mano al verificar cada release |
| G37 | La página web verifica sin red | README «What works today» | — | **sin test** de que no use la red; `sdk/ts/test/bundle.test.ts` comprueba que el bundle da el mismo veredicto que la biblioteca |

---

## 2. Límites: lo que Núcleo NO garantiza

| # | lo que no se garantiza | dónde está documentado | lo demuestra |
|---|---|---|---|
| L1 | **Un testigo que pierde su memoria no detecta nada**: acepta cualquier historia como la primera | `docs/OPERACION.md` §1 «Testigo mutuo»; `deploy/witness/README.md` | `internal/logsync/logsync_test.go#TestSyncWithoutWitnessMemoryIsNotRollback`; y la prueba de potencia del ensayo mutuo (testigo con la base vacía), hecha a mano en el Sprint 15 y **no** automatizada |
| L2 | **Testigos compinchados**: un adversario que controla el testigo que tu política acepta, o dos empresas de acuerdo en un testigo mutuo, pueden cosignar lo que quieran | README «Limits we document»; `docs/OPERACION.md` §1 | **sin test** |
| L3 | **El dueño de todo sin recibos emitidos**: quien controla claves, ledger y todos los testigos, sin recibos en manos de otros, puede reescribir sin dejar rastro | CONCEPTO §6; PROTOCOL §10 | **sin test** |
| L4 | **La red puede impedir la detección**: con el log parado, reproducir un intercambio viejo hace que `sync` termine bien sin hablar con el testigo; solo delata que la atestación no rejuvenece | README «Limits we document» | `internal/logsync/replay_test.go#TestPostReproducidoNoPruebaContactoActual`, `cmd/nucleo/freshness_test.go#TestSyncAvisaDeUnaCosignatureVieja` |
| L5 | **Datos falsos desde el origen**: se certifica el *cuándo* y el *sin cambios*, no que sea verdad | CONCEPTO §6; PROTOCOL §10 | **sin test** (no es comprobable por construcción) |
| L6 | **El compromiso de la máquina antes del sellado**: la ventana se reduce, no se elimina | CONCEPTO §6 | **sin test** |
| L7 | **El `payload_hash` confirma un documento adivinable**: los compromisos por campo no suben la barrera por encima de la entropía del documento entero | README «Trust model» | ADR-023; **sin test** que lo demuestre |
| L8 | **Un recibo no prueba la entrega**, ni impide al emisor emitir otro para el mismo registro | README «Limits we document» | ADR-015; **sin test** |
| L9 | **Sin política, la frescura sale del propio fichero**: es un registro local, no verificado | README «Limits we document» | `cmd/nucleo/freshness_test.go#TestFrescuraNoSeFiaDelRegistroLocal` |
| L10 | **Los testigos no verifican las firmas de los bloques** | README «Limits we document» | ADR-014; `internal/store/exploit2_test.go#TestExploit2ReescrituraTotal` demuestra que una reescritura autofirmada solo se rechaza con política |
| L11 | **Una passphrase robada no se arregla cambiándola**: la DEK y las claves de firma no cambian | ADR-029, enmienda §F; `docs/OPERACION.md` §3 | **sin test** del límite en sí; `cmd/nucleo/restore_test.go#TestSealYaDesbloqueadoDuranteRestore` fija lo que sí ocurre (un sellado ya desbloqueado termina) |
| L12 | **Una copia del ledger anterior a un cambio de passphrase se sigue abriendo con las tarjetas viejas** | ADR-029 §B; `docs/TUTORIAL-es.md` | comprobado a mano en el Sprint 14, **sin test** automatizado; `cmd/nucleo/docs_test.go#TestElTutorialDiceLoQueRestoreNoHace` solo vigila que el tutorial lo diga |
| L13 | **Borrar un secreto de memoria no garantiza que no haya copias** | ADR-029, enmienda §G | **sin test** (no se puede escribir uno que sea verdad); `cmd/nucleo/secretos_test.go#TestLaCLINoRecibeLaDEK` fija la parte estructural |
| L14 | **ML-DSA-44 solo protege una firma**: las cosignatures de los testigos siguen siendo Ed25519 | README «What works today» | `internal/checkpoint/mldsa_test.go#TestMLDSAIsBackwardCompatible` |
| L15 | **Un VRF da verificabilidad, no privacidad**; el compromiso del ledger es y seguirá siendo HMAC | README «Limits we document»; enmienda de CONCEPTO | ADR-003 y ADR-012; **sin test** (el VRF no está implementado) |
| L16 | **El perfil de acta de SAS no está conectado a la CLI** | README «What works today» | `cmd/nucleo/profile_test.go#TestPerfilesExpuestos` |
| L17 | **En un testigo mutuo, cada empresa opera un servicio para la otra**: si uno se cae, la alarma de la otra suena por algo que no puede arreglar | `docs/OPERACION.md` §1 | **sin test** |
| L18 | **La supresión es la mitad técnica de un derecho de borrado, no una opinión legal** —y hoy la CLI no la ofrece: existe en la biblioteca, sin comando— | README «What works today»; PROTOCOL §5 | `internal/vault/erase_test.go#TestEraseBlobLeavesLedgerProvable` (biblioteca); **sin test** de CLI, porque no hay comando |
| L19 | **No ha habido auditoría profesional de seguridad** | README «Security & audits» | — |
