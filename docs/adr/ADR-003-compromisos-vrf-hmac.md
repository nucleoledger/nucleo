# ADR-003-compromisos-vrf-hmac

**Estado:** aceptada · **Fecha:** 2026-08-31 · **Fuentes:** docs/CONCEPTO-v1.2-es.md §9

Los datos adivinables nunca se comprometen como hash desnudo. VRF vrf-r255 (RFC 9381 style) cuando se requiera verificabilidad por terceros sin revelar la clave; HMAC-SHA-256 con clave del tenant para lo interno. Blobs cifrados borrables satisfacen supresion LOPDP; redaccion oficial: disenado para alinearse, nunca certificado sin dictamen.
