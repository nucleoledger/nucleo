// Recibo de ejemplo, COPIADO de testdata/vectors/receipt/valido-1-cosignature.json.
// Está aquí para que la página se pueda probar sin un despliegue delante.
// No es un recibo real de nadie: sus claves son de prueba.
//
// GENERADO por sdk/ts/scripts/ejemplo.mjs dentro de `npm run bundle`. No se
// edita a mano: si el formato del recibo cambia, el vector cambia y este fichero
// se regenera. Que estuviera viejo lo detecta sdk/ts/test/bundle.test.ts.
window.NUCLEO_EJEMPLO = {
  "receipt": "nucleo.org/receipt@v1\ndestinatario      : María Pérez (cédula 1712345678)  (anotado por el emisor, no firmado)\nemisor (tenant)   : 1790012345001\ntipo de registro  : sri.factura.v1\nhash del contenido: 6b75de6c86109aadce553f98c7a55767f3feebb7fef8df1a8e52b97a23f6439d\nbloque            : 2\n\nTIEMPO DECLARADO  : 2026-09-06T14:32:00Z  (declarado por el sistema emisor)\nTIEMPO DEMOSTRABLE: 2026-09-06T15:00:00Z  (atestiguado por testigos)\n\nADVERTENCIA LEGAL\nEste recibo es evidencia técnica de integridad y tiempo. No constituye por sí\nmismo un acto público, una certificación notarial ni un pronunciamiento de\nautoridad. Su valor probatorio lo determina un perito o un juez.\n\n--- prueba verificable ---\n{\"index\":2,\"payload_cid\":\"blob://x\",\"payload_hash\":\"6b75de6c86109aadce553f98c7a55767f3feebb7fef8df1a8e52b97a23f6439d\",\"prev_hash\":\"b86f29fb74ba110fae869e4b827208269a2d3a330cb50c3ccb55f4417b1a911d\",\"signer_pubkey\":\"79b5562e8fe654f94078b112e8a98ba7901f853ae695bed7e0e3910bad049664\",\"tenant\":\"1790012345001\",\"timestamp\":\"2026-09-06T14:32:00Z\",\"type\":\"sri.factura.v1\"}\nc2sp.org/tlog-proof@v1\n2\nxOhUVzyARU23vHkMtkVJ4y7LyEKGNtfOyV1zBNBqN7M=\n+gGvG+l+y0s9srMF+HmQ9tXJuVj+0WJdOGrF83+fOSg=\nPi11jt5WE0DGrD2KL+/e2E0TkKTQC/zr4XbLDZWAh8M=\n\nnucleoledger.com/recibos\n5\nzskn84s97pizKDh6YIJ2cWTOUA4zcWUxL7zmlh7Rt4g=\n\n— nucleoledger.com/recibos O0zkALS6PItaJH+VC289ZBzrYsb7xePmn2CAJpRBButDQwxCBimslaUmSOWqzRv4Drj4t4xCsAjXOpWJoCu/xCCcAwc=\n— witness.example/w1 D3og2AAAAABqnX/wMYluZnTcuCWSNUsNysjhUbHMvyxQ7zy/t65M0+g9n9OOyfCkY9zImJxJteSvTnWG0muRW0PRoEpn/s+PK4daCg==\n",
  "policy": {
    "origin": "nucleoledger.com/recibos",
    "logKey": "5e423033044f56a13a686799487bcbfa63dd1e39204cec27dd39a26daa615628",
    "witnesses": {
      "witness.example/w1": "1e985ffbe45a77ee58253c6b392ae9272442cee842cec49dbf88fbb0fffd16a8"
    },
    "quorum": 1
  }
};
