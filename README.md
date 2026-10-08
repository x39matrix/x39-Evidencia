# X-39 Evidencia

X-39 Evidencia is a proof-of-existence layer for documents.
1. The SHA-256 of the file is computed on the user's device; the file itself never leaves it (on the web, text typed into the site is sent to the service, and the site says so).
2. That hash is anchored in Bitcoin through OpenTimestamps; proofs verify against any Bitcoin node, and the reference deployment verifies them against our own full node.
3. Where a legally recognised time is needed, the same hash receives an RFC 3161 qualified timestamp from ANF AC, a qualified trust service provider listed in the EU and Spanish trusted lists; the chain is verified with openssl against the ANF root, and the TSA certificate in that chain is cross-checked against the certificate registered in the Spanish trusted list.
4. Proofs may carry an ML-DSA-87 (FIPS 204) co-signature produced on an air-gapped machine and verified against a published key fingerprint; it is optional, and its absence is reported, not hidden.
5. Everything is verifiable with free tools and without trusting X-39. The code is AGPL-3.0. This is not a notary and not a qualified electronic signature.

## Verify it yourself

These commands use the files of the Evidence Bundle v1. Run them from the bundle folder.

**Requirements:**
- Python 3 with `cryptography` and `pqcrypto` (ML-DSA-87);
- OpenSSL;
- the OpenTimestamps client (`pip install opentimestamps-client`) for the Bitcoin step.

**1. Integrity of every file in the bundle.** `MANIFEST` lists the SHA-256 of every other file.

```sh
sha256sum -c MANIFEST
```

**2. The agreement proof, offline.** This checks the proof hash, the chat chain, the per-message Ed25519 signatures and the COLD ML-DSA-87 co-signature against the fingerprint pinned in `verify_bundle.py`. `--skip-ots` leaves out the Bitcoin step, and the output says so.

```sh
python3 verify_bundle.py 31e1cf09a5b2a74cd978.zip --skip-ots
```

Expected: `VALID (OTS omitido)`. Add `--content <original file>` to check that the sealed `content_hash` is your file.

**3. The RFC 3161 qualified timestamp.** The `.cadena.pem` chain ends at the TSA certificate, not at the root. So `-CAfile` must be the ANF root and the chain goes in `-untrusted`:

```sh
D=2O-ACTA-DEL-PLENO-MUNICIPAL-EXTRAORDINARIO-PRESUPUESTO-2026-01-29.pdf
openssl ts -reply -in "$D.tsr" -text
openssl ts -verify -data "$D" -in "$D.tsr" -CAfile anf_root.pem -untrusted "$D.cadena.pem"
openssl x509 -in anf_root.pem -noout -fingerprint -sha256
```

Expected: `Verification: OK`. The root is ANF Global Root CA, SHA-256 `E0:AF:BD:2C:0E:E9:5A:68:CD:9A:3C:59:0B:2D:3F:E0:7C:0A:6D:0B:E7:96:AE:52:91:E4:24:D4:77:92:17:8E`. The Spanish trusted list registers the TSA service certificate (`AF:BC:8E:2D:54:6C:A7:49:9D:8A:81:04:A7:65:B0:0D:2A:30:F3:B0:27:53:94:D6:7A:8D:60:C0:3D:01:63:B5`), which travels in the chain and is issued by that root. You reach that list from the European Commission's list of trusted lists: <https://ec.europa.eu/tools/lotl/eu-lotl.xml>.

**4. The Bitcoin anchor.**

- With your own Bitcoin node, nothing depends on a third party. Use either of these:

  ```sh
  ots verify "$D.ots"
  python3 verify_bundle.py 31e1cf09a5b2a74cd978.zip --bitcoin-node http://user:pass@127.0.0.1:8332
  ```

- Without a node, upload the file and its `.ots` to <https://opentimestamps.org>. That check relies on that service.
- `ots info` only reads the proof. It does not check it against Bitcoin.

## Links

- **Web:** <https://x39matrix.org>. Public verifier: <https://x39matrix.org/verificar>.
- **Android app (X-39 Evidencia 0.3.3):** [Releases](https://github.com/x39matrix/x39-Evidencia/releases). Each release lists the APK SHA-256, the signing-certificate fingerprint, the qualified timestamp and the `.ots` proof.
- **Evidence Bundle v1:** [release `bundle-v1`](https://github.com/x39matrix/x39-Evidencia/releases/tag/bundle-v1). The ZIP `x39-bundle-v1.zip` has SHA-256 `2c93b6c74071139f4201cfbd6012cc4391ebe8430cf7b2f7eced34cc7121a0ce`.
- **Documentation and audits:** [`docs/`](docs/).
- **Offline verifier:** [`verify_bundle.py`](verify_bundle.py).
- **Air-gapped COLD signer and key ceremony:** [`pi500/`](pi500/).

## Repository

- `frontend/`: the web (React).
- `backend/`: the API (FastAPI, MongoDB).
- `pi500/`: the air-gapped ML-DSA-87 signer and its runbooks.
- `verify_bundle.py`: the reference offline verifier.
- `docs/`: audits and the independent verification record.
- `deploy/`: deployment notes.

## License

[AGPL-3.0](LICENSE). If you run a modified version as a service, you must publish its source.

**Development transparency:** how generative AI is used in this project is described in [GENAI.md](GENAI.md).

Author: X39matrix.
