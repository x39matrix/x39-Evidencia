# X-39 Evidencia

X-39 Evidencia is a proof-of-existence layer for documents.

> [!WARNING]
> **Status: test release.** X-39 Evidencia 0.3.4 is a test version, not the final one. It has not been audited by any independent third party; that audit is pending. The verifier has passed internal, reproducible tests. Do not rely on this build for critical use.
> This applies to the app, not to the evidence it produces: a Bitcoin anchor or an ANF qualified timestamp, once issued, is real and anyone can verify it.
> Every release publishes its APK SHA-256, signing-certificate fingerprint, qualified timestamp and `.ots` proof, so you can check the evidence yourself instead of trusting this notice.

1. In the website flow, the SHA-256 is computed in the browser and the file bytes stay in that browser; only the SHA-256 digest is sent to the service; the file name is not. This statement describes the website only. In the Android evidence app, sealing/anchoring sends a 32-byte commitment derived from the fingerprint to timestamp calendars. If the user chooses to send a capsule to a paired phone, the original is sent end-to-end encrypted.
2. That hash is anchored in Bitcoin through OpenTimestamps; proofs verify against any Bitcoin node, and the reference deployment verifies them against our own full node.
3. Where a legally recognised time is needed, the same hash receives an RFC 3161 qualified timestamp from ANF AC, a qualified trust service provider listed in the EU and Spanish trusted lists; the chain is verified with openssl against the ANF root, and the TSA certificate in that chain is cross-checked against the certificate registered in the Spanish trusted list.
4. Proofs may carry an ML-DSA-87 (FIPS 204) co-signature produced on an air-gapped machine and verified against a published key fingerprint; it is optional, and its absence is reported, not hidden.
5. Everything is verifiable with free tools and without trusting X-39. The code is AGPL-3.0. This is not a notary and not a qualified electronic signature.

## Verify it yourself

There are two independent checks. **A** takes a real seal all the way to the reference verifier's `VALID [0]`. **B** reproduces the published Evidence Bundle v1, including its qualified timestamp.

Exit codes of `verify_bundle.py`: `0` VALID; `5` VALID with warnings; `6` CONSISTENT — the required document-hash, manifest/format and Bitcoin-anchor checks pass, but the package has no COLD co-signature (applied after sealing, offline). Warnings outside that scope may remain; this is not COLD attestation or approval; `1` integrity, `2` signature, `3` anchor not verified; `4` usage or container.

### Set up once

```sh
python3 -m venv .venv
. .venv/bin/activate
pip install cryptography pqcrypto opentimestamps-client
```

`opentimestamps-client` installs both the `ots` command and the `opentimestamps` Python library into the same environment, and the verifier needs both. An `ots` installed separately (for example with pipx) is not enough: the verifier imports the library from its own interpreter. You also need OpenSSL for step B3.

The Bitcoin step needs a Bitcoin node. If Bitcoin Core runs on the same machine, `ots` finds it through `~/.bitcoin/bitcoin.conf` (cookie or `rpcuser`/`rpcpassword`) and no option is needed. Otherwise pass `--bitcoin-node http://<rpcuser>:<rpcpassword>@<host>:8332` with real credentials; the literal `user:pass` gets `401 Unauthorized`.

### A. The demo seal, end to end

The demo agreement `demo0000demo0001` ("Contrato de diseno — Ana y Beto (demo)") is a real seal: co-signed with the production COLD key pinned in `verify_bundle.py` and anchored in Bitcoin. Its document is public, so you can supply it with `--content`. From a clone of this repository:

```sh
git clone https://github.com/x39matrix/x39-Evidencia && cd x39-Evidencia
python3 -c "import ast; t = next(n.value for n in ast.walk(ast.parse(open('backend/notaria.py', encoding='utf-8').read())) if isinstance(n, ast.Constant) and isinstance(n.value, str) and n.value.startswith('CONTRATO DE SERVICIOS FREELANCE\n\n')); open('contrato.txt','wb').write(t.encode('utf-8'))"
sha256sum testdata/bundle_v1_prod.zip contrato.txt
python3 verify_bundle.py testdata/bundle_v1_prod.zip --content contrato.txt
```

Expected hashes: `a648c11a00e3420e27e2a8e27ce0b6830e4b920fcd318335f5c30d6bd1505911` for the bundle and `d854b7e34a56b6a17289446d2ff8ff55236dc53cdf00b81d53bf81e680fbf937` for the document (the sealed `content_hash`).

The verifier prints in Spanish. Expected output, abridged:

```text
  OTS Bitcoin: rama confirmada - bloque '957242' - Merkle 'ea27277f…'
  OTS Bitcoin: rama confirmada - bloque '957246' - Merkle '384ddf6b…'
  OTS Bitcoin: rama confirmada - bloque '957244' - Merkle '9356c7a4…'
  ...
  co-firma:    COLD ML-DSA-87 valida - clave PINEADA '8453a25a41d6fe8fcb5647600f042a7c303daaca79b80928534025711981c6a1'
  ...
  NO cubiertos: ninguno
VALID [0]
[FIN VEREDICTO]
```

A verdict only counts if the output ends with `[FIN VEREDICTO]`. `VALID [0]` means: the COLD co-signature over `proof.json` is valid with the pinned key, your document matches the sealed `content_hash`, and every Bitcoin branch of the proof was confirmed against your node. It does not prove authorship beyond control of the keys, nor that the contents are true. The output lists which files the verdict covers and which it does not.

Partial checks never approve:

- With `--content` and `--skip-ots`, the verifier checks everything except Bitcoin and ends with `INVALID[3]: VERIFICACION INCOMPLETA: OTS NO COMPROBADO (--skip-ots); no se emite VALID`. It means the check is unfinished, not that the evidence is bad.
- Without `--content` there is no `VALID [0]`. Unless an earlier failure is reported first, the result is `ERROR USO/CONTENEDOR [4]: DOCUMENTO NO COMPROBADO`: the document was not supplied. It says nothing about the evidence.
- Without a reachable Bitcoin node the anchor cannot be confirmed and there is no `VALID [0]`. The verifier reports this as `INVALID[3]: ANCLA NO COMPROBADA: no hay nodo Bitcoin accesible (el RPC no responde o falta su configuracion); la rama Bitcoin '957242' queda sin confirmar. Sin nodo no hay VALID; esto no indica que la evidencia sea falsa. Use un nodo Bitcoin propio (bitcoin.conf local) o --bitcoin-node URL`. If the node rejects the RPC credentials, the reason reads `el nodo Bitcoin rechazo las credenciales RPC (401 Unauthorized)` instead. Either way it means the anchor was not checked, not that the evidence is bad. To compare without a node, extract `proof.json` and `proof.json.ots` from the ZIP and upload them to <https://opentimestamps.org>; that check relies on that service.

Exit codes: `0` VALID; `5` VALID with warnings; `6` CONSISTENT (required checks pass, but the COLD co-signature is absent; NOT VALID); `1` integrity; `2` signature; `3` Bitcoin anchor not confirmed (also `--skip-ots`); `4` usage or environment.

### B. The published Evidence Bundle v1

Download `x39-bundle-v1.zip` from the [`bundle-v1` release](https://github.com/x39matrix/x39-Evidencia/releases/tag/bundle-v1), check its SHA-256 (see [Links](#links)), unzip it and run these commands from the bundle folder.

**1. Integrity of every file in the bundle.** `MANIFEST` lists the SHA-256 of every other file.

```sh
sha256sum -c MANIFEST
```

**2. The agreement proof.** The bundle ships the `verify_bundle.py` it was published with, an earlier and more lenient version than the reference verifier in this repository. It checks the proof hash, the chat chain, the per-message Ed25519 signatures and the COLD ML-DSA-87 co-signature against the pinned fingerprint.

```sh
python3 verify_bundle.py 31e1cf09a5b2a74cd978.zip --skip-ots
```

Expected: `VALID (OTS omitido)`. That is a partial result: the Bitcoin step was skipped. Without `--skip-ots`, and with a node as described above, the expected result is `VALID`.

This agreement's document is encrypted and not published, so this bundle cannot reach the reference verifier's `VALID [0]`, which requires the document. Use check A for that.

**3. The RFC 3161 qualified timestamp.** The `.cadena.pem` chain ends at the TSA certificate, not at the root. So `-CAfile` must be the ANF root and the chain goes in `-untrusted`:

```sh
D=2O-ACTA-DEL-PLENO-MUNICIPAL-EXTRAORDINARIO-PRESUPUESTO-2026-01-29.pdf
openssl ts -reply -in "$D.tsr" -text
openssl ts -verify -data "$D" -in "$D.tsr" -CAfile anf_root.pem -untrusted "$D.cadena.pem"
openssl x509 -in anf_root.pem -noout -fingerprint -sha256
```

Expected: `Verification: OK`. The root is ANF Global Root CA, SHA-256 `E0:AF:BD:2C:0E:E9:5A:68:CD:9A:3C:59:0B:2D:3F:E0:7C:0A:6D:0B:E7:96:AE:52:91:E4:24:D4:77:92:17:8E`. The Spanish trusted list registers the TSA service certificate (`AF:BC:8E:2D:54:6C:A7:49:9D:8A:81:04:A7:65:B0:0D:2A:30:F3:B0:27:53:94:D6:7A:8D:60:C0:3D:01:63:B5`), which travels in the chain and is issued by that root. You reach that list from the European Commission's list of trusted lists: <https://ec.europa.eu/tools/lotl/eu-lotl.xml>.

**4. The Bitcoin anchor of the document.**

- With your own Bitcoin node, nothing depends on a third party:

  ```sh
  ots verify "$D.ots"
  ```

  Expected: `Success! Bitcoin block 966822 attests existence as of 2026-09-13` (the date is shown in your local time zone). The proof carries several Bitcoin attestations; `ots verify` reports the earliest.
- Without a node, upload the file and its `.ots` to <https://opentimestamps.org>. That check relies on that service.
- `ots info` only reads the proof. It does not check it against Bitcoin.

### C. The test suite

The verifier ships with its adversarial test suite (mutated ZIP containers, forged
signatures, altered documents, terminal-escape injection, resource limits). It runs
offline: no network, no signing, no Bitcoin node. The macOS container tests use real
archives produced on a Mac by [`x39-fixtures-macos`](https://github.com/x39matrix/x39-fixtures-macos);
clone it next to this repository or those tests are skipped.

```sh
git clone https://github.com/x39matrix/x39-fixtures-macos
git clone https://github.com/x39matrix/x39-Evidencia && cd x39-Evidencia
pip install pytest
python3 -m pytest tests/
```

Expected: every test passes (494 as of commit `65a9b89c`). Node.js is needed by the
tests that compare the Python verifier with the JavaScript ZIP reference.

## Links

- **Web:** <https://x39matrix.org>. Public verifier: <https://x39matrix.org/verificar>.
- **Android app (X-39 Evidencia 0.3.4, test release, not audited):** [Releases](https://github.com/x39matrix/x39-Evidencia/releases). Each release lists the APK SHA-256, the signing-certificate fingerprint, the qualified timestamp and the `.ots` proof.
- **Demo seal:** [`testdata/bundle_v1_prod.zip`](testdata/bundle_v1_prod.zip), agreement `demo0000demo0001`, SHA-256 `a648c11a00e3420e27e2a8e27ce0b6830e4b920fcd318335f5c30d6bd1505911`.
- **Evidence Bundle v1:** [release `bundle-v1`](https://github.com/x39matrix/x39-Evidencia/releases/tag/bundle-v1). The ZIP `x39-bundle-v1.zip` has SHA-256 `2c93b6c74071139f4201cfbd6012cc4391ebe8430cf7b2f7eced34cc7121a0ce`.
- **Evidence Bundle v1.1:** [release `bundle-v1.1`](https://github.com/x39matrix/x39-Evidencia/releases/tag/bundle-v1.1): both clocks required (Bitcoin anchor and RFC 3161 qualified timestamp) and its own strict verifier, `verify_bundle_v1_1.py`. The commands above refer to v1.
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
