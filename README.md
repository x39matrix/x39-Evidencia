# X-39 Evidencia

X-39 Evidencia is a proof-of-existence layer for documents.

> [!WARNING]
> **Status: test release.** X-39 Evidencia 0.3.5 is a test version, not the final one. It has not been audited by any independent third party; that audit is pending. The verifier has passed internal, reproducible tests. Do not rely on this build for critical use.
> This applies to the app, not to the evidence it produces: a Bitcoin anchor or an ANF qualified timestamp, once issued, is real and anyone can verify it.
> Every Android app release publishes its APK SHA-256, signing-certificate fingerprint, qualified timestamp and `.ots` proof, so you can check the evidence yourself instead of trusting this notice.

1. In the website flow, the SHA-256 is computed in the browser and the file bytes stay in that browser; only the SHA-256 digest is sent to the service; the file name is not. This statement describes the website only. In the Android evidence app, sealing/anchoring sends a 32-byte commitment derived from the fingerprint to timestamp calendars. If the user chooses to send a capsule to a paired phone, the original is sent end-to-end encrypted.
2. That hash is anchored in Bitcoin through OpenTimestamps; proofs verify against any Bitcoin node, and the reference deployment verifies them against our own full node.
3. Where a legally recognised time is needed, the same hash receives an RFC 3161 qualified timestamp from ANF AC, a qualified trust service provider listed in the EU and Spanish trusted lists; the chain is verified with openssl against the ANF root, and the fingerprint of the TSA service certificate registered in the Spanish trusted list is published below, so that the certificate travelling in the chain can be cross-checked by hand.
4. Proofs may carry an ML-DSA-87 (FIPS 204) co-signature produced on an air-gapped machine and verified against a published key fingerprint; it is optional, and its absence is reported, not hidden.
5. Everything is verifiable with free tools and without trusting X-39. The code is AGPL-3.0. This is not a notary and not a qualified electronic signature.

## Verify it yourself

There are two independent checks. **A** takes a real seal all the way to the reference verifier's `VALID [0]`. **B** reproduces the published Evidence Bundle v1, including its qualified timestamp.

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
- Without `--content` the document is not checked, so there is no `VALID [0]`. The verifier says so (`documento: NO COMPROBADO (sin --content)` plus an `ANOMALIA` line) and the verdict is decided by everything else: `CONSISTENTE [6]` when the Bitcoin anchor is confirmed and the package carries no COLD co-signature, `VALID CON AVISOS [5]` when the COLD co-signature is valid. This is the normal situation for a third party, who will not have the private document; it says nothing bad about the evidence.
- Without a reachable Bitcoin node the anchor cannot be confirmed and there is no `VALID [0]`. The verifier reports this as `INVALID[3]: ANCLA NO COMPROBADA: no hay nodo Bitcoin accesible (el RPC no responde o falta su configuracion); la rama Bitcoin '957242' queda sin confirmar. Sin nodo no hay VALID; esto no indica que la evidencia sea falsa. Use un nodo Bitcoin propio (bitcoin.conf local) o --bitcoin-node URL`. If the node rejects the RPC credentials, the reason reads `el nodo Bitcoin rechazo las credenciales RPC (401 Unauthorized)` instead. Either way it means the anchor was not checked, not that the evidence is bad. To compare without a node, extract `proof.json` and `proof.json.ots` from the ZIP and upload them to <https://opentimestamps.org>; that check relies on that service.

Exit codes: `0` VALID; `5` VALID with warnings; `6` CONSISTENT (required checks pass, but the COLD co-signature is absent; NOT VALID); `1` integrity; `2` signature; `3` Bitcoin anchor not confirmed (also `--skip-ots`); `4` usage or environment.

### B. The published Evidence Bundle v1

Download `x39-bundle-v1.zip` from the [`bundle-v1` release](https://github.com/x39matrix/x39-Evidencia/releases/tag/bundle-v1), check its SHA-256 (see [Links](#links)), unzip it and run these commands from the bundle folder.

**1. Integrity of every file in the bundle.** `MANIFEST` lists the SHA-256 of every other file.

```sh
sha256sum -c MANIFEST
```

**2. The agreement proof.** Use the reference verifier from this repository, not the copy inside the bundle. The bundled copy is an earlier, more lenient version, kept there only so the release stays exactly as it was published. Point the reference verifier at the bundle's ZIP:

```sh
python3 /path/to/x39-Evidencia/verify_bundle.py 31e1cf09a5b2a74cd978.zip --bitcoin-node http://<rpcuser>:<rpcpassword>@<host>:8332
```

This agreement's document is encrypted and not published, so `--content` cannot be supplied and `VALID [0]` is out of reach here; the expected verdict is `VALID CON AVISOS [5]`. Use check A for a `VALID [0]`.

The bundled copy can still be run, but it answers `VALID (OTS omitido)` to `--skip-ots`: an earlier verdict vocabulary, in which skipping the Bitcoin step did not stop the word VALID. The reference verifier refuses to do that, and the refusal is the correct behaviour.

**3. The RFC 3161 qualified timestamp.** The `.cadena.pem` chain ends at the TSA certificate, not at the root. So `-CAfile` must be the ANF root and the chain goes in `-untrusted`. **Validate at the date of the seal, not at today's**: timestamping units expire — the unit that signed this seal is valid until 18 January 2030 — and a seal must stay verifiable long after the unit that issued it is gone.

```sh
D=2O-ACTA-DEL-PLENO-MUNICIPAL-EXTRAORDINARIO-PRESUPUESTO-2026-01-29.pdf
openssl ts -reply -in "$D.tsr" -text
SEAL=$(date -u -d "$(openssl ts -reply -in "$D.tsr" -text | sed -n 's/^Time stamp: *//p' | sed 's/\.[0-9]*//')" +%s)
openssl ts -verify -data "$D" -in "$D.tsr" -CAfile anf_root.pem -untrusted "$D.cadena.pem" -attime "$SEAL"
openssl x509 -in anf_root.pem -noout -fingerprint -sha256
```

Expected: `Verification: OK`. Without `-attime`, OpenSSL validates the chain against the clock of whoever is checking: the same command returns `OK` today and `Verification: FAILED` from 18 January 2030 onwards, on this same unchanged, valid seal. `-attime` takes that expiry date out of the equation; a qualified timestamp does not age.

The root is ANF Global Root CA, SHA-256 `E0:AF:BD:2C:0E:E9:5A:68:CD:9A:3C:59:0B:2D:3F:E0:7C:0A:6D:0B:E7:96:AE:52:91:E4:24:D4:77:92:17:8E`. The Spanish trusted list registers the TSA service certificate (`AF:BC:8E:2D:54:6C:A7:49:9D:8A:81:04:A7:65:B0:0D:2A:30:F3:B0:27:53:94:D6:7A:8D:60:C0:3D:01:63:B5`), which travels in the chain and is issued by that root; compare it if you want to close that link by hand. You reach that list from the European Commission's list of trusted lists: <https://ec.europa.eu/tools/lotl/eu-lotl.xml>.

A `Verification: FAILED` accompanied by `BIO_new_file ... no such file` means a file is missing — wrong folder, or `$D` not set — not a broken seal.

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

Expected: every test passes (534 as of commit `d335bd2c`). Node.js is needed by the
tests that compare the Python verifier with the JavaScript ZIP reference.

## Links

- **Web:** <https://x39matrix.org>. Public verifier: <https://x39matrix.org/verificar>.
- **Android app (X-39 Evidencia 0.3.5, test release, not audited):** [Releases](https://github.com/x39matrix/x39-Evidencia/releases). Each release lists the APK SHA-256, the signing-certificate fingerprint, the qualified timestamp and the `.ots` proof.
- **Demo seal:** [`testdata/bundle_v1_prod.zip`](testdata/bundle_v1_prod.zip), agreement `demo0000demo0001`, SHA-256 `a648c11a00e3420e27e2a8e27ce0b6830e4b920fcd318335f5c30d6bd1505911`. The historical release is [`demo-verificable-1`](https://github.com/x39matrix/x39-Evidencia/releases/tag/demo-verificable-1). Use the reference verifier linked below.
- **Evidence Bundle v1:** [release `bundle-v1`](https://github.com/x39matrix/x39-Evidencia/releases/tag/bundle-v1). The ZIP `x39-bundle-v1.zip` has SHA-256 `2c93b6c74071139f4201cfbd6012cc4391ebe8430cf7b2f7eced34cc7121a0ce`.
- **Evidence Bundle v1.1:** [release `bundle-v1.1`](https://github.com/x39matrix/x39-Evidencia/releases/tag/bundle-v1.1): a sealed release from 2026-10-12 pairing both clocks (Bitcoin anchor and RFC 3161 qualified timestamp). It is kept exactly as published; the verifier bundled with it belongs to the same earlier, more lenient line as v1's. Verify any bundle, v1 or v1.1, with the reference verifier of this repository: `verify_bundle.py`. The commands above refer to v1.
- **Documentation and audits:** [`docs/`](docs/).
- **Reference offline verifier:** [release `verificador-340f9d68`](https://github.com/x39matrix/x39-Evidencia/releases/tag/verificador-340f9d68) · [source](verify_bundle.py). SHA-256 of `verify_bundle.py`: `340f9d686270f38697af88303cfa0032e67f2cf8ab8c7a9e73cb166c9a1e5648`. The release includes `SHA256SUMS` and its OpenTimestamps proof.
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
