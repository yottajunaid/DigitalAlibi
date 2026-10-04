# MEMORY.md: Digital Alibi Context and Handoff

## Project identity

- **Name:** Digital Alibi
- **Version:** 1.0.0
- **Purpose:** Cross-platform, USB-oriented, authorised live-triage utility that captures nearby environmental radio identifiers, falls back to an in-memory audio fingerprint where radios are unavailable, hashes canonical evidence, and seals evidence through RFC 3161 or an offline locally signed Merkle batch.
- **Author metadata:** Developed by **Junaid Nizam Quadri**, M.Tech in Information Security and Cyber Forensics.
- **Created/updated:** October 4, 2026.
- **Repository state at handoff:** Initial implementation created from an empty Git repository. A project-local `.venv` was created and used for all Python dependency installation and test execution.

## Non-negotiable forensic constraints

1. **Zero-footprint acquisition scope:** Every persistent artifact written by `alibi_core.py` must resolve under `Path.cwd()` / `os.getcwd()`. Do not introduce defaults that write to `/tmp`, `%TEMP%`, user profiles, cache folders, application data, or a host database.
2. **No PyInstaller onefile builds:** Onefile extraction uses host temporary storage. Build only self-contained `--onedir` folders for field acquisition.
3. **No silent acquisition failures:** If Wi-Fi, BLE, audio, network, or a timestamp authority is unavailable, save explicit acquisition/error metadata in the evidence payload or queue state. Do not create fake empty success claims.
4. **No persistence of raw audio:** Audio is an in-memory fingerprint fallback only. Do not add WAV/PCM sample storage without a deliberate policy and schema revision.
5. **No custom radio driver, monitor-mode, or packet capture logic:** Wi-Fi uses only `netsh wlan`, `nmcli`, or `airport -s`. BLE uses `bleak`.
6. **Cryptographic precision matters:** Do not change canonical JSON encoding, digest semantics, Merkle ordering, or signature envelope without a schema/version migration and matching verifier updates.
7. **Avoid forensic overclaims:** Radio visibility is not identity or geolocation. A TSA token covers a digest, not the truth of collection context. Local signatures are not independent timestamps.
8. **Testing rule from user:** Build, debug, and test only in an isolated project-local virtual environment or sandbox. Existing validation uses `.venv` and `.sandbox-test` under the repository.

## Current directory structure

```text
.
├── .gitignore
├── .venv/                              # ignored, project-local test/build venv
├── .sandbox-test/                      # ignored, test-only evidence sandbox
├── alibi_core.py                       # core Python CLI
├── build_forensic_usb.py               # native PyInstaller --onedir build helper
├── Autopsy_DigitalAlibi_Ingest.py      # Jython 2.7 Autopsy data source ingest module
├── README.md                           # investigator and build manual
├── MEMORY.md                           # this handoff document
├── requirements.txt                    # runtime dependencies
├── requirements-build.txt              # runtime + PyInstaller
└── tests/
    └── test_alibi_core.py              # isolated unittest suite
```

Generated acquisition artifacts are ignored by Git:

```text
digital_alibi.sqlite
digital_alibi_ed25519_private.pem
digital_alibi_ed25519_public.pem
tsr/
```

Build output is also ignored:

```text
build/
dist/
*.spec
```

## Core engine: `alibi_core.py`

### CLI

```text
capture [--tsa-url HTTPS_URL] [--no-tsa] [--ble-seconds N]
        [--audio-seconds N] [--capture-id ID] [--note TEXT]
flush   [--tsa-url HTTPS_URL] [--limit N]
watch   [--tsa-url HTTPS_URL] [--interval SECONDS]
verify  [--capture-id ID]
status
```

### Core behavior

- `EvidenceStore` owns all evidence-path creation and uses `.resolve()` plus `relative_to(root)` to reject path escape.
- The SQLite database is `digital_alibi.sqlite` in CWD. PRAGMAs are `journal_mode=DELETE`, `synchronous=FULL`, and `foreign_keys=ON`.
- `scan_wifi()` chooses a platform command:
  - Windows: `netsh wlan show networks mode=bssid`
  - Linux: `nmcli --terse --fields BSSID device wifi list --rescan no`
  - macOS: `/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport -s`
- BSSID parsing normalises colon/hyphen MAC notation to uppercase colon-delimited form.
- `scan_ble()` runs two `bleak` discoveries and keeps only MAC-form IDs in the intersection. This deliberately excludes CoreBluetooth UUIDs, because they are not physical MAC addresses.
- `capture_audio_digest()` uses a 16 kHz, mono, signed 16-bit, in-memory `sounddevice` recording only if both Wi-Fi and BLE result sets are empty. It hashes the memory and stores metadata only.
- Native subprocesses use fixed argv arrays, `shell=False`, controlled `LANG=C` and `LC_ALL=C`, CWD equal to evidence root, timeouts, and capped output.

### Evidence digest contract

Do **not** casually modify this contract.

1. Payload is encoded with `canonical_json()`: UTF-8, `ensure_ascii=False`, `sort_keys=True`, compact separators, `allow_nan=False`.
2. `compressed_evidence()` applies `zlib.compress(raw, level=9)`.
3. SHA-256 of that exact compressed byte sequence becomes `compressed_sha256` and the RFC 3161 imprint.
4. Exact compressed bytes are retained as Base64 in `captures.compressed_payload_b64`.
5. Verification Base64-decodes the exact blob, hashes it, checks `compressed_size`, and verifies `zlib.decompress(blob) == canonical_json(payload)`.

Storing exact compressed bytes was a deliberate correction made during development. It prevents cross-platform verifier mismatch when different zlib implementations produce different valid compressed streams.

### Online TSA behavior

- Default endpoint: `https://freetsa.org/tsr`.
- `build_timestamp_request()` manually DER-encodes RFC 3161 TimeStampReq with SHA-256 OID, 128-bit nonce, and `certReq=TRUE`.
- `obtain_timestamp()` enforces HTTPS, validates response content type, caps response size, and performs a **minimal structural status check** before saving the `.tsr`.
- Collection code intentionally does not claim trust-chain verification. Autopsy or an independent verifier must validate the token signature, chain, anchor, and revocation policy.
- `capture` automatically first attempts TSA submission for previously pending/local records, then captures new evidence and tries it too.
- `watch` gives the requested automatic reconnection retry without creating a host service. It only retries while the USB-launched process is running.
- `flush` is a one-shot retry.

### Offline local seal

- `LocalSigner` creates a USB-local Ed25519 PKCS#8 private PEM and a public PEM on first use.
- Pending leaf hashes are sorted, then Merkle-paired with duplicate-last behavior for an odd level.
- The signature envelope has fixed fields:

```json
{
  "purpose": "digital-alibi.merkle-root/v1",
  "batch_id": "...",
  "created_at_utc": "...",
  "leaf_count": 0,
  "merkle_root": "..."
}
```

- `merkle_batches` retains roots, leaf hashes, signature Base64, public key DER Base64, and public key SHA-256 fingerprint.
- `LOCAL_SEALED` evidence remains eligible for later TSA submission. Existing local batches are never deleted after TSA seal.

### Database tables

- `metadata`: schema version and creation time.
- `captures`: evidence payload, exact compressed bytes, digest, TSA status/path/errors, local key/batch references.
- `merkle_batches`: locally signed leaf batches.
- `audit_events`: immutable-style event records from application behavior. It is not protected from SQLite editing by an append-only filesystem, so acquisition-media controls still matter.

### Known core caveats

- A system can expose no usable Wi-Fi/BLE identifiers because of hardware, policy, permissions, radio state, OS cache, or platform limitations. The tool reports method error metadata, not a complete radio environment guarantee.
- macOS has deliberately reduced BLE behavior by excluding non-MAC CoreBluetooth IDs.
- A timestamp HTTP response is only minimally syntactically checked at collection time. Trust validation belongs to a verifier with a pinned trust policy.
- `watch` is not a background service. This is intentional for zero-footprint behavior.
- The project has no formal external security audit, reproducible-build lockfile, signed release manifest, or full forensic certification as of this handoff.

## Build helper: `build_forensic_usb.py`

- Refuses to run unless `sys.prefix != sys.base_prefix`, ensuring the Python build command is using a virtual environment.
- Uses current native OS/architecture to name output, such as `DigitalAlibi-linux-x86_64`.
- Deletes only its matching `dist/<release-name>` folder before building.
- Invokes PyInstaller in `--onedir` mode, using the current venv’s Python.
- Collects `cryptography`, `bleak`, `sounddevice`, and `numpy`, plus expected BLE hidden-import backends.
- Writes generated bundle data under project-local `build/` and `dist/` only.
- Builds are native only. Windows, Linux, macOS Intel, and macOS Apple Silicon must be built/tested in matching native environments or separately validated target-compatible environments.

## Autopsy integration: `Autopsy_DigitalAlibi_Ingest.py`

### Intended environment

- Jython 2.7 Data Source Ingest Module.
- Requires an Autopsy installation plus an approved matching SQLite JDBC JAR under the module `lib/` directory.
- Bouncy Castle `bcprov` + `bcpkix` JARs are needed for CMS/RFC 3161 token parsing and signature verification.
- An optional, strongly recommended `DigitalAlibi_TSA_Root.pem` in the module directory is used for pinned-root validation.

### Behavior

- Locates `digital_alibi.sqlite` via Autopsy FileManager.
- Copies database/TSR contents into the active **Autopsy case temp directory**, not the evidence USB. It deletes temporary extraction after use. This is post-acquisition analysis and deliberately outside core zero-footprint scope.
- Reads captures through JDBC.
- Recalculates core evidence verification using stored exact compressed bytes, SHA-256, and canonical decompression.
- Recomputes offline Merkle root, then attempts Ed25519 JCA verification. Older JREs may lack Ed25519, producing `LOCAL_UNVERIFIED`, not a false pass.
- For `TSA_SEALED`, locates the named TSR, verifies RFC 3161 message imprint and CMS signature via Bouncy Castle.
- If a pinned root PEM is available, attempts PKIX chain validation. It intentionally disables revocation checking and reports that limitation.
- Posts `TSK_INTERESTING_FILE_HIT` Blackboard artifacts on the SQLite file with `TSK_SET_NAME` and `TSK_COMMENT`.

### Autopsy caveats that require real environment validation

- This module was syntax-compiled with CPython only, not executed inside a real Autopsy/Jython runtime in this development session.
- Verify the exact Autopsy API/JRE/Jython combination that the lab uses. In particular validate `ContentUtils`, `newArtifact`, Blackboard posting, module JAR loading, Bouncy Castle classes, `FileManager.findFiles`, Java Ed25519 availability, and parsed token chain behavior.
- The database query expects the v1 schema with `compressed_payload_b64`. Use schema migration or a backward-compatible query if future formats change.
- Add known-good and tampered USB fixture cases to a lab validation pack before operational use.

## Test environment and observed validation

All package installation and execution were done using the project-local `.venv`, created under the repo:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-build.txt
```

Installed into `.venv` only:

- `cryptography`
- `bleak`
- `numpy`
- `sounddevice`
- `PyInstaller`

Successful checks run on October 4, 2026:

```bash
.venv/bin/python -m py_compile alibi_core.py build_forensic_usb.py Autopsy_DigitalAlibi_Ingest.py tests/test_alibi_core.py
.venv/bin/python -m unittest discover -s tests -v
```

At the last successful test run, **8 tests passed**:

1. BSSID colon/hyphen normalisation and de-duplication.
2. Canonical compressed hash repeatability.
3. Order-independent Merkle root plus odd-leaf handling.
4. RFC 3161 DER request and granted response structural parser.
5. Path-escape refusal.
6. No-radio offline capture creates only expected evidence files inside a local sandbox and then verifies.
7. Local Ed25519 Merkle batch verifies against recorded public key.
8. Payload tampering is detected by `verify`.

Hardware scanning, actual microphone capture, network TSA submission, PyInstaller executable launch, and Autopsy runtime integration were **not** run against live systems in this session. These are mandatory pre-deployment validation tasks.

## Recommended next work

1. Run build helper on each target OS in isolated build VMs, then launch each native bundle from a dedicated USB-like case directory.
2. Add a controlled local RFC 3161 test server or checked-in fixed test fixture, then test successful online `.tsr` write and deferred queue behavior without relying on a public TSA during CI.
3. Produce a lab-signed release manifest, SBOM, dependency lockfiles/hashes, and reproducible build record.
4. Build a validation fixture USB with:
   - one locally sealed capture,
   - one valid TSA-sealed capture,
   - a missing TSR case,
   - altered payload / altered compressed blob / altered Merkle signature / altered TSR cases.
5. Test the Autopsy module with approved JARs and the fixture media. Fix any API/Jython compatibility details discovered on the lab’s actual Autopsy version.
6. Decide whether to package trusted TSA roots, support several pinned TSA profiles, and implement formal revocation evidence collection. Do not silently accept an unpinned chain.
7. Add a project license, threat model, CI using only isolated environments, static analysis, dependency pinning, and signed tagged releases.

## Editing guidance for future agents

- Use the project-local `.venv`, never global `pip` or a system Python test environment.
- Keep test artifacts under `.sandbox-test` and Git-ignored.
- Update `README.md` and this file whenever database schema, digest rules, output paths, TSA trust policy, or Autopsy requirements change.
- If adding a new evidence source, first assess legal authority, privacy, side effects, persistence, deterministic canonicalisation, and Autopsy verification support.
- If a new dependency writes caches by default, do not add it to acquisition runtime unless its write paths can be confined to the USB root or disabled.
- For any claim of forensic readiness, distinguish source-code unit tests from target-OS hardware tests, executable-packaging tests, independent timestamp verification, and actual Autopsy ingest validation.
