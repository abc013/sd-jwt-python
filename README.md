# Demonstration of Attacks on Weak Untraceability of the SD-JWT Reference Implementation

This repository implements the four attacks described in the paper "Invisible Traces: Subversion Attacks on Batch-Issued Credentials", targeting weak untraceability of the [reference implementation](https://github.com/openwallet-foundation-labs/sd-jwt-python/) of the [IETF SD-JWT specification](https://datatracker.ietf.org/doc/draft-ietf-oauth-selective-disclosure-jwt/) written in Python.

## Quickstart

We provide a simple script to demonstrate the four tracing attacks, one at a time. Each walkthrough has three
separate commands: the **issuer** embeds a tracing marker, the **holder** chooses
which claims to present, and a **colluding verifier** recovers the marker from the
presentation. No server or browser is needed.

### 1. Install this PoC

Use Python 3.8+ and Bash. From this repository's `demo/` directory (the directory
containing `pyproject.toml` and this README), run:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e .
```

The installation needs internet access to download dependencies; the demo itself
runs locally. In a new terminal, return to this directory and activate `.venv`.

The helper [`scripts/quickstart.py`](scripts/quickstart.py) selects exactly one
attack using Python booleans. The helper supplies its own demo tracing key and hidden data, so no
exports are needed.

### 2. Salt: recover a marker from a disclosed attribute

```bash
python scripts/quickstart.py salt issue
python scripts/quickstart.py salt present
python scripts/quickstart.py salt verify
```

Read the output after each command:

1. **Issuance:** `[SALT] Hiding bytes b'USER0001'` embeds the eight-byte marker
   in the salt of `age_over_18`. The ciphertext changes on each issuance.
2. **Presentation:** `[PRESENT] Holder releases: ['age_over_18']`. Releasing the
   attribute also releases its salt.
3. **Verification:** `[SALT] Got cleartext b'USER0001'` recovers the marker.
   Signature and disclosure checks still pass. The normally disclosed payload
   contains `iss` and `age_over_18`, but no explicit tracing-ID claim.

Now withhold that attribute and verify again:

```bash
python scripts/quickstart.py salt present --disclose none
python scripts/quickstart.py salt verify
```

There is no `[SALT] Got cleartext` line this time: the verifier does not receive
the salt. The presentation still verifies, and its disclosed payload contains
only `iss`.

### 3. Decoy: recover a marker without any disclosed attributes

```bash
python scripts/quickstart.py decoy issue
python scripts/quickstart.py decoy present
python scripts/quickstart.py decoy verify
```

The maximum number of attributes in a credential is arbitrarily set to 10 via the variable MAX_DIGEST_COUNT: hence, if there are less than 10 attributes in the credential, decoy digests are added.
(Every quickstart credential contains one real selectively disclosable attribute plus nine decoys. There are ten digest entries.)

For each decoy, verification prints `[DECOY] Got cleartext b'USER0001USER0001'`.
Note that you will see nine recovered markers and one unrelated result. This is because the verifier will also attempt to extract tracing data from attribute digests, which results in random bits. This is unavoidable since both types of digests are indistinguishable. A malicious party could recognize tracing data by a specific data format.
We get to embed 16 bytes of tracing data, encrypted into a 32-byte decoy digest, matching the 32-byte SHA-256 digests.

### 4. Order: recover a byte from the digest permutation

```bash
python scripts/quickstart.py order issue
python scripts/quickstart.py order present
python scripts/quickstart.py order verify
```

With the fixed number of attributes 10, we get to embed a single byte "A".
Remark that due to the limited space for the subversion attack, the encryption here uses only a single byte of randomness.

Issuance prints `[ORDER] Hiding bytes b'A', ciphertext: ..., amount: 10`, and verification prints `[ORDER] Got cleartext b'A', ciphertext: ..., amount: 10`.

### 5. ECDSA: recover a marker from the signature

```bash
python scripts/quickstart.py ecdsa issue
python scripts/quickstart.py ecdsa present
python scripts/quickstart.py ecdsa verify
```

We try to embed a single byte here, which should on average use 256 tries. We set the maximum tries to 8192 (both set via variables in `src/sd_jwt/subliminal_ecdsa.py`): if this number of tries is exceeded, we simply use the first k such that extraction will fail later, following the paper's choice to guarantee termination instead of extraction.

Issuance prints `[SIGNATURE] Hiding bytes b'A', trials: ...`, and verification prints `[SIGNATURE] Got cleartext b'A'`.

### 6. Compare ordinary verification and repeated issuance

Verify any saved presentation with tracing extraction disabled:

```bash
python scripts/quickstart.py ecdsa verify --honest
```

The signature and disclosure checks still pass, but there is no
`[SIGNATURE] Got cleartext` line. Replace `ecdsa` with `salt`, `decoy`, or `order`
to make the same comparison for the other channels. This checks an honestly
verifying party's behavior on a subverted credential; it does not issue an honest
control credential.

To see the same tracing marker survive across **fresh credentials**, repeat
issuance and presentation, for example:

```bash
for run in 1 2; do
  echo "Fresh credential $run"
  python scripts/quickstart.py ecdsa issue
  python scripts/quickstart.py ecdsa present
  python scripts/quickstart.py ecdsa verify
done
```

The rejection-sampled signatures change, but the recovered marker stays the same.
This illustrates the tracing mechanism relevant to batch-issued, one-time
credentials; the helper issues one credential per invocation rather than
implementing a batch protocol.

### Files and interpretation

Each attack stores `issuance.txt`, `presentation.txt`, `issuer-public.jwk`, and
`issuer-private.jwk` under `quickstart-output/<attack>/`. Each command runs in a
separate Python process. The holder reads only the issuance; the verifier reads
the presentation and public key.
The symmetric tracing key (abused as a PRF key in the ECDSA demo) is fixed in the helper.
Reissuing retains the signing key, replaces the issuance, and removes the old
presentation; run `present` again before `verify`. Use `--out another-directory`
on all three commands to keep a separate run.

| Attack | Carrier | Default attribute disclosure | Recovered marker |
| --- | --- | --- | --- |
| Salt | Salt in a released disclosure | `age_over_18` | `b'USER0001'` |
| Decoy | Decoy entries in the signed `_sd` array | None | `b'USER0001USER0001'` per decoy |
| Order | Permutation of ten signed digests | None | `b'A'` |
| ECDSA | PRF evaluated on R | None | `b'A'` |

The `[...] Hiding bytes` and `Got cleartext` lines are intentional diagnostic
messages from the attack implementation. Successful verification alongside
recovered tracing data is the result to look for: selective disclosure does not
remove these tracing channels. These walkthroughs use flat claims and omit holder
key binding to isolate the mechanisms. They are local research demos with demo
key material, not a production deployment or a proof of undetectability.

The corresponding paper sections are §5.1 (salt), §5.2 (signature), §6.2 (order),
and §6.3 (decoy digests).

## Details on the Implementation of Each Attack

- *Salt manipulation attack.* We use the 16-Byte long salt to hide an 8-Byte long pseudo-randomly encrypted message per disclosure. This attack is undetectable. It can be activated / deactivated with the environment variable `ENABLE_SALT_ATTACK=[True|False]`.
- *Decoy digest attack.* We use the 32-byte decoy entries to hide an 16-Byte long pseudo-randomly encrypted message per digest. 
Its environment switch is `ENABLE_DECOY_DIGEST_ATTACK=[True|False]`.
- *Order of digests attack.* As the standard allows for random shuffling of digests, we can encode information within the order of digests. Nine digests are the minimum for the current encrypted one-byte payload.
Its environment switch is `ENABLE_ORDER_ATTACK=[True|False]`.
- *ECDSA subliminal channel attack.*  Its environment switch is `ENABLE_ECDSA_ATTACK=[True|False]`. 
ECDSA tracing extraction requires the shared PRF key and the issuer’s public key. The issuer’s private signing key is not shared with the verifier.

The salt, decoy, and order channels use the HKDF-based encryption in `encryption_hkdf.py`; the ECDSA channel instead rejection-samples a PRF.
A 16-Byte symmetric key must be set in both issuer and verifier instances by providing it in hex format in the environment variable `HIDDEN_ENCRYPTION_KEY=deadbeefdeadbeefdeadbeefdeadbeef`.
The data that you want to hide can be set in `HIDDEN_DATA` in hex format.
