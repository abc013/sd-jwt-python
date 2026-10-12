#!/usr/bin/env python3
"""Run one tracing channel in separate issuance/presentation/verification steps."""
import argparse
import json
from pathlib import Path

from jwcrypto.jwk import JWK

from sd_jwt.common import SDObj
from sd_jwt.holder import SDJWTHolder
from sd_jwt.issuer import SDJWTIssuer
from sd_jwt.verifier import SDJWTVerifier

ATTACKS = {
    "salt": "enable_salt_attack",
    "decoy": "enable_decoy_digest_attack",
    "order": "enable_order_attack",
    "ecdsa": "enable_ecdsa_attack",
}
ISSUER = "https://issuer.example"
# Public, fixed demo material
TRACING_KEY = bytes.fromhex("00112233445566778899aabbccddeeff")
MARKERS = {"salt": b"USER0001", "decoy": b"USER0001USER0001",
           "order": b"A", "ecdsa": b"A"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("attack", choices=ATTACKS)
    parser.add_argument("step", choices=("issue", "present", "verify"))
    parser.add_argument("--out", type=Path, default=Path("quickstart-output"))
    parser.add_argument("--disclose", choices=("age", "none"), default=None,
                        help="presentation only; default: age for salt, none otherwise")
    parser.add_argument("--honest", action="store_true",
                        help="verification only: verify without extracting tracing data")
    args = parser.parse_args()
    if args.disclose is not None and args.step != "present":
        parser.error("--disclose is only valid for present")
    if args.honest and args.step != "verify":
        parser.error("--honest is only valid for verify")

    # Enable the selected attack, overriding environment settings
    for cls in (SDJWTIssuer, SDJWTVerifier):
        for name, attr in ATTACKS.items():
            setattr(cls, attr, name == args.attack and not args.honest)
        cls.hidden_encryption_key = TRACING_KEY
    SDJWTIssuer.unsafe_randomness = False
    directory = args.out / args.attack

    def read(name):
        path = directory / name
        if not path.is_file():
            parser.error(f"Missing {path}; run issue, then present, then verify.")
        return path.read_text()

    if args.step == "issue":
        directory.mkdir(parents=True, exist_ok=True)
        # Retain the issuer key across repeated issuances in this demo directory.
        key_path = directory / "issuer-private.jwk"
        key = (JWK.from_json(key_path.read_text()) if key_path.exists()
               else JWK.generate(kty="EC", crv="P-256"))
        key_path.write_text(key.export_private())
        key_path.chmod(0o600)
        (directory / "issuer-public.jwk").write_text(key.export_public())
        claims = {"iss": ISSUER, SDObj("age_over_18"): True}
        marker = MARKERS[args.attack]
        # Every decoy carries the same ID; avoid random padding in the output.
        SDJWTIssuer.hidden_data = marker * (SDJWTIssuer.MAX_DIGEST_COUNT
                                               if args.attack == "decoy" else 1)
        print(f"[ISSUE] Channel: {args.attack}; tracing marker: {marker!r}")
        issued = SDJWTIssuer(claims, key, add_decoy_claims=True)
        (directory / "issuance.txt").write_text(issued.sd_jwt_issuance)
        # An old presentation must not be mistaken for the new credential.
        presentation = directory / "presentation.txt"
        if presentation.exists():
            presentation.unlink()
        print(f"[ISSUE] Saved {directory / 'issuance.txt'}")

    elif args.step == "present":
        selection = args.disclose or ("age" if args.attack == "salt" else "none")
        disclosed = {"age_over_18": True} if selection == "age" else {}
        holder = SDJWTHolder(read("issuance.txt"))
        holder.create_presentation(disclosed)
        (directory / "presentation.txt").write_text(holder.sd_jwt_presentation)
        print(f"[PRESENT] Holder releases: {list(disclosed)}")
        print("[PRESENT] Signed payload and signature remain in the presentation.")
        print(f"[PRESENT] Saved {directory / 'presentation.txt'}")

    else:
        presentation = read("presentation.txt")
        public_key = JWK.from_json(read("issuer-public.jwk"))

        def issuer_key(issuer, header):
            if issuer != ISSUER or header.get("alg") != "ES256":
                raise ValueError("Unexpected issuer or signing algorithm")
            return public_key

        print("[VERIFY] Checking presentation" +
              (" without tracing extraction." if args.honest else " and extracting tracing data."))
        verifier = SDJWTVerifier(presentation, issuer_key)
        payload = verifier.get_verified_payload()
        print("[VERIFY] Signature and disclosure checks passed.")
        print("[VERIFY] Normally disclosed payload: " + json.dumps(payload, sort_keys=True))


if __name__ == "__main__":
    main()
