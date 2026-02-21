import math
import os
from .common import (
    SDJWTCommon,
    DEFAULT_SIGNING_ALG,
    DIGEST_ALG_KEY,
    SD_DIGESTS_KEY,
    SD_LIST_PREFIX,
    KB_DIGEST_KEY,
)

from json import dumps, loads
from typing import Dict, List, Union, Callable

from jwcrypto.jwk import JWK
from jwcrypto.jws import JWS

from .lehmer_code import rank_permutation
from .encryption_hkdf import aes_decrypt
from .subliminal_ecdsa import verify

class SDJWTVerifier(SDJWTCommon):
    _input_disclosures: List
    _hash_to_decoded_disclosure: Dict
    _hash_to_disclosure: Dict

    # Attack parameter section
    hidden_signature_key: bytes = os.environ.get("HIDDEN_SIGNATURE_KEY", None)
    hidden_encryption_key: bytes = bytearray.fromhex(os.environ.get("HIDDEN_ENCRYPTION_KEY", bytes("0123456789abcdef", "utf-8").hex()))
    enable_salt_attack: bool = os.environ.get("ENABLE_SALT_ATTACK", True)
    enable_decoy_digest_attack: bool = os.environ.get("ENABLE_DECOY_DIGEST_ATTACK", True)
    enable_order_attack: bool = os.environ.get("ENABLE_ORDER_ATTACK", True)
    enable_ecdsa_attack: bool = os.environ.get("ENABLE_ECDSA_ATTACK", True)

    def __init__(
        self,
        sd_jwt_presentation: str,
        cb_get_issuer_key: Callable[[str, Dict], str],
        expected_aud: Union[str, None] = None,
        expected_nonce: Union[str, None] = None,
        serialization_format: str = "compact",
    ):
        super().__init__(serialization_format=serialization_format)

        self._parse_sd_jwt(sd_jwt_presentation)
        self._create_hash_mappings(self._input_disclosures)
        self._verify_sd_jwt(cb_get_issuer_key)

        if self.enable_salt_attack:
            self._get_bytes_from_disclosures()

        # expected aud and nonce either need to be both set or both None
        if expected_aud or expected_nonce:
            if not (expected_aud and expected_nonce):
                raise ValueError(
                    "Either both expected_aud and expected_nonce must be provided or both must be None"
                )

            # Verify the SD-JWT-Release
            self._verify_key_binding_jwt(
                expected_aud,
                expected_nonce,
            )

    # SALT ATTACK: Retrieve salts from sent disclosures. Each is 16 bytes long.
    def _get_bytes_from_disclosures(self):
        for k, v in self._hash_to_decoded_disclosure.items():
            salt = self._base64url_decode(v[0])
            msg = aes_decrypt(self.hidden_encryption_key, salt)
            print(f"[SALT] Got cleartext {msg}, ciphertext: {salt.hex()}")

    def get_verified_payload(self):
        return self._extract_sd_claims()

    def _verify_sd_jwt(
        self,
        cb_get_issuer_key,
        sign_alg: str = None,
    ):
        parsed_input_sd_jwt = JWS()
        parsed_input_sd_jwt.deserialize(self._unverified_input_sd_jwt)

        unverified_issuer = self._unverified_input_sd_jwt_payload.get("iss", None)
        unverified_header_parameters = parsed_input_sd_jwt.jose_header
        issuer_public_key = cb_get_issuer_key(unverified_issuer, unverified_header_parameters)
        parsed_input_sd_jwt.verify(issuer_public_key, alg=sign_alg)

        # ECDSA ATTACK: Retrieve bytes from signature.
        if self.enable_ecdsa_attack:
            verify(parsed_input_sd_jwt, issuer_public_key, alg=sign_alg, hidden_encryption_key=self.hidden_encryption_key, hidden_signature_key=self.hidden_signature_key)

        self._sd_jwt_payload = loads(parsed_input_sd_jwt.payload.decode("utf-8"))
        # TODO: Check exp/nbf/iat

        self._holder_public_key_payload = self._sd_jwt_payload.get("cnf", None)

    def _verify_key_binding_jwt(
        self,
        expected_aud: Union[str, None] = None,
        expected_nonce: Union[str, None] = None,
        sign_alg: Union[str, None] = None,
    ):

        # Deserialized the key binding JWT
        _alg = sign_alg or DEFAULT_SIGNING_ALG
        parsed_input_key_binding_jwt = JWS()
        parsed_input_key_binding_jwt.deserialize(self._unverified_input_key_binding_jwt)

        # Verify the key binding JWT using the holder public key
        if not self._holder_public_key_payload:
            raise ValueError("No holder public key in SD-JWT")

        holder_public_key_payload_jwk = self._holder_public_key_payload.get("jwk", None)
        if not holder_public_key_payload_jwk:
            raise ValueError(
                "The holder_public_key_payload is malformed. "
                "It doesn't contain the claim jwk: "
                f"{self._holder_public_key_payload}"
            )

        pubkey = JWK.from_json(dumps(holder_public_key_payload_jwk))

        parsed_input_key_binding_jwt.verify(pubkey, alg=_alg)

        # Check header typ
        key_binding_jwt_header = parsed_input_key_binding_jwt.jose_header

        if key_binding_jwt_header["typ"] != self.KB_JWT_TYP_HEADER:
            raise ValueError("Invalid header typ")

        # Check payload
        key_binding_jwt_payload = loads(parsed_input_key_binding_jwt.payload)

        if key_binding_jwt_payload["aud"] != expected_aud:
            raise ValueError("Invalid audience in KB-JWT")
        if key_binding_jwt_payload["nonce"] != expected_nonce:
            raise ValueError("Invalid nonce in KB-JWT")

        # Reassemble the SD-JWT in compact format and check digest
        if self._serialization_format == "compact":
            string_to_hash = self._combine(
                        self._unverified_input_sd_jwt,
                        *self._input_disclosures,
                        ""
            )
            expected_sd_jwt_presentation_hash = self._b64hash(string_to_hash.encode("ascii"))

            if key_binding_jwt_payload[KB_DIGEST_KEY] != expected_sd_jwt_presentation_hash:
                raise ValueError("Invalid digest in KB-JWT")

    def _extract_sd_claims(self):
        if DIGEST_ALG_KEY in self._sd_jwt_payload:
            if self._sd_jwt_payload[DIGEST_ALG_KEY] != self.HASH_ALG["name"]:
                # TODO: Support other hash algorithms
                raise ValueError("Invalid hash algorithm")

        self._duplicate_hash_check = []
        return self._unpack_disclosed_claims(self._sd_jwt_payload)

    def _unpack_disclosed_claims(self, sd_jwt_claims):
        # In a list, unpack each element individually
        if type(sd_jwt_claims) is list:
            output = []
            for element in sd_jwt_claims:
                if (
                    type(element) is dict
                    and len(element) == 1
                    and SD_LIST_PREFIX in element
                    and type(element[SD_LIST_PREFIX]) is str
                ):
                    digest_to_check = element[SD_LIST_PREFIX]
                    if digest_to_check in self._hash_to_decoded_disclosure:
                        _, value = self._hash_to_decoded_disclosure[digest_to_check]
                        output.append(self._unpack_disclosed_claims(value))
                else:
                    output.append(self._unpack_disclosed_claims(element))
            return output

        elif type(sd_jwt_claims) is dict:
            # First, try to figure out if there are any claims to be
            # disclosed in this dict. If so, replace them by their
            # disclosed values.

            pre_output = {
                k: self._unpack_disclosed_claims(v)
                for k, v in sd_jwt_claims.items()
                if k != SD_DIGESTS_KEY and k != DIGEST_ALG_KEY
            }

            # ORDER ATTACK: Use the permutation of digests to hide information. Note that we work on byte-level.
            claims = sd_jwt_claims.get(SD_DIGESTS_KEY, [])
            byte_count = int(math.log2(math.factorial(len(claims)))) // 8
            if self.enable_order_attack and byte_count > 0:
                hidden_bytes = rank_permutation(claims).to_bytes(byte_count, byteorder="big")
                print(f"[ORDER] Got cleartext {hidden_bytes}, amount: {len(claims)}")

            for digest in sd_jwt_claims.get(SD_DIGESTS_KEY, []):
                if digest in self._duplicate_hash_check:
                    raise ValueError(f"Duplicate hash found in SD-JWT: {digest}")
                self._duplicate_hash_check.append(digest)

                if digest in self._hash_to_decoded_disclosure:
                    _, key, value = self._hash_to_decoded_disclosure[digest]
                    if key in pre_output:
                        raise ValueError(
                            f"Duplicate key found when unpacking disclosed claim: '{key}' in {pre_output}. This is not allowed."
                        )
                    unpacked_value = self._unpack_disclosed_claims(value)
                    pre_output[key] = unpacked_value
                else:
                    # DECOY DIGEST ATTACK: decrypt cipher blocks and extract hidden payload
                    # (this iterates all undisclosed attributes + decoy digests)
                    try:
                        raw = self._base64url_decode(digest)
                    except Exception:
                        raw = None

                    if raw is not None and len(raw) == 16 and self.enable_decoy_digest_attack:
                        msg = aes_decrypt(self.hidden_encryption_key, raw)
                        print(f"[DECOY] Got cleartext {msg}, ciphertext: {raw.hex()}")

            # Now, go through the dict and unpack any nested dicts.
            return pre_output

        else:
            return sd_jwt_claims