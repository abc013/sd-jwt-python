import math
import os
import random
from json import loads, dumps
from typing import Dict, List, Union, override

from jwcrypto.jws import JWS

from .common import (
    DEFAULT_SIGNING_ALG,
    DIGEST_ALG_KEY,
    SD_DIGESTS_KEY,
    SD_LIST_PREFIX,
    SDJWTCommon,
    SDObj,
)
from .disclosure import SDJWTDisclosure

from Crypto.Random import get_random_bytes

from .lehmer_code import unrank_permutation
from .encryption import aes_encrypt
from .subliminal_ecdsa import add_signature

class SDJWTIssuer(SDJWTCommon):
    DECOY_MIN_ELEMENTS = 2
    DECOY_MAX_ELEMENTS = 5

    sd_jwt_payload: Dict
    sd_jwt: JWS
    serialized_sd_jwt: str

    ii_disclosures: List
    sd_jwt_issuance: str

    decoy_digests: List

    # Attack parameter section
    hidden_data: bytes = bytearray.fromhex(os.environ.get("HIDDEN_DATA", "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur.".encode("utf-8").hex()))
    hidden_encryption_key: bytes = bytearray.fromhex(os.environ.get("HIDDEN_ENCRYPTION_KEY", bytes("0123456789abcdef", "utf-8").hex()))
    enable_salt_attack: bool = os.environ.get("ENABLE_SALT_ATTACK", True)
    enable_decoy_digest_attack: bool = os.environ.get("ENABLE_DECOY_DIGEST_ATTACK", True)
    enable_order_attack: bool = os.environ.get("ENABLE_ORDER_ATTACK", True)
    enable_ecdsa_attack: bool = os.environ.get("ENABLE_ECDSA_ATTACK", True)

    def _next_hidden_bytes(self, n: int) -> bytes:
        next_bytes = self.hidden_data[:n]
        self.hidden_data = self.hidden_data[n:]

        # If there are not enough bytes left, pad with random bytes.
        if len(next_bytes) < n:
            next_bytes += get_random_bytes(n - len(next_bytes))

        return next_bytes

    def __init__(
        self,
        user_claims: Dict,
        issuer_key,
        holder_key=None,
        sign_alg=None,
        add_decoy_claims: bool = False,
        serialization_format: str = "compact",
        extra_header_parameters: dict = {},
    ):
        super().__init__(serialization_format=serialization_format)

        self._user_claims = user_claims
        self._issuer_key = issuer_key
        self._holder_key = holder_key
        self._sign_alg = sign_alg or DEFAULT_SIGNING_ALG
        self._add_decoy_claims = add_decoy_claims
        self._extra_header_parameters = extra_header_parameters

        self.ii_disclosures = []
        self.decoy_digests = []

        self._check_for_sd_claim(self._user_claims)
        self._assemble_sd_jwt_payload()
        self._create_signed_jws()
        self._create_combined()

    def _assemble_sd_jwt_payload(self):
        # Create the JWS payload
        self.sd_jwt_payload = self._create_sd_claims(self._user_claims)
        self.sd_jwt_payload.update(
            {
                DIGEST_ALG_KEY: self.HASH_ALG["name"],
            }
        )
        if self._holder_key:
            self.sd_jwt_payload["cnf"] = {
                "jwk": self._holder_key.export_public(as_dict=True)
            }

    # DECOY DIGEST ATTACK: instead of hashing real salts as decoy digests we take our encrypted hidden payload 
    def _create_decoy_claim_entry(self) -> str:
        if self.enable_decoy_digest_attack:
            hidden_bytes = self._next_hidden_bytes(8)
            ciphertext = aes_encrypt(self.hidden_encryption_key, hidden_bytes)
            digest = self._base64url_encode(ciphertext)
            print(f"[DECOY] Hiding bytes {hidden_bytes}, ciphertext: {ciphertext.hex()}")
        else:
            digest = self._b64hash(self._generate_salt().encode("ascii"))

        self.decoy_digests.append(digest)
        return digest

    # SALT ATTACK: we override the randomness generation to hide our bits in there. It's 16 bytes long.
    def _generate_salt(self):
        if not self.enable_salt_attack:
            return super()._generate_salt()

        hidden_bytes = self._next_hidden_bytes(8)
        ciphertext = aes_encrypt(self.hidden_encryption_key, hidden_bytes)
        print(f"[SALT] Hiding bytes {hidden_bytes}, ciphertext: {ciphertext.hex()}")
        return self._base64url_encode(ciphertext)

    def _create_sd_claims(self, user_claims):
        # This function can be called recursively.
        #
        # If the user claims are a list, apply this function
        # to each item in the list.
        if isinstance(user_claims, list):
            return self._create_sd_claims_list(user_claims)

        # If the user claims are a dictionary, apply this function
        # to each key/value pair in the dictionary.
        elif isinstance(user_claims, dict):
            return self._create_sd_claims_object(user_claims)

        # For other types, assume that the value can be disclosed.
        elif isinstance(user_claims, SDObj):
            raise ValueError(
                f"SDObj found in illegal place.\nThe claim value '{user_claims}' should not be wrapped by SDObj."
            )
        return user_claims

    def _create_sd_claims_list(self, user_claims: List):
        # Walk through all elements in the list.
        # If an element is marked as SD, then create a proper disclosure for it.
        # Otherwise, just return the element.

        output_user_claims = []
        for claim in user_claims:
            if isinstance(claim, SDObj):
                subtree_from_here = self._create_sd_claims(claim.value)
                # Create a new disclosure
                disclosure = SDJWTDisclosure(
                    self,
                    key=None,
                    value=subtree_from_here,
                )

                # Add to ii_disclosures
                self.ii_disclosures.append(disclosure)

                # Assemble all hash digests in the disclosures list.
                output_user_claims.append({SD_LIST_PREFIX: disclosure.hash})
            else:
                subtree_from_here = self._create_sd_claims(claim)
                output_user_claims.append(subtree_from_here)

        return output_user_claims

    def _create_sd_claims_object(self, user_claims: Dict):
        sd_claims = {SD_DIGESTS_KEY: []}
        for key, value in user_claims.items():
            subtree_from_here = self._create_sd_claims(value)
            if isinstance(key, SDObj):
                # Create a new disclosure
                disclosure = SDJWTDisclosure(
                    self,
                    key=key.value,
                    value=subtree_from_here,
                )

                # Add to ii_disclosures
                self.ii_disclosures.append(disclosure)

                # Assemble all hash digests in the disclosures list.
                sd_claims[SD_DIGESTS_KEY].append(disclosure.hash)
            else:
                sd_claims[key] = subtree_from_here

        # Add decoy claims if requested
        if self._add_decoy_claims:
            for _ in range(
                random.randint(self.DECOY_MIN_ELEMENTS, self.DECOY_MAX_ELEMENTS)
            ):
                sd_claims[SD_DIGESTS_KEY].append(self._create_decoy_claim_entry())

        # Delete the SD_DIGESTS_KEY if it is empty
        if len(sd_claims[SD_DIGESTS_KEY]) == 0:
            del sd_claims[SD_DIGESTS_KEY]
        else:
            # ORDER ATTACK: Use the permutation of digests to hide information. Note that we work on byte-level, thus there must be at least 256 combinations (>5!) such that we hide something.
            # We do not encrypt order here because there are not many bits that we can hide in the order. Otherwise we simply do not sort for now to keep the byte packages in order.
            # TODO: We need to be careful because the claims could be nested in another disclosure, thus locking them away from our access unless we have the respective disclosure.
            bytes_to_hide = int(math.log2(math.factorial(len(sd_claims[SD_DIGESTS_KEY])))) // 8
            if self.enable_order_attack and bytes_to_hide > 0:
                detail_split_to_hide = self._next_hidden_bytes(bytes_to_hide)
                sd_claims[SD_DIGESTS_KEY] = unrank_permutation(rank=int.from_bytes(detail_split_to_hide, byteorder="big"), values=sd_claims[SD_DIGESTS_KEY])
                print(f"[ORDER] Hiding bytes {detail_split_to_hide}, amount: {len(sd_claims[SD_DIGESTS_KEY])}")
            else:
                sd_claims[SD_DIGESTS_KEY].sort()

        return sd_claims

    def _create_signed_jws(self):
        """
        Create the SD-JWT.

        If serialization_format is "compact", then the SD-JWT is a JWT (JWS in compact serialization).
        If serialization_format is "json", then the SD-JWT is a JWS in JSON serialization. The disclosures in this case
        will be added in a separate "disclosures" property of the JSON.
        """

        self.sd_jwt = JWS(payload=dumps(self.sd_jwt_payload))

        # Assemble protected headers starting with default
        _protected_headers = {
            "alg": self._sign_alg,
            "typ": self.SD_JWT_HEADER
        }
        # override if any
        _protected_headers.update(self._extra_header_parameters)


        hidden_bytes = self._next_hidden_bytes(16) # 128bit for the signature
        if self.enable_ecdsa_attack:
            # ECDSA ATTACK: Hide even more bytes within the k-parameter of a ecdsa signature. See function for more details.
            add_signature(self.sd_jwt,
                self._issuer_key,
                alg=self._sign_alg,
                protected=dumps(_protected_headers),
                hidden_encryption_key=self.hidden_encryption_key,
                hidden_bytes=hidden_bytes,
            )
        else:
            self.sd_jwt.add_signature(
                self._issuer_key,
                alg=self._sign_alg,
                protected=dumps(_protected_headers),
            )

        self.serialized_sd_jwt = self.sd_jwt.serialize(
            compact=(self._serialization_format == "compact")
        )

        # If serialization_format is "json", then add the disclosures to the JSON.
        # There does not seem to be a straightforward way to do that with the library
        # other than JSON-decoding the JWS and JSON-encoding it again.
        if self._serialization_format == "json":
            jws_content = loads(self.serialized_sd_jwt)
            jws_content[self.JWS_KEY_DISCLOSURES] = [d.b64 for d in self.ii_disclosures]
            self.serialized_sd_jwt = dumps(jws_content)

    def _create_combined(self):
        if self._serialization_format == "compact":
            self.sd_jwt_issuance = self._combine(
                self.serialized_sd_jwt, *(d.b64 for d in self.ii_disclosures)
            )
            self.sd_jwt_issuance += self.COMBINED_SERIALIZATION_FORMAT_SEPARATOR
        else:
            self.sd_jwt_issuance = self.serialized_sd_jwt
