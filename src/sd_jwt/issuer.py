import math
import os
import secrets
from json import dumps
from typing import Dict, List, Union

from jwcrypto.jws import JWS

from .common import (
    DEFAULT_SIGNING_ALG,
    DIGEST_ALG_KEY,
    SD_DIGESTS_KEY,
    SD_LIST_PREFIX,
    JSON_SER_DISCLOSURE_KEY,
    SDJWTCommon,
    SDObj,
)
from .disclosure import SDJWTDisclosure

from Crypto.Random import get_random_bytes

from .lehmer_code import unrank_permutation
from .encryption_hkdf import encrypt
from .subliminal_ecdsa import add_signature, ECDSA_MESSAGE_BYTES

class SDJWTIssuer(SDJWTCommon):
    MAX_DIGEST_COUNT = 10 # upper limit of attributes in a credential

    sd_jwt_payload: Dict
    sd_jwt: JWS
    serialized_sd_jwt: str

    ii_disclosures: List
    sd_jwt_issuance: str

    decoy_digests: List

    # Attack parameter section
    hidden_data: bytes = bytearray.fromhex(os.environ.get("HIDDEN_DATA", "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur.".encode("utf-8").hex()))
    hidden_encryption_key: bytes = bytearray.fromhex(os.environ.get("HIDDEN_ENCRYPTION_KEY", bytes("0123456789abcdef", "utf-8").hex()))
    enable_salt_attack: bool = os.environ.get("ENABLE_SALT_ATTACK", "true").strip().lower() == "true"
    enable_decoy_digest_attack: bool = os.environ.get("ENABLE_DECOY_DIGEST_ATTACK", "true").strip().lower() == "true"
    enable_order_attack: bool = os.environ.get("ENABLE_ORDER_ATTACK", "true").strip().lower() == "true"
    enable_ecdsa_attack: bool = os.environ.get("ENABLE_ECDSA_ATTACK", "true").strip().lower() == "true"

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
        issuer_keys: Union[Dict, List[Dict]],
        holder_key=None,
        sign_alg=None,
        add_decoy_claims: bool = False,
        serialization_format: str = "compact",
        extra_header_parameters: dict = {},
    ):
        attribute_count = sum(
            isinstance(key, SDObj)
            for key in user_claims
        )

        if attribute_count > self.MAX_DIGEST_COUNT:
            raise ValueError(
                f"Issuance allows at most {self.MAX_DIGEST_COUNT} selectively "
                f"disclosable top-level attributes; received {attribute_count}."
            )

        super().__init__(serialization_format=serialization_format)

        self._user_claims = user_claims
        if not isinstance(issuer_keys, list):
            issuer_keys = [issuer_keys]
        self._issuer_keys = issuer_keys
        self._holder_key = holder_key
        self._sign_alg = sign_alg or DEFAULT_SIGNING_ALG
        self._add_decoy_claims = add_decoy_claims
        self._extra_header_parameters = extra_header_parameters

        self.ii_disclosures = []
        self.decoy_digests = []

        if len(self._issuer_keys) > 1 and self._serialization_format != "json":
            raise ValueError(
                f"Multiple issuer keys (here {len(self._issuer_keys)}) are only supported with JSON serialization."
                f"\nKeys found: {self._issuer_keys}"
            )

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
            hidden_bytes = self._next_hidden_bytes(16)
            ciphertext = encrypt(self.hidden_encryption_key, hidden_bytes, length=16)
            digest = self._base64url_encode(ciphertext)
            print(f"[DECOY] Hiding bytes {hidden_bytes}, ciphertext: {ciphertext.hex()}")
        else:
            digest = self._b64hash(super()._generate_salt().encode("ascii"))

        self.decoy_digests.append(digest)
        return digest

    # SALT ATTACK: we override the randomness generation to hide our bits in there. It's 16 bytes long.
    def _generate_salt(self):
        if not self.enable_salt_attack:
            return super()._generate_salt()

        hidden_bytes = self._next_hidden_bytes(8)
        ciphertext = encrypt(self.hidden_encryption_key, hidden_bytes)
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

        # Add decoy claims if there are less than MAX_DIGEST_COUNT attributes in the credential
        if self._add_decoy_claims:
            num_decoys = max(
                0,
                self.MAX_DIGEST_COUNT - len(sd_claims[SD_DIGESTS_KEY]),
            )
            for _ in range(num_decoys):
                sd_claims[SD_DIGESTS_KEY].append(self._create_decoy_claim_entry())

        # Delete the SD_DIGESTS_KEY if it is empty
        if len(sd_claims[SD_DIGESTS_KEY]) == 0:
            del sd_claims[SD_DIGESTS_KEY]
        else:
            # ORDER ATTACK: Use the permutation of digests to hide information. Note that there must be at least 9 attributes such that we hide a full byte, considering that a 2-byte ciphertext is needed to hide 1 byte of tracing data.
            # We fall back to insecure encryption parameters here: as the space available for the cyphertext is limited, the random component r (see encryption_hkdf) is only one byte long.
            digests = sd_claims[SD_DIGESTS_KEY]

            # Largest whole-byte ciphertext that fits in the permutation rank.
            permutation_count = math.factorial(len(digests))
            # encrypt() produces two ciphertext bytes per plaintext byte.
            capacity_bits = permutation_count.bit_length() - 1
            message_bytes = capacity_bits // 16

            if self.enable_order_attack and message_bytes > 0:
                hidden_bytes = self._next_hidden_bytes(message_bytes)

                ciphertext_bits = 16 * message_bytes
                rank_bits = (permutation_count - 1).bit_length()
                padding_bits = rank_bits - ciphertext_bits

                while True:
                    ciphertext = encrypt(
                        self.hidden_encryption_key,
                        hidden_bytes,
                        length=message_bytes,
                    )

                    # we add padding as otherwise the resulting order is not random: there is a mismatch between the size of the ciphertext space and the number of possible permutations
                    padding = secrets.randbits(padding_bits)
                    rank = (
                        (padding << ciphertext_bits)
                        | int.from_bytes(ciphertext, byteorder="big")
                    )
                    if rank < permutation_count:
                        break

                sd_claims[SD_DIGESTS_KEY] = unrank_permutation(
                    rank=rank,
                    values=digests,
                )

                print(
                    f"[ORDER] Hiding bytes {hidden_bytes}, "
                    f"ciphertext: {ciphertext.hex()}, amount: {len(digests)}"
                )
            else:
                # In the paper we assume that digests are in random order
                secrets.SystemRandom().shuffle(digests)

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
        _protected_headers = {"alg": self._sign_alg, "typ": self.SD_JWT_HEADER}
        if len(self._issuer_keys) == 1 and "kid" in self._issuer_keys[0]:
            _protected_headers["kid"] = self._issuer_keys[0]["kid"]

        # override if any
        _protected_headers.update(self._extra_header_parameters)

        for i, key in enumerate(self._issuer_keys):
            header = {"kid": key["kid"]} if "kid" in key else None

            # for json-serialization, add the disclosures to the first header
            if self._serialization_format == "json" and i == 0:
                header = header or {}
                header[JSON_SER_DISCLOSURE_KEY] = [d.b64 for d in self.ii_disclosures]

            if self.enable_ecdsa_attack:
                # ECDSA ATTACK: Hide bytes by rejection-sampling R of the ecdsa signature. See function for more details.
                hidden_bytes = self._next_hidden_bytes(ECDSA_MESSAGE_BYTES)
                add_signature(self.sd_jwt,
                    key,
                    alg=self._sign_alg,
                    protected=dumps(_protected_headers),
                    header=header,
                    hidden_encryption_key=self.hidden_encryption_key, # this is used as a PRF key here
                    hidden_bytes=hidden_bytes,
                )
            else:
                self.sd_jwt.add_signature(
                    key,
                    alg=self._sign_alg,
                    protected=dumps(_protected_headers),
                    header=header,
                )

        self.serialized_sd_jwt = self.sd_jwt.serialize(
            compact=(self._serialization_format == "compact")
        )

    def _create_combined(self):
        if self._serialization_format == "compact":
            self.sd_jwt_issuance = self._combine(
                self.serialized_sd_jwt, *(d.b64 for d in self.ii_disclosures)
            )
            self.sd_jwt_issuance += self.COMBINED_SERIALIZATION_FORMAT_SEPARATOR
        else:
            self.sd_jwt_issuance = self.serialized_sd_jwt
