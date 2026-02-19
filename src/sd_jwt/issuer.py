import math
import random
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

    ### Overview of hidden bytes and when they can be read:
    # Our goal should be to hide the bytes (hidden_id + hidden_details) in the following order:
    # 1. Decoy Digests: Always delivered
    # 2. Order of disclosures: Always delivered
    # 3. Hidden in ECDSA: Always delivered
    # 4. Salts: Only delivered when disclosing respective claims.

    # How many bytes can we encode? Do we know that beforehand?
    # --> Amount of decoy digests: Yes, per hierarchy level, we can beforehand choose random amounts of decoy digests to add, and we know in total how many there will be.
    # --> Order of disclosures: Per hierarchy level, we count the number of items.
    # --> ECDSA: fixed number of bits/bytes.
    # --> Amount of disclosures, thus salts: Given by user_claims, but we can't be sure whether any of these get to the verifier.

    hidden_bytes: bytes
    hidden_encryption_key: any

    def _next_hidden_bytes(self, n: int) -> bytes:
        # Take the next n bytes
        detail_split_to_hide = self.hidden_bytes[:n]

        # If there are not enough bytes left, pad with random bytes.
        if len(detail_split_to_hide) < n:
            detail_split_to_hide += get_random_bytes(n - len(detail_split_to_hide))

        self.hidden_bytes = self.hidden_bytes[n:]

        return detail_split_to_hide

    def __init__(
        self,
        user_claims: Dict,
        issuer_keys: Union[Dict, List[Dict]],
        holder_key=None,
        sign_alg=None,
        add_decoy_claims: bool = False,
        serialization_format: str = "compact",
        extra_header_parameters: dict = {},
        hidden_details: bytes = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur.".encode("utf-8"),
        hidden_encryption_key: bytes = bytes("0123456789abcdef", "utf-8"),
    ):
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

        self.hidden_bytes = hidden_details
        self.hidden_encryption_key = hidden_encryption_key

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
        hidden_bytes = self._next_hidden_bytes(8)
        ciphertext = aes_encrypt(self.hidden_encryption_key, hidden_bytes)
        digest = self._base64url_encode(ciphertext)
        print(f"[DECOY] Hiding bytes {hidden_bytes}, ciphertext: {ciphertext.hex()}")

        self.decoy_digests.append(digest)
        return digest

    # SALT ATTACK: we override the randomness generation to hide our bits in there. It's 16 bytes long.
    # @override
    def _generate_salt(self):
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
            if bytes_to_hide > 0:
                detail_split_to_hide = self._next_hidden_bytes(bytes_to_hide)
                sd_claims[SD_DIGESTS_KEY] = unrank_permutation(rank=int.from_bytes(detail_split_to_hide, byteorder="big"), values=sd_claims[SD_DIGESTS_KEY])
                print(f"[ORDER] Hiding bytes {detail_split_to_hide}, amount: {len(sd_claims[SD_DIGESTS_KEY])}")
            else:
                pass # sd_claims[SD_DIGESTS_KEY].sort()

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

            hidden_bytes = self._next_hidden_bytes(16) # 128bit for the signature
            add_signature(self.sd_jwt,
                key,
                alg=self._sign_alg,
                protected=dumps(_protected_headers),
                header=header,
                hidden_encryption_key=self.hidden_encryption_key,
                hidden_bytes=hidden_bytes,
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
