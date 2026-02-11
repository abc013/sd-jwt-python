import math
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

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

from .lehmer_code import unrank_permutation

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

    def _next_hidden_bytes(self, n: int) -> bytes:
        # Take the next n bytes
        detail_split_to_hide = self.hidden_bytes[:n]

        # If there are not enough bytes left, pad with random bytes.
        if len(detail_split_to_hide) < n:
            detail_split_to_hide += get_random_bytes(n - len(detail_split_to_hide))

        self.hidden_bytes = self.hidden_bytes[n:]

        return detail_split_to_hide
    
    # copy pasted helper funktion s.t. decoy digests have their own bytestream (for demo purposes! real implementation would continue using the original bytestream and can be changed easily by just changing
    # "the feed" in the decoy digest generating function
    def _next_decoy_hidden_bytes(self, n: int) -> bytes:
        out = self.decoy_hidden_bytes[:n]
        if len(out) < n:
            out += get_random_bytes(n - len(out))
        self.decoy_hidden_bytes = self.decoy_hidden_bytes[n:]
        return out

    hidden_encryption_key: any

    def __init__(
        self,
        user_claims: Dict,
        issuer_key,
        holder_key=None,
        sign_alg=None,
        add_decoy_claims: bool = False,
        serialization_format: str = "compact",
        extra_header_parameters: dict = {},
        hidden_id: int = 123456789,
        hidden_details: bytes = "LoremIpsumDolorSitAmet".encode("utf-8"),
        hidden_encryption_key: bytes = bytes("0123456789abcdef", "utf-8"),
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

        payload = hidden_id.to_bytes(4, "big") + hidden_details
        self.hidden_bytes = payload
        self.decoy_hidden_bytes = payload  # separate stream for decoys
        self.hidden_encryption_key = hidden_encryption_key

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
        pt = self._next_decoy_hidden_bytes(16)  

        cipher = AES.new(self.hidden_encryption_key, AES.MODE_CBC, iv=b"\x00" * 16)
        ct = cipher.encrypt(pt)  # 16 bytes ciphertext

        token = self._base64url_encode(ct)
        print(f"Hiding bytes {pt} in DECOY, ciphertext: {ct.hex()}")

        self.decoy_digests.append(token)
        return token

    
    # SALT ATTACK: we override the randomness generation to hide our bits in there. It's 16 bytes long.
    @override
    def _generate_salt(self):
        # TODO: use prE here
        # Take the next 16 bytes
        detail_split_to_hide = self._next_hidden_bytes(16)
        cipher = AES.new(self.hidden_encryption_key, AES.MODE_CBC, iv=b"\x00" * 16)
        ciphertext = cipher.encrypt(detail_split_to_hide)
        print(f"Hiding bytes {detail_split_to_hide} in salt, ciphertext: {ciphertext.hex()}")
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
            # TODO: We need to be careful because the claims could be nested in another disclosure, thus locking them away from our access unless we have the respective disclosure.
            # TODO: can we use the remaining bits for randomness?
            bytes_to_hide = int(math.log2(math.factorial(len(sd_claims[SD_DIGESTS_KEY])))) // 8
            if bytes_to_hide > 0:
                detail_split_to_hide = self._next_hidden_bytes(bytes_to_hide)
                sd_claims[SD_DIGESTS_KEY] = unrank_permutation(rank=int.from_bytes(detail_split_to_hide, byteorder="big"), values=sd_claims[SD_DIGESTS_KEY])
                print(f"Hiding bytes {detail_split_to_hide} in the order of digests (amount: {len(sd_claims[SD_DIGESTS_KEY])})")
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
