import hashlib

import hmac
import secrets

from ecdsa import NIST256p
from ecdsa.ellipticcurve import INFINITY

from jwcrypto.common import base64url_decode, base64url_encode
from jwcrypto.common import json_decode, json_encode
from jwcrypto.jws import JWS, InvalidJWSObject, JWSCore, InvalidJWSSignature
from jwcrypto.common import JWKeyNotFound
from jwcrypto.jwk import JWK, JWKSet

from ecdsa import numbertheory, SigningKey, VerifyingKey
from ecdsa.keys import sigdecode_string

ECDSA_MESSAGE_BYTES = 1
ECDSA_MAX_TRIALS = 8192

#######################################################################################################################################
# PRF
#######################################################################################################################################

def tracing_prf(key, point):
    """HMAC-SHA256 truncated to the tracing-message length."""
    # Canonical compressed P-256 point encoding; includes both coordinates
    # through x and the parity of y.
    encoded_point = (
        bytes([2 + (int(point.y()) & 1)])
        + int(point.x()).to_bytes(32, "big")
    )
    return hmac.new(
        bytes(key),
        b"sd-jwt-ecdsa-tracing-v1\x00" + encoded_point,
        hashlib.sha256,
    ).digest()[:ECDSA_MESSAGE_BYTES]


#######################################################################################################################################
# Extracting
#######################################################################################################################################

def es256_extract_bytes(
    self: JWSCore,
    signature,
    hidden_encryption_key
):
    verifying_key = VerifyingKey.from_pem(
        self.key.export_to_pem(private_key=False),
        hashfunc=hashlib.sha256,
    )
    if verifying_key.curve != NIST256p:
        raise ValueError("This tracing implementation requires P-256")

    generator = verifying_key.curve.generator
    order = generator.order()
    public_point = verifying_key.pubkey.point

    r, s = sigdecode_string(signature, order)
    if not (1 <= r < order and 1 <= s < order):
        raise InvalidJWSSignature("Invalid ECDSA signature scalars")

    sigin = b".".join([
        self.protected.encode("utf-8"),
        self.payload,
    ])
    z = int.from_bytes(hashlib.sha256(sigin).digest(), "big")
    s_inverse = numbertheory.inverse_mod(s, order)

    # R = (H(m)/s)G + (r/s)Q
    point = (
        ((z * s_inverse) % order) * generator
        + ((r * s_inverse) % order) * public_point
    )

    if point == INFINITY or int(point.x()) % order != r:
        raise InvalidJWSSignature("Invalid reconstructed ECDSA point")

    message = tracing_prf(hidden_encryption_key, point)
    print(f"[SIGNATURE] Got cleartext {message}")

def _verify(self: JWS, alg, key, payload, signature, protected, header=None, hidden_encryption_key=None):
    p = {}
    # verify it is a valid JSON object and decode
    if protected is not None:
        p = json_decode(protected)
        if not isinstance(p, dict):
            raise InvalidJWSSignature('Invalid Protected header')
    # merge headers, and verify there are no duplicates
    if header:
        if not isinstance(header, dict):
            raise InvalidJWSSignature('Invalid Unprotected header')

    # Merge and check (critical) headers
    chk_hdrs = self._merge_check_headers(p, header)
    for hdr in chk_hdrs:
        if hdr in self.header_registry:
            if not self.header_registry.check_header(hdr, self):
                raise InvalidJWSSignature('Failed header check')

    # check 'alg' is present
    if alg is None and 'alg' not in p:
        raise InvalidJWSSignature('No "alg" in headers')
    if alg:
        if 'alg' in p and alg != p['alg']:
            raise InvalidJWSSignature(
                '"alg" mismatch, requested'
                f''' "{alg}", found "{p['alg']}"'''
            )
        resulting_alg = alg
    else:
        resulting_alg = p['alg']

    # the following will verify the "alg" is supported and the signature
    # verifies
    if isinstance(key, JWK):
        signer = JWSCore(resulting_alg, key, protected,
                            payload, self._allowed_algs)

        signer.verify(signature)

        if resulting_alg == "ES256":
            es256_extract_bytes(signer, signature, hidden_encryption_key)

        self.verifylog.append("Success")
    elif isinstance(key, JWKSet):
        keys = key
        if 'kid' in self.jose_header:
            kid_keys = key.get_keys(self.jose_header['kid'])
            if not kid_keys:
                raise JWKeyNotFound('Key ID {} not in key set'.format(
                                    self.jose_header['kid']))
            keys = kid_keys

        for k in keys:
            try:
                signer2 = JWSCore(
                    resulting_alg, k, protected,
                    payload, self._allowed_algs
                )

                signer2.verify(signature)

                if resulting_alg == "ES256":
                    es256_extract_bytes(signer2, signature, hidden_encryption_key)

                self.verifylog.append("Success")
                break
            except Exception as e:  # pylint: disable=broad-except
                keyid = k.get('kid', k.thumbprint())
                self.verifylog.append('Key [{}] failed: [{}]'.format(
                                        keyid, repr(e)))
        if "Success" not in self.verifylog:
            raise JWKeyNotFound('No working key found in key set')
    else:
        raise ValueError("Unrecognized key type")

def verify(self: JWS, key, alg=None, detached_payload=None, hidden_encryption_key=None):
    """Verifies a JWS token.

    :param key: A (:class:`jwcrypto.jwk.JWK`) verification or
        a (:class:`jwcrypto.jwk.JWKSet`) that contains a key indexed by the
        'kid' header.
    :param alg: The signing algorithm (optional). Usually the algorithm
        is known as it is provided with the JOSE Headers of the token.
    :param detached_payload: A detached payload to verify the signature
        against. Only valid for tokens that are not carrying a payload.

    :raises InvalidJWSSignature: if the verification fails.
    :raises InvalidJWSOperation: if a detached_payload is provided but
                                    an object payload exists
    :raises JWKeyNotFound: if key is a JWKSet and the key is not found.
    """

    self.verifylog = []
    self.objects['valid'] = False
    obj = self.objects
    missingkey = False
    if 'signature' in obj:
        payload = self._get_obj_payload(obj, detached_payload)
        try:
            _verify(self, alg, key,
                            payload,
                            obj['signature'],
                            obj.get('protected', None),
                            obj.get('header', None),
                            hidden_encryption_key=hidden_encryption_key)
            obj['valid'] = True
        except Exception as e:  # pylint: disable=broad-except
            if isinstance(e, JWKeyNotFound):
                missingkey = True
            self.verifylog.append('Failed: [%s]' % repr(e))

    elif 'signatures' in obj:
        payload = self._get_obj_payload(obj, detached_payload)
        for o in obj['signatures']:
            try:
                _verify(self, alg, key,
                                payload,
                                o['signature'],
                                o.get('protected', None),
                                o.get('header', None),
                                hidden_encryption_key=hidden_encryption_key)
                # Ok if at least one verifies
                obj['valid'] = True
            except Exception as e:  # pylint: disable=broad-except
                if isinstance(e, JWKeyNotFound):
                    missingkey = True
                self.verifylog.append('Failed: [%s]' % repr(e))
    else:
        raise InvalidJWSSignature('No signatures available')

    if not self.is_valid:
        if missingkey:
            raise JWKeyNotFound('No working key found in key set')
        raise InvalidJWSSignature('Verification failed for all '
                                    'signatures' + repr(self.verifylog))

#######################################################################################################################################
# Signing
#######################################################################################################################################

def custom_es256_sign(self: JWSCore, hidden_encryption_key, hidden_bytes):
    if len(hidden_bytes) != ECDSA_MESSAGE_BYTES:
        raise ValueError(
            f"ECDSA tracing requires {ECDSA_MESSAGE_BYTES} message byte(s)"
        )

    signing_key = SigningKey.from_pem(
        self.key.export_to_pem(private_key=True, password=None),
        hashfunc=hashlib.sha256,
    )
    if signing_key.curve != NIST256p:
        raise ValueError("This tracing implementation requires P-256")

    generator = signing_key.curve.generator
    order = generator.order()

    first_nonce = None
    selected_nonce = None
    matched = False

    # rejection sample the PRF
    for attempt in range(1, ECDSA_MAX_TRIALS + 1):
        nonce = secrets.randbelow(order - 1) + 1
        if first_nonce is None:
            first_nonce = nonce

        point = nonce * generator
        if tracing_prf(hidden_encryption_key, point) == hidden_bytes:
            selected_nonce = nonce
            matched = True
            break

    # failure
    if not matched:
        # The paper specifies using the first sampled nonce on failure.
        selected_nonce = first_nonce

    sigin = b".".join([
        self.protected.encode("utf-8"),
        self.payload,
    ])
    signature = signing_key.sign(
        sigin,
        hashfunc=hashlib.sha256,
        allow_truncate=False,
        k=selected_nonce,
    )

    if matched:
        print(
            f"[SIGNATURE] Hiding bytes {hidden_bytes}, "
            f"trials: {attempt}"
        )
    else:
        print(
            f"[SIGNATURE] No match after {ECDSA_MAX_TRIALS} trials; "
            "using the first nonce. Tracing recovery may fail."
        )

    return {
        "protected": self.protected,
        "payload": self.payload,
        "signature": base64url_encode(signature),
    }

def add_signature(self: JWS, key, alg=None, protected=None, header=None, hidden_encryption_key=None, hidden_bytes=None):
    """Adds a new signature to the object.

    :param key: A (:class:`jwcrypto.jwk.JWK`) key of appropriate for
        the "alg" provided.
    :param alg: An optional algorithm name. If already provided as an
        element of the protected or unprotected header it can be safely
        omitted.
    :param protected: The Protected Header (optional)
    :param header: The Unprotected Header (optional)

    :raises InvalidJWSObject: if invalid headers are provided.
    :raises ValueError: if the key is not a (:class:`jwcrypto.jwk.JWK`)
    :raises ValueError: if the algorithm is missing or is not provided
        by one of the headers.
    :raises InvalidJWAAlgorithm: if the algorithm is not valid, is
        unknown or otherwise not yet implemented.
    """

    b64 = True

    if protected:
        if isinstance(protected, dict):
            protected = json_encode(protected)
        # Make sure p is always a deep copy of the dict
        p = json_decode(protected)
    else:
        p = dict()

    # If b64 is present we must enforce criticality
    if 'b64' in list(p.keys()):
        crit = p.get('crit', [])
        if 'b64' not in crit:
            raise InvalidJWSObject('b64 header must always be critical')
        b64 = p['b64']

    if 'b64' in self.objects:
        if b64 != self.objects['b64']:
            raise InvalidJWSObject('Mixed b64 headers on signatures')

    h = None
    if header:
        if isinstance(header, dict):
            header = json_encode(header)
        # Make sure h is always a deep copy of the dict
        h = json_decode(header)

    p = self._merge_check_headers(p, h)

    if 'alg' in p:
        if alg is None:
            alg = p['alg']
        elif alg != p['alg']:
            raise ValueError('"alg" value mismatch, specified "alg" '
                                'does not match JOSE header value')

    if alg is None:
        raise ValueError('"alg" not specified')

    c = JWSCore(
        alg, key, protected, self.objects.get('payload'),
        self.allowed_algs
    )

    if alg == "ES256":
        sig = custom_es256_sign(c, hidden_encryption_key, hidden_bytes)
    else:
        sig = c.sign()

    o = {
        'signature': base64url_decode(sig['signature']),
        'valid': True,
    }
    if protected:
        o['protected'] = protected
    if header:
        o['header'] = h

    if 'signatures' in self.objects:
        self.objects['signatures'].append(o)
    elif 'signature' in self.objects:
        self.objects['signatures'] = []
        n = {'signature': self.objects.pop('signature')}
        if 'protected' in self.objects:
            n['protected'] = self.objects.pop('protected')
        if 'header' in self.objects:
            n['header'] = self.objects.pop('header')
        if 'valid' in self.objects:
            n['valid'] = self.objects.pop('valid')
        self.objects['signatures'].append(n)
        self.objects['signatures'].append(o)
    else:
        self.objects.update(o)
        self.objects['b64'] = b64