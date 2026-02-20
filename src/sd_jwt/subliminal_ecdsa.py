
import hashlib

from jwcrypto.common import base64url_decode, base64url_encode
from jwcrypto.common import json_decode, json_encode
from jwcrypto.jws import JWS, InvalidJWSObject, JWSCore, InvalidJWSSignature
from jwcrypto.common import JWKeyNotFound
from jwcrypto.jwk import JWK, JWKSet

from ecdsa.ecdsa import Signature
from ecdsa import numbertheory, SigningKey, VerifyingKey
from ecdsa.keys import sigdecode_string, _truncate_and_convert_digest
from .encryption import aes_encrypt, aes_decrypt

signing_key: SigningKey

#######################################################################################################################################
# Extracting
#######################################################################################################################################

def _es256_extract_k(signing_key: SigningKey, hash, signature: Signature) -> bytes:
    G = signing_key.privkey.public_key.generator
    n = G.order()
    r = signature.r
    s = signature.s
    if r < 1 or r > n - 1:
        return False
    if s < 1 or s > n - 1:
        return False

    c = numbertheory.inverse_mod(s, n)
    u1 = (hash * c) % n
    u2 = (r * c) % n
    if hasattr(G, "mul_add"):
        xy = G.mul_add(u1, signing_key.privkey.public_key.point, u2)
    else:
        xy = u1 * G + u2 * signing_key.privkey.public_key.point
    v = xy.x() % n

    k = c * (hash + r * signing_key.privkey.secret_multiplier) % n

    return k.to_bytes(32, byteorder='big')

def custom_es256_extract_k(signature, sigin, hidden_signature_key) -> bytes:
    if hidden_signature_key is None:
        global signing_key
    else:
        signing_key = SigningKey.from_string(hidden_signature_key, hashfunc=hashlib.sha256)
    verifying_key: VerifyingKey = signing_key.get_verifying_key()

    r, s = sigdecode_string(signature, verifying_key.pubkey.order)
    ecdsa_signature = Signature(r, s)

    number = _truncate_and_convert_digest(
        hashlib.sha256(sigin).digest(),
        verifying_key.curve,
        False,
    )

    return _es256_extract_k(signing_key, number, ecdsa_signature)

def es256_extract_bytes(self: JWS, signature, hidden_encryption_key, hidden_signature_key):
    global signing_key
    """Verifies a signature

    :raises InvalidJWSSignature: if the verification fails.

    :return: Returns True or an Exception
    :rtype: `bool`
    """
    sigin = b'.'.join([self.protected.encode('utf-8'),
                        self.payload])

    ciphertext = custom_es256_extract_k(signature, sigin, hidden_signature_key);
    msg = aes_decrypt(hidden_encryption_key, ciphertext, length=16)
    print(f"[SIGNATURE] Got cleartext {msg}, ciphertext: {ciphertext.hex()}")

def _verify(self: JWS, alg, key, payload, signature, protected, header=None, hidden_encryption_key=None, hidden_signature_key=None):
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

        if resulting_alg == "ES256":
            es256_extract_bytes(signer, signature, hidden_encryption_key, hidden_signature_key)

        signer.verify(signature)

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

                if resulting_alg == "ES256":
                    es256_extract_bytes(signer2, signature, hidden_encryption_key, hidden_signature_key)

                signer2.verify(signature)

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

def verify(self: JWS, key, alg=None, detached_payload=None, hidden_encryption_key=None, hidden_signature_key=None):
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
                            hidden_encryption_key=hidden_encryption_key,
                            hidden_signature_key=hidden_signature_key)
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
                                hidden_encryption_key=hidden_encryption_key,
                                hidden_signature_key=hidden_signature_key)
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
        global signing_key

        sigin = b'.'.join([self.protected.encode('utf-8'),
                           self.payload])

        # es256 has order in [0;2^256) range. We make our lives simple here and send 128bit information and 128bit randomness. If we get out of range, we simply reroll.
        signing_key = SigningKey.from_pem(self.key.export_to_pem(private_key=True, password=None), hashfunc=hashlib.sha256)

        k = signing_key.privkey.order + 1
        while k > signing_key.privkey.order or k <= 1:
            ciphertext = aes_encrypt(hidden_encryption_key, hidden_bytes, length=16)
            k = int.from_bytes(ciphertext, byteorder="big")

        signature = signing_key.sign(sigin, allow_truncate=False, k=k)
        print(f"[SIGNATURE] Hiding bytes {hidden_bytes}, ciphertext: {ciphertext.hex()}")

        return {'protected': self.protected,
                'payload': self.payload,
                'signature': base64url_encode(signature)}

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