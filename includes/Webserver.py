import os
import ssl
import time
import json
import base64
import hashlib
import threading
import urllib.parse
import http.server
from http import HTTPStatus

WHITESPACE_LENGTH = 16
def w(data, length=WHITESPACE_LENGTH):
    return f"{data}{' ' * (length - len(data))}: "

class AuthHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        url = urllib.parse.urlparse(self.path)
        
        parameters = urllib.parse.parse_qs(url.query)
        if "error" in parameters:
            self.send_response(HTTPStatus.NOT_FOUND)
            self.end_headers()
            print(f"{w('Error')}{parameters.get('error_description')}")
            return
        
        code = parameters.get("code", [None])[0]
        if not code:
            self.send_response(HTTPStatus.BAD_REQUEST)
            self.end_headers()
            self.server.auth_result = {"error": True, "parameters": parameters}
            return
        
        self.send_response(HTTPStatus.OK)
        self.end_headers()
        self.wfile.write(b"You may close this window. You have logged in successfully.")
        self.server.auth_result = {"error": False, "code": code}

class WebServer:

    def __init__(self, tid, cid, host, port):
        self.tid = tid
        self.cid = cid
        self.host = host
        self.port = port
        self.scope = ["openid", "profile", "offline_access", "https://graph.microsoft.com/.default"]
        self.redirect_endpoint = "getAuth"
        self.redirect_url = f"https://{self.host}:{self.port}/{self.redirect_endpoint}"

    def generate_url(self):
        self.generate_pkce_pair()
        url = f"https://login.microsoftonline.com/common/oauth2/v2.0/authorize"
        data = {    "client_id": self.cid, "response_type": "code", "redirect_uri": self.redirect_url, "response_mode": "query", "scope": " ".join(self.scope), "code_challenge": self.challenge, "code_challenge_method": "S256"}
        return f"{url}?{urllib.parse.urlencode(data)}"

    def server(self):
        timeout = 300
        self.server = http.server.HTTPServer((self.host, self.port), AuthHandler)
        self.server.auth_result = None
        print(f"{w('Success')}Web server listening on {self.host} port {self.port}")

        certfile = "includes/web/cert.pem"
        keyfile = "includes/web/key.pem"

        try:
            if os.path.exists(certfile) and os.path.exists(keyfile):
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                context.load_cert_chain(certfile, keyfile)
                self.server.socket = context.wrap_socket(self.server.socket, server_side=True)
            else:
                print(f"{w('Error')}TLS Certificate or key file missing.")
                exit()
        except Exception as e:
            print(f"{w('Error')}TLS was not enabled redirection will fail. {str(e)}")
            exit()

        def serve():
            self.server.timeout = 1
            while self.server.auth_result == None:
                self.server.handle_request()
        
        thread = threading.Thread(target=serve, daemon=True)
        thread.start()

        start = time.time()
        while self.server.auth_result == None and (time.time() - start) < timeout:
                time.sleep(1)
        
        return self.server.auth_result.get("code"), self.verifier, self.redirect_url

    def generate_pkce_pair(self):
        self.verifier = self.base64_url_encode(os.urandom(32))
        self.digest = hashlib.sha256(self.verifier.encode("ascii")).digest()
        self.challenge = self.base64_url_encode(self.digest)

    def base64_url_encode(self, data):
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")