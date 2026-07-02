import os
import ssl
import time
import json
import base64
import hashlib
import argparse
import threading
import urllib.parse
import urllib.request
import http.server
from http import HTTPStatus
from datetime import datetime

WHITESPACE_LENGTH = 16

def w(data, length=WHITESPACE_LENGTH):
    return f"{data}{' ' * max(0, length - len(data))}: "

class AuthHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        return

    def log_source_ip(self):
        source_ip = self.client_address[0]
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        with open("network.log", "a", encoding="utf-8") as f:
            f.write(f"({now}) {source_ip} {self.path}\n")

    def do_GET(self):
        self.log_source_ip()

        url = urllib.parse.urlparse(self.path)
        parameters = urllib.parse.parse_qs(url.query)

        if url.path == "/":
            self.send_response(HTTPStatus.OK)
            self.end_headers()
            self.wfile.write(b"Server is running.")
            return

        if url.path == "/login":
            auth_url = self.server.webserver.generate_url()
            self.send_response(HTTPStatus.FOUND)
            self.send_header("Location", auth_url)
            self.end_headers()
            return

        if url.path != f"/{self.server.webserver.redirect_endpoint}":
            self.send_response(HTTPStatus.NOT_FOUND)
            self.end_headers()
            self.wfile.write(b"Not Found")
            return

        if "error" in parameters:
            self.send_response(HTTPStatus.BAD_REQUEST)
            self.end_headers()

            error_description = parameters.get("error_description", ["Unknown error"])[0]
            self.wfile.write(error_description.encode())

            print(f"{w('Error')}{error_description}")
            return

        code = parameters.get("code", [None])[0]
        state = parameters.get("state", [None])[0]

        if not code:
            self.send_response(HTTPStatus.BAD_REQUEST)
            self.end_headers()
            self.wfile.write(b"Missing authorization code")
            return

        token_response = self.server.webserver.token_request(code, state)

        if "error" in token_response:
            self.send_response(HTTPStatus.BAD_REQUEST)
            self.end_headers()
            self.wfile.write(b"Token request failed.")

            print(f"{w('Error')}{token_response.get('error')}")
            print(f"{w('Description')}{token_response.get('error_description')}")
            return

        self.send_response(HTTPStatus.OK)
        self.end_headers()
        self.wfile.write(self.server.webserver.generate_final_url())

        print(f"{w('Success')}Token received")

        with open("token.json", "a", encoding="utf-8") as f:
            json.dump(token_response, f, indent=4)

class WebServer:
    def __init__(self, tid, cid, host, redirect_host, port, certfile, keyfile, microsoft_endpoint, scope, redirect_final):
        self.tid = tid
        if self.tid is None:
            self.tid = "common"

        self.cid = cid
        self.host = host
        self.redirect_host = redirect_host
        self.port = port
        self.certfile = certfile
        self.keyfile = keyfile
        self.microsoft_endpoint = microsoft_endpoint
        self.scope = scope
        self.redirect_endpoint = "getAuth"
        self.pkce = {}
        self.redirect_final = redirect_final

        if self.port == 443:
            self.redirect_url = f"https://{self.redirect_host}/{self.redirect_endpoint}"
        else:
            self.redirect_url = f"https://{self.redirect_host}:{self.port}/{self.redirect_endpoint}"
            
        print(f"URL to use: {self.generate_url()}")
        
    def generate_final_url(self):
        s = f'<script>document.location="{self.redirect_final}";</script>'
        return bytearray(s, "utf-8")

    def generate_url(self):
        verifier, challenge = self.generate_pkce_pair()
        state = self.base64_url_encode(os.urandom(32))

        self.pkce[state] = verifier

        url = f"https://login.{self.microsoft_endpoint}/{self.tid}/oauth2/v2.0/authorize"

        data = {
            "client_id": self.cid,
            "response_type": "code",
            "redirect_uri": self.redirect_url,
            "response_mode": "query",
            "scope": self.scope,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "state": state
        }

        return f"{url}?{urllib.parse.urlencode(data)}"

    def token_request(self, code, state):
        if state not in self.pkce:
            return {
                "error": "invalid_state",
                "error_description": "The state value was missing or invalid."
            }

        verifier = self.pkce.pop(state)

        data = {
            "client_id": self.cid,
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": self.redirect_url,
            "code_verifier": verifier,
            "scope": self.scope
        }

        token_url = f"https://login.{self.microsoft_endpoint}/{self.tid}/oauth2/v2.0/token"

        encoded_data = urllib.parse.urlencode(data).encode("utf-8")

        request = urllib.request.Request(
            token_url,
            data=encoded_data,
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "application/json"
            },
            method="POST"
        )

        try:
            with urllib.request.urlopen(request) as response:
                body = response.read().decode("utf-8")
                return json.loads(body)

        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", errors="replace")

            try:
                return json.loads(body)
            except Exception:
                return {
                    "error": "http_error",
                    "error_description": body
                }

        except Exception as e:
            return {
                "error": "request_failed",
                "error_description": str(e)
            }

    def server(self):
        httpd = http.server.ThreadingHTTPServer((self.host, self.port), AuthHandler)
        httpd.webserver = self

        if not os.path.exists(self.certfile) or not os.path.exists(self.keyfile):
            print(f"{w('Error')}TLS certificate or key file missing.")
            print(f"{w('Cert')}{self.certfile}")
            print(f"{w('Key')}{self.keyfile}")
            return

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(self.certfile, self.keyfile)
        httpd.socket = context.wrap_socket(httpd.socket, server_side=True)

        print(f"{w('Success')}Web server listening on {self.host} port {self.port}")
        print(f"{w('Login URL')}https://{self.redirect_host}/login")
        print(f"{w('Redirect URL')}{self.redirect_url}")
        print(f"{w('Network Log')}network.log")
        print(f"{w('Token Output')}token.json")

        httpd.serve_forever()

    def generate_pkce_pair(self):
        verifier = self.base64_url_encode(os.urandom(32))
        digest = hashlib.sha256(verifier.encode("ascii")).digest()
        challenge = self.base64_url_encode(digest)

        return verifier, challenge

    def base64_url_encode(self, data):
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--tenant", default="common")
    parser.add_argument("--client-id", required=True)
    parser.add_argument("--listen-host", default="0.0.0.0")
    parser.add_argument("--redirect-host", default="localhost")
    parser.add_argument("--redirect-final", default="https://login.microsoftonline.com")
    parser.add_argument("--port", type=int, default=443)
    parser.add_argument("--cert", default="cert.pem")
    parser.add_argument("--key", default="key.pem")
    parser.add_argument("--microsoft-endpoint", default="microsoftonline.com")
    parser.add_argument("--scope", default="openid profile offline_access https://graph.microsoft.com/.default")
    args = parser.parse_args()

    server = WebServer(
        tid=args.tenant,
        cid=args.client_id,
        host=args.listen_host,
        redirect_host=args.redirect_host,
        port=args.port,
        certfile=args.cert,
        keyfile=args.key,
        microsoft_endpoint=args.microsoft_endpoint,
        scope=args.scope,
        redirect_final = args.redirect_final
    )

    server.server()

if __name__ == "__main__":
    main()
