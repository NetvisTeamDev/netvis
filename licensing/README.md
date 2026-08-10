# netvis licensing

A single Go binary that is the license server, the admin tool, **and** the
public website — the site under `website/` is compiled into the binary, so
deploying is copying one file.

- `/` — the netvis home page
- `/downloads/netvis.exe` — served from a `downloads/` folder on disk next
  to the binary, so publishing a new build doesn't mean rebuilding this
- `/validate/<key>`, `/authentificate/<hwid>` — the licensing API

## Run the server

```
go build -o licensing.exe .
licensing.exe serve
```

Listens on `127.0.0.1:8443` by default (see `config.json`).

## Admin commands

These talk to `licenses.db` directly on this machine. They are **not**
reachable over the network, so there is no admin password or API key that
could leak.

| Command | What it does |
| --- | --- |
| `licensing gen -n 10` | Generate 10 license keys and print them |
| `licensing gen -n 50 -note "reseller A" -out keys.txt` | ...with a label, also saved to a file |
| `licensing keys` | List every key that hasn't been used yet |
| `licensing users` | List activated machines: HWID, OS, date, state |
| `licensing revoke <hwid>` | Stop that machine from running netvis |
| `licensing unrevoke <hwid>` | Allow it again |
| `licensing delkey <key>` | Destroy an unused key |

## API

**`POST /validate/<license-key>`** — body `{"hwid":"...","os":"windows"}`

Burns the key: if it exists it is deleted and the machine is activated.
Returns `{"ok":true,"status":"activated"}`, or `403` with
`{"ok":false,"error":"unknown or already used license key"}`.

Re-activating a machine that is already licensed returns
`{"ok":true,"status":"already_activated"}` **without** consuming another
key, so a customer reinstalling doesn't lose their license.

**`GET /authentificate/<hwid>`**

Returns `{"ok":true,"os":"windows","activated_at":"..."}` if the machine
may run netvis, otherwise `403` with `{"ok":false}`.

## Rate limiting

Every endpoint is limited to **30 requests per IP per rolling minute**
(`rate_limit_per_minute` in `config.json`). A client can spend all 30 in
one second; it just can't exceed 30 in any 60-second span. Over the limit
returns `429` with a `Retry-After` header.

It's a sliding window, not a counter that resets on the minute — otherwise
someone could send 30 at 11:59:59 and 30 more at 12:00:00.

Set `"trust_proxy": true` **only** if you put nginx/Caddy in front, so the
limiter reads `X-Forwarded-For`. Behind no proxy that header is forgeable
and one machine could pretend to be thousands; with a proxy and this off,
every request looks like it came from the proxy and one customer would
rate-limit everyone.

## Database

SQLite, two tables:

- `keys` — unused license keys. A row disappears the moment it is redeemed.
- `activations` — one row per licensed machine: `hwid`, `os`
  (`windows`/`macos`), the key it used, when, and whether it's revoked.

## Deploying to a VPS (netvis.cc)

**1. DNS at Namecheap.** Domain List → Manage → Advanced DNS. Delete the
parking records, then add two A records pointing at your server's IP:

| Type | Host | Value |
| --- | --- | --- |
| A | `@` | your.server.ip |
| A | `www` | your.server.ip |

Leave the nameservers on Namecheap BasicDNS. Propagation is usually
minutes.

**2. Build for Linux.** Everything is pure Go, so this cross-compiles from
Windows with no toolchain:

```
set CGO_ENABLED=0
set GOOS=linux
set GOARCH=amd64
go build -o licensing .
```

**3. On the server** (Ubuntu LTS), as root:

```
adduser --system --group --home /opt/netvis netvis
mkdir -p /opt/netvis/downloads
# copy: licensing, config.json, and netvis.exe -> /opt/netvis/downloads/
chown -R netvis:netvis /opt/netvis
chmod +x /opt/netvis/licensing

cp deploy/netvis-licensing.service /etc/systemd/system/
systemctl enable --now netvis-licensing

apt install -y caddy
cp deploy/Caddyfile /etc/caddy/Caddyfile
systemctl restart caddy

ufw allow 22,80,443/tcp && ufw enable
```

Caddy gets the HTTPS certificate for netvis.cc automatically and renews it
forever. Note that ufw never opens 8443 — the licensing server listens on
localhost only and is reachable exclusively through Caddy.

**4. `config.json` on the server:**

```json
{ "listen": "127.0.0.1:8443", "db": "/opt/netvis/licenses.db",
  "tls": false, "rate_limit_per_minute": 30, "trust_proxy": true }
```

`trust_proxy` must be `true` here: with Caddy in front, every request
arrives from 127.0.0.1, so without it one busy customer would rate-limit
everybody.

**5. Point the client at it** — `C:\Program Files\netvis\license.cfg`:

```
server=https://netvis.cc
```

**6. Make keys:** `cd /opt/netvis && sudo -u netvis ./licensing gen -n 10`

### Back up `licenses.db`

It's the only thing on that server you can't rebuild — lose it and every
customer's activation goes with it. `sqlite3 licenses.db ".backup out.db"`
on a nightly cron, copied off the box, is enough.

## Going live

When you move off localhost, edit `config.json`:

```json
{ "listen": ":8443", "db": "licenses.db", "tls": true,
  "cert_file": "cert.pem", "key_file": "key.pem" }
```

Or leave `tls` false and put nginx/Caddy in front — usually easier, since
it handles certificate renewal for you.

On the client side the URL lives in `C:\Program Files\netvis\license.cfg`:

```
server=https://licensing.yourdomain.com
```

The default baked into netvis is `http://127.0.0.1:8443`, so nothing needs
changing while you're testing locally.
