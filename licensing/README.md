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
| `licensing gen -n 10` | Generate 10 license keys and print them (manual sales, giveaways) |
| `licensing gen -n 50 -note "reseller A" -out keys.txt` | ...with a label, also saved to a file |
| `licensing keys` | List every key that hasn't been used yet |
| `licensing users` | List activated machines: HWID, OS, date, state |
| `licensing revoke <hwid>` | Stop that machine from running netvis |
| `licensing unrevoke <hwid>` | Allow it again |
| `licensing delkey <key>` | Destroy an unused key |

## License keys

30 characters from `A-Z2-7` — 150 bits of randomness, unguessable, but
short enough to read off a screen and type. The alphabet has no `0`, `1`,
`8` or `9`, so there's no `O`/`0` or `I`/`1` confusion.

Case and separators are normalised away on both sides, so all of these are
the same key:

```
GCN32GFISXB7OKKRLEGQAU4KOMF6VH
gcn32-gfisx-b7okk-rlegq-au4ko-mf6vh
GCN32 GFISX B7OKK RLEGQ AU4KO MF6VH
```

A customer pasting from an email — line breaks and all — activates fine.

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

## Selling (Polar)

Polar is the shop: it takes the payment, handles VAT as merchant of
record, generates the license key, emails it to the customer, and enforces
both the 6-month term and the one-machine limit. Nothing to pre-generate,
nothing to upload, and you can't run out of keys.

**Set up in the Polar dashboard**

1. Create a product, one-time payment, $25.
2. Add a **License Keys** benefit to it:
   - prefix `NETVIS`
   - expires after **6 months**
   - activation limit **1**
3. Copy your **organization ID** (Settings) and the product's **checkout
   link**.

**Then on the server**, in `config.json`:

```json
{ "polar_organization_id": "fda84e25-...",
  "checkout_url": "https://buy.polar.sh/polar_cl_..." }
```

The Buy button on the site points at `/buy`, which redirects to
`checkout_url` — so changing the shop link never needs a rebuild.

**What happens when someone activates:** netvis sends the key here, this
server calls Polar once to activate it (labelled with the machine's HWID,
so the customer can see and free devices in their Polar portal), and stores
the activation locally with the expiry Polar reports.

Every launch after that is answered from this server's own database —
Polar is not consulted. That keeps startup fast, keeps customers working if
Polar has an outage, and means `licensing users` and `revoke` still
describe reality.

If Polar is unreachable *during* an activation, nothing is recorded and the
customer is told to try again — their key is not consumed.

### Your own keys still work

`licensing gen` keys are unchanged and are checked locally, before Polar is
ever contacted. Use them for giveaways, support cases and testing:

```
.\deploy\keys.ps1 -Server ubuntu@YOUR.IP -N 5
```

## License term

A key is worth **6 months** from redemption.

- `/authentificate` returns `days_left`, and `403 {"error":"expired"}` once
  the term is up — the client shows "your license ran out, enter a new key"
  rather than pretending the machine was never activated.
- Redeeming a key on a machine that's already licensed **renews** it, and
  extends from the current expiry, so renewing early doesn't throw away
  paid days.
- With more than 7 days left, a key is refused politely instead of being
  consumed — the customer keeps it for later or uses it on another PC.
- Activations created before expiry existed have an empty `expires_at` and
  never expire. They were sold that way.

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

**2. Set up the server, once.** On OVH the IP is on the VPS dashboard. OVH
images often log you in as `ubuntu` or `debian` rather than `root`, so
`sudo -i` first if needed.

```
scp deploy/setup-server.sh root@YOUR.IP:/tmp/
ssh root@YOUR.IP "bash /tmp/setup-server.sh netvis.cc"
```

That installs Caddy (from its own repo — it isn't in Ubuntu's), creates the
`netvis` service user, writes `config.json`, installs the systemd unit, and
turns on the firewall. Port 8443 is deliberately left closed: the licensing
server listens on localhost and is reachable only through Caddy.

Do this **after** DNS has propagated, so Caddy can get its certificate on
first start.

**3. Deploy, from your PC.** Windows has `ssh`/`scp` built in.

```
.\deploy\deploy.ps1 -Server root@YOUR.IP
```

It cross-compiles for Linux, uploads, and restarts the service. Re-run it
for every update — the website is embedded, so one file is the whole
deployment. Add `-Exe ..\netvis.exe` to publish a new client build to
`/downloads/` at the same time.

**4. The client already points here** — the address is compiled into
netvis.exe (`kServer` in `src/license.cpp`). Nothing to configure on a
customer's machine.

**5. Make keys:** `ssh root@YOUR.IP "cd /opt/netvis && sudo -u netvis ./licensing gen -n 10"`

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

The server address is **compiled into netvis.exe** (`kServer` in
`src/license.cpp`) and can't be overridden at runtime — a config file
holding it would be a one-line license bypass, since anyone could point the
client at a server of their own that approves everything. Changing the
address means editing that constant and rebuilding.

To test against a server on your own machine, change `kServer` to
`http://127.0.0.1:8443` in a local build.
