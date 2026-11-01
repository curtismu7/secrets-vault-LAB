# Secrets Vault LAB

A simulation of Ping's User Vault and Secret Store Management release claims: a private credential store per person, injected into that person's backend calls at request time so the backend sees who actually acted, and one inventory and one read/write policy over five enterprise secret managers without becoming another copy of them.

Tier: Demo
Repo: https://github.com/ping-sandbox/secrets-vault-LAB
Catalog: D108

**Tier: Demo.** Source: the Ping ID4AI Workforce H2 2026 deck, slides 42 and 43 (and 36 and 35, read only), release 2026-11-02. **Every product claim is a Ping release claim, UNVERIFIED on our tenant.** Nothing here calls a real secret manager, key service, gateway, backend, identity provider or tenant, and nothing leaves your machine. Every credential is a lab mock, and no API ever returns a stored value.

## What is simulated

**Mock mode (default).** Everything runs offline in one process and is read-only. Seven scripted scenarios (store, edit and use a credential; delete, restore and purge after 24 hours; nobody else can read it, not even an administrator; four credential shapes injected at request time; create, rotate, soft-delete and purge in a secret store; read and write as separate grants; the nightly re-sync noticing a rename) were run through the lab's own engine with a deterministic random source, and the tables the pages show are generated from that run (`server/src/mockTable.json`; a doctor check and a test fail if it drifts). Every write is refused with 409. The tables are recorded as one person per scenario.

**Live mode (owner-run, still local).** The same engine acts on your own actions, as the person you pick in the header (the lab has no sign-in: you choose who acts so you can try the wrong person; the real product takes the caller from the verified token). Real AES-256-GCM seals every value; five mock secret managers hold real state in this process (versions, soft-delete and purge for Azure, rotation counters, the hierarchy each keeps, file fields for Delinea); you move a **lab clock** (+1 minute, +1 hour, +23 h 59 min, +24 hours, +7 days), so the 24-hour purge and the nightly 02:00 re-sync run for real. The banner says which mode you are in. Live never leaves loopback and never touches a real system.

What it shows:

1. **User Vault.** Store a credential (type a lab mock value, or let the lab generate one) for a target system in one of four shapes (bearer token, API key, username and password as HTTP Basic, custom header pairs). Entries show present, size, version, masked and the first 8 hex characters of the nonce; the value is never shown again. Edit metadata with the secret left blank: the stored value is kept byte for byte (a field you fill in replaces only that field). Delete stages for 24 hours (restore inside the window, purged at exactly 24:00, a staged entry cannot be edited or used). 500 entries per user and 64 KB (65536 bytes) per credential, to the byte. There is no administrator override. **Try every other role** has each other person ask for your entry: each is forced into their own vault (not found), naming an owner is refused. The key provider panel shows where the AES-256-GCM key comes from (AWS Secrets Manager with KMS envelope decryption, HashiCorp Vault, or the compiled-in development key with a loud warning; all three are mocks) and how many nonces are distinct.
2. **Request-time injection.** A simulated agent asks a backend for an operation; the gateway builds the credential from the caller's own entry and injects it. Three panes: what the agent sees (no credential, masked), what the gateway injects (header names, masked values), what the backend logged (the principal who actually acted). The same call through a shared service account logs the same identity for everyone. With no entry for the target the call is refused and never falls back to the shared account. Removing a target (administrator) cleans up the entries that pointed at it, automatically. The slide 36 backend-credential modes (none, an app-wide static token, a per-user credential from the User Vault, a second OAuth flow, and token pass-through as a fifth) are described in text; the gateway is another lab's subject.
3. **Secret Stores.** Five providers with their own structure (GCP organisation, folder, project; Delinea folders and templates; CyberArk safes; Azure vaults; AWS name prefixes). Create, read, update, rotate on demand and delete across all five; soft-delete, recover and purge only on Azure (the other four refuse); a Delinea file field. A read is fetched live from the provider and delivered to a simulated consumer: the page says "value delivered to the consumer (masked)". The provider connection credential is sealed at rest and never shown. A lab helper changes a provider directly (rename, delete, rotate, add) without telling Privilege.
4. **Governance.** The grant table (read and write are separate grants; default deny; only the administrator edits it), the audit trail (every read and mutation, and every refusal: allowed, denied or refused, credential-free, scoped by role), the nightly re-sync reports (new, renamed, deleted, changed, with the effect of a rename on the grants), and the **no-copy proof**, computed from the current state: everything the Privilege side keeps is searched for every value the providers, the connections and the vaults hold (plain, JSON-escaped, base64, hex; a long value by its first, middle and last 63 characters; a short value of 4 to 11 bytes only as a whole field). Its self-test is computed by the same scans from hard canaries (a quote, a backslash, non-ASCII, a newline, a short value), so a zero means something. In a large workspace the proof is not run on every read: the page says so and a button runs it on the server in short slices that never block the lab. The consumers table compares what each simulated consumer holds against a fresh read of the provider (it goes stale after a provider-side rotation).
5. **Diagram.** ReactFlow, drawn from diagram-studio/1 data loaded by name: movable boxes, Simulate, speed, Reset (restores box positions). Two diagrams: the credential injected at request time; a governed read with no copy.
6. **Talk track,** with two "Why it matters" entries (challenge, technical and business lines, marked as Ping claims). Also in `docs/talk-track.md`. Three vertical packs (finance, health, retail) change every name.

### What is lab-invented

The deck gives claims; everything else is the lab's own, and each field is tagged in the app as "deck claim", "lab reading" or "lab-invented". This lab cites no console swagger field names. In particular:

- **Invented:** the additional authenticated data (user id and entry id), the key provider choice (configured, reachable, restart and re-seal), the simulated gateway, agent and backend (the backend recognises a credential by an HMAC it keeps and logs the credential's owner; the first registration of a credential wins), the grant shape (principal, "provider:path" scope with `*` and `**`, read and write), the nightly time (02:00 on the lab clock) and finding kinds, the simulated consumers, the no-copy proof method, the roster, the verticals and the four sample targets.
- **Lab readings:** no fallback to a shared account; field-by-field merge inside a credential; staged entries count toward the 500 until purged; 64 KB as 65536 bytes over the secret fields only; target removal deletes entries outright; AWS, GCP, Delinea and CyberArk delete permanently (the deck lists soft-delete and purge for Azure); Azure vaults and AWS prefixes as the structure of those two; "not found" for a caller with no grant versus "denied" for one with the other action.
- **Provider call shapes** on `.example` hosts: illustrations of typical public API shapes, never sent.

### Known limits of the model

- **Masking is a heuristic.** One normaliser runs before every check (the input cleaner, the name and id refusals, the hop panes and the response mask): Unicode NFKC; every default-ignorable and format character deleted (Hangul fillers, variation selectors, tag characters, Arabic number signs, bidi marks and the like); **every C0 and C1 control character except tab, line feed and carriage return deleted, never turned into a space** (so `p<U+0001>a<U+0001>ssword` is `password`); percent-escapes decoded as UTF-8, up to four rounds (so `%C2%85` is a control character and is deleted). Tab, line feed, carriage return, U+2028 and U+2029 are separators: every scan runs a second time with them deleted, so `pass<TAB>word=x` is caught while a plain multi-line note stays readable. The detectors then catch the common token, key and password shapes, key-aware forms (a JSON key, `userPassword`, `client_secret`, in any quoting, including `{"password":"x"}` typed as text), "my password is ..." style text, URL user info (with a scheme, with a bare `//`, and with none: `bob:word@host`, and a token alone before the `@`) and long key-like runs. A masked answer shows the decoded, masked text, and **object key names are masked too**. Names, paths, tags, header names, workspace ids and grant scopes that look like a credential are refused; notes are masked first and only then checked against the length limit (a note that is too long once masked is refused whole, never cut). Every hop pane shows the request echo masked, with unknown key names replaced and any shown text cut at 300 characters marked as cut. **False-positive trade-off:** a credential word, whitespace only and a value of 6 or more characters that contains a digit is masked (`password hunter2xyz`, `api key hunter2xyz`, `pw hunter2xyz`), so `password reset` and `the token requirements` stay readable but `password reset99` is masked too. **What it still misses:** a bare word with no keyword before it (`hunter2xyz` alone); a value without a digit after a bare space (`password correcthorse`) or shorter than 6 characters (`pw a1b2`); look-alike letters from another alphabet (a Cyrillic or Greek letter inside `password` is not folded to Latin by NFKC); a keyword split by an ordinary space or another visible character (`pass word=x`); a value percent-encoded more than four times; words in other languages. Type lab mock values only, or let the lab generate one.
- Editing an entry's metadata keeps the stored value byte for byte, and does NOT move it: the simulated backend knows the credential under the target and header it was stored with. Retargeting an entry, or renaming an API-key header, leaves a credential the new target does not recognise, so a gateway call then returns the lab's 200 carrying the simulated backend's own 401 ("rejected: credential not recognised"); store the secret again to register it. That 401 is the simulated backend's answer, shown as data.
- A vault entry deleted here is not revoked at the target (a vault holds a credential, it does not control the target); the simulated backend keeps the credential it issued.
- Limits: 500 entries per user (staged entries count until purged) and 64 KB (65536 bytes) per credential, one byte over refused whole; a workspace holds at most 4 MB of sealed credentials in all (a lab safety limit, not a deck claim: 64 full-size credentials, or 500 small ones); a name is at most 80 characters and notes 200 (longer text is refused whole with `bad_name` or `bad_notes`, never cut); a custom header credential has 1 to 5 pairs; 20 targets, 400 inventory secrets, 100 grants and 2000 audit entries (a full workspace refuses new work: Reset); the clock moves forward only, at most 7 days (10080 minutes) per move; a store field is at most 4096 bytes; one answer shows at most 40 hops; the backend and gateway logs keep the last 300 calls (a response shows the latest 20). The no-copy proof is cached against the state version; a workspace too large to search on every read shows "not run" with a button (`POST /api/proof/run`), never a made-up pass. Values under 4 bytes are skipped by the proof and counted. A purge or clean-up writes one audit entry per person (ids listed up to three, then a count), and a clock move the audit trail could not hold is refused whole. `aws:prod/payments/**` covers `prod/payments` itself and everything below it (`**` matches zero or more segments).
- Restarting the key service re-seals every value under the new key so the demo continues; a real service that came up on a different key could not open its old values.
- The grants are a table, not the request-approve workflow the deck mentions ("one request-approve policy"); approvals are another lab's subject.
- State is per `X-Workspace` id, 500 workspaces, and a workspace is dropped after one hour with no activity (every action renews it); a new workspace beyond the cap is refused (503). The visitor's id is chosen by the page, not authenticated. An id that looks like a credential (24 or more hex digits, a prefix such as `sk-`, `pw-` or `token-`, a keyword read with its hyphens as spaces, or no letter at all) is a 400 `bad_workspace`, never echoed, and creates nothing. The page makes ids of the form `w-` plus 16 hex digits (always a letter) and, when the server refuses its stored id, makes a new one and repeats the call once, so a bad stored id cannot brick the tab; a bare word with no keyword (`bob-hunter2xyz`) cannot be told from a name and is accepted.
- An unidentified caller (no `X-Lab-Actor`, or one off the roster) gets a 401 with no state in the body, and no workspace is created for it. **A missing file is a JSON 404, never the page:** `/assets/...`, `/favicon.ico`, `/robots.txt`, `/foo.map`, `/foo.svg`, `/sitemap.xml` and any dotfile are `{"error":"not_found"}`; only a GET for an extension-less path that is not a dotfile (`/vault`) gets the page. **A wrong method on a known route is a 405** with an `Allow` header (`POST /api/state` allows `GET, HEAD`; `GET /api/stores/rotate` allows `POST`); an unknown path or method anywhere is a JSON 404 or 405 that never echoes the path (Express's default "Cannot POST /path" page cannot appear), and a malformed escape, a bad JSON body or an oversized body is a fixed JSON 400 or 413.
- **Every refused Live action is a real HTTP 4xx** (400, 401, 403, 404, 409, 413, 503) with a JSON body (`ok: false`, the error code and detail, the fresh state and the hops) that the page reads as data. Chromium logs each 4xx as a console line (for example "Failed to load resource: 409"): that is expected and documented, nothing is hidden behind a 200. An unknown vertical is a 400, an unknown scenario or diagram a 404, never a silent fallback.
- The lab helpers: the provider-side change helper and the manual re-sync are the administrator's (a non-administrator gets an audited 403; the helper bypasses the grant model on purpose). The clock buttons are a lab control, not a product action: they are not role-gated and are audited under whoever presses them.

## Run from a clone

Prerequisites: Node 26 or newer. Docker only if you use the Docker form. Mock mode works with no setup at all: no tenant, no credentials, no settings file.

```
git clone https://github.com/ping-sandbox/secrets-vault-LAB.git
cd secrets-vault-LAB
npm ci
npm run build
npm start
```

Open http://localhost:7450/. Or in one step: `./scripts/run.sh` (installs and builds if needed, runs the doctor, starts).

## Settings file

All standalone apps read one settings file, `~/Development/.env`, which must be mode 600. `STANDALONE_ENV` overrides its path. This lab needs none of it. It parses the file (`util.parseEnv`) and takes exactly one optional key; no other key from the file ever enters the server's environment:

- `SVL_LAB_MODE` (optional): `mock` (default) or `live`, the mode the page opens in. The header toggle switches per visit. A bare `MODE` in the shared file is ignored, because it may belong to another app.

The shared file holds no `PORT`: the lab keeps its port default in code. Admin or worker credentials never belong in that file (they live in `~/.config/demo-kit/provisioning.json`), and this lab uses none. The doctor reports whether the file exists and its mode, and never prints a value.

## Ports, and what to do if the port is taken

```
Ports: secrets-vault-LAB listens on 7450 (set with PORT, default 7450).
Port range for this app: 7450-7499.

If the port is taken:
1. Find what is using it:
   lsof -iTCP:7450 -sTCP:LISTEN -n -P
2. If it is an old copy of this app, stop that process: kill <PID>.
3. If it is something else, stop it, or start this app on another port:
   PORT=<other port> npm start
4. Do not use 8080, 5173, 3000, 4000, 4400, 4510, 4600-4601, 18080, 19080 or 19090.
```

## Mock and live modes

The toggle in the header switches between them on every page, and the banner shows the same mode. **Mock** reads the generated tables (recorded as one person per scenario; the "Acting as" list shows that person and is off) and refuses every write with 409. **Live** drives the real local engine on your own actions as the person you pick; the lab clock, the key provider, the targets, the grants and Reset are live controls. Both are loopback-only with zero outbound network.

## Health, doctor and reset

- `GET /api/health` returns `demo-health/1` (public, GET only, no detail).
- `npm run doctor` (or `PORT=7459 npm run doctor` if 7450 is busy) prints one line per check and exits 1 on failure: Node, mode, bind, port range, the settings file, the scripted scenarios, the Mock table against the engine, a real vault cycle (a sealed entry unsealed for a gateway call, the backend logging the real user, an administrator forced into their own empty vault, the no-copy search finding nothing and finding a planted copy), the story tokens in every vertical, the hosts, the response mask, the diagrams, and the netguard self-test.
- `npm run reset` clears the default workspace of a running lab; the Reset button does the same for your workspace and puts the diagram boxes back.

## Docker (optional)

```
HOST_PORT=7450 docker compose up --build -d
```

Publishes on `127.0.0.1` only (a test pins it), runs as a non-root user with a read-only filesystem and every capability dropped. Open http://127.0.0.1:7450/. `docker compose down --rmi local` removes it. Docker runs on OrbStack, never Docker Desktop.

## Tests

`npm test` runs the server tests (`node --test test/*.test.js`, a glob), the web tests (vitest against the real Express app) and the repo tests (`node --test scripts/*.test.mjs`). On Node 26: 225 server tests, 54 web tests and 24 repo tests, all passing. Conformance (`node ~/Development/demo-kit-base-rule18-warn/scripts/conformance.mjs . --new`), `check-drift.sh` and `check-css.sh` are run by hand.

## Troubleshooting

- **The page says "Could not load the lab".** The server is not running, or it is on another port: `npm start`, then open the URL it prints.
- **Port 7450 is taken.** See "Ports, and what to do if the port is taken" above.
- **Live controls are greyed out.** You are in Mock mode (tables are read-only): press Live in the header.
- **Restart, add target, grant or revoke is greyed out.** Those are administrator actions: pick the administrator in "Acting as". None of them reads a credential.
- **A name, path or tag is refused as "credential_shaped_text".** The masking heuristic thought it looked like a key (a long unbroken run of letters and digits). Use words.
- **The browser console shows 4xx lines (404, 400, 409...) after a refused action or "Try every other role".** They are the real status codes of deliberate refusals; see the known limits.

## Ownership

Owner: the Ping demo owner. Licence: MIT (see `LICENSE`). Report problems to the owner or open an issue in the `ping-sandbox` repository once it exists.

## Not done

- No SE k8s mock build (deferred by the owner, 2026-10-31); no k8s manifests.
- The grants are a table, not a request-approve workflow; the gateway itself and the other slide 36 backend-credential modes are another lab's subject.
- Nothing was verified against a real Ping tenant, gateway, console or secret manager: every product claim is UNVERIFIED on our tenant.
