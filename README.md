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
4. **Governance.** The grant table (read and write are separate grants; default deny; only the administrator edits it), the audit trail (every read and mutation, allowed or denied, scoped by role), the nightly re-sync reports (new, renamed, deleted, changed, with the effect of a rename on the grants), and the **no-copy proof**, computed when you ask: everything the Privilege side keeps is searched for every value the providers, the connections and the vaults hold (plain, base64, hex), with a planted-copy self-test so a zero means something.
5. **Diagram.** ReactFlow, drawn from diagram-studio/1 data loaded by name: movable boxes, Simulate, speed, Reset (restores box positions). Two diagrams: the credential injected at request time; a governed read with no copy.
6. **Talk track,** with two "Why it matters" entries (challenge, technical and business lines, marked as Ping claims). Also in `docs/talk-track.md`. Three vertical packs (finance, health, retail) change every name.

### What is lab-invented

The deck gives claims; everything else is the lab's own, and each field is tagged in the app as "deck claim", "lab reading" or "lab-invented". This lab cites no console swagger field names. In particular:

- **Invented:** the additional authenticated data (user id and entry id), the key provider choice (configured, reachable, restart and re-seal), the simulated gateway, agent and backend (the backend recognises a credential by an HMAC it keeps and logs the credential's owner; the first registration of a credential wins), the grant shape (principal, "provider:path" scope with `*` and `**`, read and write), the nightly time (02:00 on the lab clock) and finding kinds, the simulated consumers, the no-copy proof method, the roster, the verticals and the four sample targets.
- **Lab readings:** no fallback to a shared account; field-by-field merge inside a credential; staged entries count toward the 500 until purged; 64 KB as 65536 bytes over the secret fields only; target removal deletes entries outright; AWS, GCP, Delinea and CyberArk delete permanently (the deck lists soft-delete and purge for Azure); Azure vaults and AWS prefixes as the structure of those two; "not found" for a caller with no grant versus "denied" for one with the other action.
- **Provider call shapes** on `.example` hosts: illustrations of typical public API shapes, never sent.

### Known limits of the model

- Masking and detection are lab-written heuristics: they catch the common token, key and password shapes, "my password is ..." style text, URL passwords and long key-like runs, but not every secret has a recognisable shape. Names, paths, tags and header names that look like a credential are refused; notes are masked. Type lab mock values only, or let the lab generate one.
- A vault entry deleted here is not revoked at the target (a vault holds a credential, it does not control the target); the simulated backend keeps the credential it issued.
- Limits: 500 entries per user (staged entries count until purged) and 64 KB (65536 bytes) per credential, one byte over refused whole; a name is at most 80 characters and notes 200; a custom header credential has 1 to 5 pairs; 20 targets, 400 inventory secrets, 100 grants and 2000 audit entries (a full workspace refuses new work: Reset); the clock moves forward only, at most 7 days (10080 minutes) per move; a store field is at most 4096 bytes; one answer shows at most 40 hops; the backend and gateway logs show the last 300 calls. On a write in a workspace with more than 60 vault entries the proof search is skipped and says so; the next state read runs it in full. Values shorter than 12 bytes are skipped by the proof (they appear in ordinary words) and counted.
- Restarting the key service re-seals every value under the new key so the demo continues; a real service that came up on a different key could not open its old values.
- The grants are a table, not the request-approve workflow the deck mentions ("one request-approve policy"); approvals are another lab's subject.
- State is per `X-Workspace` id, 500 workspaces and one hour of age at most; a new workspace beyond the cap is refused (503). The visitor's id is chosen by the page, not authenticated. An id that looks like a credential is refused, never echoed.
- The browser logs the deliberate 4xx answers of the isolation check (404 and 400) as console messages; every other refusal comes back as data (HTTP 200 with `ok: false`) because the page asks for that.

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

`npm test` runs the server tests (`node --test test/*.test.js`, a glob), the web tests (vitest against the real Express app) and the repo tests (`node --test scripts/*.test.mjs`). On Node 26: __COUNTS__. Conformance (`node ~/Development/demo-kit-base-rule18-warn/scripts/conformance.mjs . --new`), `check-drift.sh` and `check-css.sh` are run by hand.

## Troubleshooting

- **The page says "Could not load the lab".** The server is not running, or it is on another port: `npm start`, then open the URL it prints.
- **Port 7450 is taken.** See "Ports, and what to do if the port is taken" above.
- **Live controls are greyed out.** You are in Mock mode (tables are read-only): press Live in the header.
- **Restart, add target, grant or revoke is greyed out.** Those are administrator actions: pick the administrator in "Acting as". None of them reads a credential.
- **A name, path or tag is refused as "credential_shaped_text".** The masking heuristic thought it looked like a key (a long unbroken run of letters and digits). Use words.
- **The browser console shows 404 and 400 lines after "Try every other role".** They are the deliberate refusals; see the known limits.

## Ownership

Owner: the Ping demo owner. Licence: MIT (see `LICENSE`). Report problems to the owner or open an issue in the `ping-sandbox` repository once it exists.

## Not done

- No SE k8s mock build (deferred by the owner, 2026-10-31); no k8s manifests.
- The grants are a table, not a request-approve workflow; the gateway itself and the other slide 36 backend-credential modes are another lab's subject.
- Nothing was verified against a real Ping tenant, gateway, console or secret manager: every product claim is UNVERIFIED on our tenant.
