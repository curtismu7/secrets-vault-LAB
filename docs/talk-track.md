# Talk track

<!-- Generated from server/src/data.js by `npm run talk-track`. Do not edit by hand. -->

> Ping release claim, UNVERIFIED on our tenant: every product claim here comes from the Ping ID4AI Workforce H2 2026 deck, slides 42 and 43 (and 36, 35), release 2026-11-02.

## Start with the problem

Shared service accounts break attribution: every action looks the same in the target system's logs, and audit findings and access reviews on those accounts stall agent deployments. Separately, secrets sprawl across five managers with no unified view, policy or rotation. (Ping's challenge text, slides 42 and 43. Fabrikam Bank has both.)

## A private vault per person

On the User Vault tab maya.chen stores a credential for ledger-api. Every operation is forced to the caller's own vault: there is no owner field to fill in. The page shows the entry as present, with a size, a version and a masked value, and never shows the value again.

## No administrator override

Press "Try every other role". omar.reyes, sam.jones (administrator), lee.park (auditor) and ana.silva (support) each ask for maya.chen's entry and each is forced into their own, empty, vault: not found. Naming an owner is refused. Nobody can read another person's credential through the API.

## Encrypted at rest, with a key you can see the source of

Real AES-256-GCM, a fresh 12-byte nonce for every value (the page shows how many are distinct), the user id and entry id bound in. The key comes from AWS Secrets Manager with KMS envelope decryption, or from HashiCorp Vault on premises; with neither, the lab falls back to a compiled-in development key and says so loudly. All three providers are mocks.

## Used at request time: the agent never sees it

On the Request-time injection tab the agent asks ledger-api for a summary. The gateway builds the credential from maya.chen's own entry and injects it. The agent view is masked; the backend logs who actually acted. Try the same call through a shared service account: every caller is the same identity.

## Safe editing: merge, never replace

Edit the notes and leave the secret blank: the stored value is kept, byte for byte. Edit one field of a Basic login and the other stays. Nothing has to be re-entered to change metadata.

## Delete is staged for 24 hours

Delete an entry: it is staged and can be restored. Move the lab clock 23 hours 59 minutes and it is still there; one more minute, exactly 24 hours, and it is purged. A staged entry cannot be edited or used.

## Bounded, and cleaned up

Five hundred entries per user and 64 KB per credential, to the byte. Remove a target system as administrator and the entries that pointed at it are cleaned up automatically, without the administrator reading them.

## Five secret managers, one inventory

On the Secret Stores tab browse AWS, GCP, Azure, Delinea and CyberArk with their own structure (GCP organisation, folder and project; Delinea folders and templates; CyberArk safes). Create, rotate on demand, update and delete across all five; Azure soft-deletes and can purge; Delinea has a file field.

## Read and write are separate grants

On the Governance tab maya.chen can read the AWS database secret but not rotate it, and sam.jones can rotate it but not read it. Someone with no grant is told the secret does not exist. Every read and every change, allowed or denied, is in the audit trail.

## No copy

The inventory keeps names, paths, tags and versions. A read fetches the value live from the provider and hands it to a simulated consumer: the page says "value delivered to the consumer (masked)". The proof panel searches everything Privilege keeps for every value the providers hold, in plain, base64 and hex, and finds none; a planted copy proves the search works.

## The nightly re-sync

Rename one secret, delete another and add a third directly at the providers. Privilege is not told. Move the clock across 02:00 and the report lists what was renamed, deleted and new, from metadata only, and what the rename did to the grants.

## Why it matters: User Vault (slide 42)

Challenge: shared service accounts break attribution: every action looks the same in the target system's logs, and audit findings and access reviews on those accounts stall agent deployments that touch backends. Technical: each user's own credential injected at request time, so backends log who actually acted. Business: audit and access reviews on service accounts pass without backend changes, cutting compliance cost and review friction. These are Ping claims, unverified on our tenant.

## Why it matters: Secret Store Management (slide 43)

Challenge: secrets sprawl across five secret managers with no unified view, policy or rotation, so governance effort grows and duplicates multiply storage and licence cost. Technical: one inventory and one request-approve policy across AWS, Google, Azure, Delinea and CyberArk, with no values ever stored. Business: eliminates duplicate-secret cost, reduces breach blast radius and standardizes rotation. These are Ping claims, unverified on our tenant.

## Where it plugs in (slide 36)

The MCP gateway has backend credential modes: none, an app-wide static token, a per-user credential from the User Vault, a full second OAuth flow, and token pass-through as a fifth. This lab shows the User Vault mode only, and the gateway is another lab's subject.

## What this is not

This is a simulation of Ping's release claims, which are unverified on our tenant. The key services, the five secret managers, the gateway and the backends are in-process models, nothing is sent anywhere, and every shape that the deck does not give is the lab's own and tagged so. Use mock values only.

## The seven scripted scenarios (Mock mode)

1. **Store a credential, edit it, use it.** A person stores a credential in their own vault, edits its notes without re-entering the secret, and the gateway uses it at request time. The backend logs who actually acted; with a shared service account it logs the same identity for everyone.
2. **Delete, restore, then purge after 24 hours.** A deletion is staged, not immediate. It can be restored inside the window, and it is purged at exactly 24 hours: one minute short and it is still there.
3. **Nobody else can read it, not even an administrator.** maya.chen has an entry. Another user, the administrator, the auditor and support each try to act on it, and each is forced into their own, empty, vault: not found. Naming an owner is refused.
4. **Four credential shapes, injected at request time.** Bearer token, API key, HTTP Basic and a custom header pair: the gateway builds each from the caller's own entry, the agent sees none of it, and the backend identifies the caller from the credential. With no entry the call is refused: it does not fall back to a shared account.
5. **Create, rotate, soft-delete and purge in a secret store.** In Azure Key Vault a secret gets created, rotated, soft-deleted, recovered, soft-deleted again and purged. Soft-delete and purge exist only where the deck lists them (Azure): AWS refuses. A Delinea secret with a file field is created too.
6. **Read and write are separate grants.** The user can read an AWS secret but not rotate it; the administrator can rotate it but not read it. A value is delivered only to a simulated consumer, never into an API response. Everything is audited, allowed or denied.
7. **The nightly re-sync notices what changed at the provider.** Someone renames one secret, deletes another and adds a third directly at the providers. Privilege is not told. When the lab clock crosses 02:00 the connected stores re-synchronise: metadata only, no value is ever requested.

## Not demonstrated

- Anything about how the real console, the real gateway or a real secret manager behaves: nothing here ran against one. The five providers are the lab's in-process models and every API call shown is an illustration of a typical public API shape on a .example host, never sent.
- Real key services: the "AWS Secrets Manager with KMS", "HashiCorp Vault" and "development key" providers are in-process mocks. The development key is derived from a public string on purpose and is NOT a secret. The AES-256-GCM sealing itself is real.
- The caller's identity: the real product takes it from the verified token. The lab has no sign-in; you choose who acts so you can try the wrong person. Nothing about authentication is modelled.
- The other backend-credential modes of slide 36 (none, an app-wide static token, a second OAuth flow, token pass-through) and the gateway itself: named, not implemented. Only the per-user User Vault mode and, for contrast, a shared service account are simulated.
- Request-approve workflow for secret access ("one request-approve policy", slide 43): the lab has a grant table (read and write), not an approval flow. Approvals are another lab's subject.
- How a real provider rotates a secret (a Lambda, a CPM, a job): the lab rotation replaces the password-type fields with a new labelled mock value and counts it.
- Whether a deleted vault entry is revoked at the target: it is not, in the lab and in general (a vault holds a credential, it does not control the target). The backend registry keeps the credential it issued.
- Masking and detection are heuristics (lab-written): not every secret has a recognisable shape. Type only lab mock values, or let the lab generate one.
