// What the Help dialog says. Plain, and as hedged as the rest of the lab (rule 2): what was measured, what is simulated, what is UNVERIFIED.
export const HELP_SECTIONS = [
  {
    heading: "What this lab is",
    body: [
      "A simulation of Ping's User Vault and Secret Store Management release claims: a private credential store per person, injected into that person's backend calls at request time so the backend sees who actually acted, and one inventory and one read/write policy over five enterprise secret managers without becoming another copy of them.",
      "Source: the Ping ID4AI Workforce H2 2026 deck, slides 42 and 43 (and 36 and 35, read only). Every product claim is a Ping release claim, UNVERIFIED on our tenant. Nothing here calls a real secret manager, key service, gateway, backend or tenant, and no API ever returns a stored value."
    ]
  },
  {
    heading: "What was measured, and what was not",
    body: [
      "What the masking layer does was measured (2026-11-02) against shared corpora: 3,754 leak probes lose their secret and stay stable, and 1,926 ordinary strings come out unchanged. That is a sample and a heuristic, not a proof — type lab mock values only, or let the lab generate one.",
      "Everything about the product behaviour is a deck claim or the lab's reading, UNVERIFIED on a tenant: the lab-invented parts (the simulated gateway, agent and backend, the grant shape, the 02:00 nightly re-sync, the no-copy proof method, the key provider choice) are tagged in the app."
    ]
  },
  {
    heading: "Mock and Live (and Real)",
    body: [
      "Mock (default): read-only tables from seven scripted scenarios run through the lab's own engine; every write is refused with 409.",
      "Live: the same engine acts on your own actions, as the person you pick in Acting as (the lab has no sign-in: try the wrong person — nobody else can read your vault, not even an administrator). Real AES-256-GCM seals every value; five mock secret managers hold real state; the lab clock (+1 minute ... +7 days) makes the 24-hour purge and the nightly 02:00 re-sync run for real.",
      "Real is Live plus one hop: the Privilege gateway check card makes one live tools/list through the SE Privilege gateway with an agent access key, then one tools/call probe of a tool no policy grants, so you see the gateway's own refusal shape. The vault, the grants and the backend stay the lab's own engine in both modes. Nothing here was run against a real gateway — Real was exercised only against an in-process fake."
    ]
  },
  {
    heading: "How to use the page",
    body: [
      "User Vault: store, edit (metadata only — the stored value is kept byte for byte), delete (staged for 24 hours: restore inside the window, purged at exactly 24:00), and Try every other role to watch each other person land in their own empty vault. The key provider panel shows where the AES key comes from (all three options are mocks).",
      "Request-time injection: three panes — what the agent sees (no credential), what the gateway injects (masked values), what the backend logged (the principal who actually acted). With no entry for the target the call is refused and never falls back to a shared account.",
      "Secret Stores: create, read, update, rotate and delete across five providers with their own structure; soft-delete and recover on Azure only. Governance: the grant table (read and write are separate grants, default deny), the audit trail, the re-sync reports, and the no-copy proof computed from the current state (a button runs it in slices when the workspace is too large to search on every read).",
      "Diagram boxes can be dragged; Reset restores them and clears your workspace. Presenter is the P key (Esc leaves); the claim tag on every tab stays. Vertical packs (finance, health, retail) change every name. Run observability under each tab shows what each layer logged for this run, with an origin tag on every row."
    ]
  }
];
