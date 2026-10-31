import { useEffect, useState } from "react";
import { SourceTag } from "./Bits";

// The key provider: where the AES-256-GCM data key comes from. Three in-process mocks; the development key is the loud fallback.
export default function KeyPanel({ state, lab }) {
  const k = state.vault.key;
  const [configured, setConfigured] = useState(k.configured);
  const [reachable, setReachable] = useState(k.reachable);
  const [msg, setMsg] = useState("");
  useEffect(() => { setConfigured(k.configured); setReachable(k.reachable); }, [k.configured, k.reachable]);
  const admin = state.actor.role === "admin";
  const off = lab.readOnly || lab.busy || !admin;
  const restart = async () => { const r = await lab.act("POST", "/api/vault/keys", { key: { configured, reachable } }); setMsg(r.ok ? `Restarted: the key now comes from ${r.body.result.provider}; ${r.body.result.resealed} sealed values were re-sealed with fresh nonces.` : `Refused: ${r.body.error || r.status}`); };
  return (
    <section className="panel" data-testid="key-panel">
      <h2 className="panel__title">Key provider <SourceTag source="deck" /></h2>
      <p data-testid="key-active">Active key source: <strong>{k.label}</strong> (key version {k.keyVersion}; {k.reason}). {k.algorithm}, {k.nonceBytes}-byte random nonce per value, {k.aad} bound in as additional authenticated data.</p>
      {k.warning && <p className="field-error" role="alert" data-testid="dev-warning"><strong>DEVELOPMENT KEY.</strong> {k.warning.replace(/^DEVELOPMENT KEY: /, "")}</p>}
      <ul className="plain">{k.steps.map((s) => <li key={s}>{s}</li>)}</ul>
      <p data-testid="nonce-info">Your vault: <strong>{state.vault.sealedValues}</strong> sealed values, <strong>{state.vault.distinctNonces}</strong> distinct nonces (a nonce is never reused).</p>
      <div className="filters">
        <label>Configured key source
          <select value={configured} disabled={off} onChange={(e) => setConfigured(e.target.value)} data-testid="key-configured">
            <option value="aws">AWS Secrets Manager with KMS (mock)</option><option value="vault">HashiCorp Vault, on premises (mock)</option><option value="none">None configured</option>
          </select>
        </label>
        <label className="check"><input type="checkbox" checked={reachable} disabled={off} onChange={(e) => setReachable(e.target.checked)} data-testid="key-reachable" /> It answers at startup</label>
        <button type="button" disabled={off} onClick={restart} data-testid="key-restart">Restart the vault service</button>
      </div>
      <p className="muted">{admin ? "Lab-invented: a restart re-resolves the key, and the lab re-seals every value under it so the demo continues (a real service that came up on a different key could not open its old values). The three providers are mocks; the development key is derived from a public string and protects nothing." : "Restarting the service is an administrator action: act as the administrator to change the key source. (It gives the administrator no way to read anyone's credential.)"}</p>
      {msg && <p role="status" data-testid="key-message">{msg}</p>}
    </section>
  );
}
