// Sealing and key providers for the User Vault. REAL AES-256-GCM (node:crypto), a fresh random 12-byte nonce per value, the user id and the
// entry id bound in as additional authenticated data (AAD), so a sealed value copied to another user's entry, or another entry, fails to open.
// The three key providers are in-process MOCKS of the deck's key sources (lab-invented behaviour behind a deck claim, UNVERIFIED):
//   aws   : a wrapped data key in a mock Secrets Manager secret, unwrapped by a mock KMS master key (envelope decryption)
//   vault : the data key held in a mock HashiCorp Vault KV path (on premises)
//   dev   : a compiled-in DEVELOPMENT KEY, only as the fallback, derived from a public string (anyone with this source can derive it)
import { createCipheriv, createDecipheriv, createHash, randomBytes } from 'node:crypto';

export const NONCE_BYTES = 12;
export const TAG_BYTES = 16;
export const KEY_BYTES = 32;

export const KEY_PROVIDERS = {
  aws: { id: 'aws', label: 'AWS Secrets Manager with KMS envelope decryption (mock)', keyRef: 'arn:aws:kms:eu-west-1:000000000000:key/mock-0001.example' },
  vault: { id: 'vault', label: 'HashiCorp Vault, on premises (mock)', keyRef: 'https://vault.example/v1/secret/data/svl/data-key' },
  dev: { id: 'dev', label: 'DEVELOPMENT KEY (compiled in, the fallback)', keyRef: 'compiled-in development key' },
};
export const CONFIGURED = ['aws', 'vault', 'none'];

// The compiled-in development key. It is derived from a public string on purpose: it is NOT a secret, and the page says so loudly.
export const DEV_KEY_SOURCE = 'secrets-vault-LAB development key: public, not a secret';
export const devKey = () => createHash('sha256').update(DEV_KEY_SOURCE).digest();

export class SealError extends Error { constructor() { super('sealed value rejected'); this.code = 'sealed_value_rejected'; } }

export const aadFor = (userId, entryId) => `svl1|user|${userId}|entry|${entryId}`;

export function sealBytes(key, plain, aad, nonce) {
  const c = createCipheriv('aes-256-gcm', key, nonce, { authTagLength: TAG_BYTES });
  c.setAAD(Buffer.from(aad, 'utf8'));
  const ct = Buffer.concat([c.update(plain), c.final()]);
  return { n: nonce.toString('base64'), ct: ct.toString('base64'), t: c.getAuthTag().toString('base64') };
}

export function openBytes(key, sealed, aad) {
  try {
    const nonce = Buffer.from(sealed.n, 'base64'); const tag = Buffer.from(sealed.t, 'base64');
    if (nonce.length !== NONCE_BYTES || tag.length !== TAG_BYTES) throw new SealError();
    const d = createDecipheriv('aes-256-gcm', key, nonce, { authTagLength: TAG_BYTES });
    d.setAAD(Buffer.from(aad, 'utf8')); d.setAuthTag(tag);
    return Buffer.concat([d.update(Buffer.from(sealed.ct, 'base64')), d.final()]);
  } catch { throw new SealError(); }
}

// Key material for the two mock providers, made once per engine from the injected random source.
export function makeKeyMaterial(rand = randomBytes) {
  const kmsMaster = rand(KEY_BYTES);     // lives "inside KMS": never leaves, only unwraps
  const dataKey = rand(KEY_BYTES);
  const wrapped = sealBytes(kmsMaster, dataKey, 'svl1|wrapped-data-key', rand(NONCE_BYTES)); // the mock Secrets Manager secret holds only this
  return { aws: { kmsMaster, wrapped }, vault: { kvKey: rand(KEY_BYTES) } };
}

// Resolves the data key at "startup". configured: aws | vault | none. reachable: whether that provider answers. Anything else falls back to the
// development key, and says why. Returns { provider, key, keyRef, steps, warning, reason }.
export function resolveKey(material, configured, reachable) {
  if (configured === 'aws' && reachable) {
    const key = openBytes(material.aws.kmsMaster, material.aws.wrapped, 'svl1|wrapped-data-key');
    return { provider: 'aws', key, keyRef: KEY_PROVIDERS.aws.keyRef, warning: null, reason: 'configured and reachable', steps: ['secretsmanager:GetSecretValue returns the wrapped data key', 'kms:Decrypt unwraps it (the KMS master key never leaves KMS)', 'the data key is held in memory only'] };
  }
  if (configured === 'vault' && reachable) {
    return { provider: 'vault', key: Buffer.from(material.vault.kvKey), keyRef: KEY_PROVIDERS.vault.keyRef, warning: null, reason: 'configured and reachable', steps: ['GET /v1/secret/data/svl/data-key from the on-premises Vault', 'the data key is held in memory only'] };
  }
  const reason = configured === 'none' ? 'no key provider configured' : 'the configured key provider did not answer';
  return { provider: 'dev', key: devKey(), keyRef: KEY_PROVIDERS.dev.keyRef, warning: 'DEVELOPMENT KEY: this key is compiled into the lab and anyone with the source can derive it. Values sealed with it are NOT protected. A real deployment must never run on it.', reason, steps: [`${reason}: falling back to the compiled-in development key`] };
}
