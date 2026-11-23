// Rule 27: this lab's side of the shared run-observability panel. The vendored collector (runObservability.js) is never edited here.
//
// What a run is here. The lab's decisions are made by its own engine (engine.js): the simulated gateway injects the caller's own sealed
// credential and the simulated backend logs who actually acted, and the grant table allows or refuses each store action, every one of them
// written to the audit trail. observeAction() reads the audit entries ONE action just wrote (plus that action's own answer) and turns them
// into events: nothing is computed twice, nothing is re-run, and an event the engine did not write is never shown. The time of an event is
// the lab clock stamped on its audit entry (the clock moves only when the visitor moves it, so events of one step tie; their order is kept).
//
// Mock reads the recorded tables, so its record is built from the events stored in the table when it was generated (scenarios.js runs the
// same observeAction for every scripted step). Nothing runs when a table is read, so Mock writes no stdout line.
// Live (rule 19 Real) runs the engine on the visitor's own actions: each event is one stdout line, written when the action ran. A Real record
// holds only what the lab RECEIVED from the Privilege gateway (the agent key's tools/list and one probe): `response` rows, never `logged`.
// The vault, the grant table and the backend are the lab's own engine in every mode, so they are not product logs and are never `response`.
//
// Stdout line: `<iso> secrets-vault-lab decision step=<step> layer=<layer> actor=<who> result=<passed|stopped|unclear|no-reply> cause=<cause> [labtime=<lab clock>] run=<id>`.
// The family's matchers read words such as refused, denied, rejected, forbidden, failed, invalid, expired, mismatch, token, audience, scope and served,
// so steps and causes come from the tables below and use none of them. A line never holds a credential, a sealed value or a gateway URL: it carries
// roster names, step words and ids the lab wrote. A test runs every line kind through the shared classify() for every product.
import crypto from 'node:crypto';
import { createMasker, createRunObservability, keepPattern, LAYERS } from './runObservability.js';

export const SERVICE = 'secrets-vault-lab';
export const KEEP_RUNS = 5; // Real runs kept (complete ones only: a run is stored when it ends, so the open run is never evicted)

// Only safe characters survive, so a typed name cannot add a second key=value pair, a quote or a line.
export const lineValue = (v, n = 64) => String(v ?? '').replace(/[^A-Za-z0-9._:/@-]+/g, '_').slice(0, n) || '-';
// The panel masks emails, addresses and ids in every row, so the stdout line masks them too (then keeps only safe characters).
const { mask } = createMasker();
const field = (v, keep = null) => lineValue(mask(String(v ?? ''), keep));
const RESULT = { allowed: 'passed', refused: 'stopped', blocked: 'stopped', info: 'unclear' };

// A recorder that throws must never break the run or the audit: the failure goes to stderr (a code and a short sanitised message) and the run goes on.
export function reportFailure(where, err) {
  process.stderr.write(`[${SERVICE}] run observability: ${lineValue(where, 40)} ${lineValue(err?.code || err?.name || 'error', 40)} ${mask(String(err?.message ?? '')).replace(/\s+/g, ' ').slice(0, 120)}\n`);
}
export function safely(where, fn) {
  try { return fn(); } catch (err) { reportFailure(where, err); return undefined; }
}

// ---- Engine events ----------------------------------------------------------------------------------------------------------------------------
// The words of a refusal, by the fixed code the engine audited. Fixed text: nothing typed is ever echoed.
const CALL_TURNED_AWAY = {
  no_credential_for_target: ['no-entry', 'the caller has no credential in their own vault for this target, and the gateway never falls back to a shared account'],
  entry_required: ['entry-unnamed', 'the caller has more than one entry for this target and named none'],
  not_found: ['not-in-vault', 'there is no such entry in the caller\'s own vault, and the gateway looks nowhere else'],
  entry_staged_for_delete: ['staged-entry', 'an entry staged for deletion cannot be used'],
  entry_target_mismatch: ['other-target', 'that entry belongs to a different target system'],
  unknown_field: ['bad-request', 'the call carried a field the lab does not take (no call names an owner)'],
};
const DEFAULT_TURN_AWAY = ['bad-request', 'the request did not pass the gateway\'s checks'];
const BACKEND_WHY = [['wrong kind', 'wrong-kind'], ['not recognised', 'not-recognised']];
const GRANT_CODES = new Set(['no_grant', 'read_not_granted', 'write_not_granted']);
const GRANT_CAUSE = { no_grant: 'no-grant', read_not_granted: 'read-not-granted', write_not_granted: 'write-not-granted' };
const STORE_ACTION = /^store\.(create|read|update|rotate|delete|recover|purge)$/;
const iso = (ms) => new Date(ms).toISOString();

const person = (a) => ({
  layer: 'person', product: 'lab roster (no sign-in)', step: 'caller', outcome: 'info', cause: '-', who: a.actor, at: a.at,
  message: `The call was made as ${a.actor} (${a.role}). The lab has no sign-in: the caller is the person chosen in the header, a stand-in for a verified sign-in.`,
  detail: { role: a.role, audit: a.id },
});

function callEvents(a, r) {
  const g = r.gatewayView; const b = r.backendView; const perUser = g.as === 'per-user';
  const names = g.injected.map((h) => h.header);
  const served = b.status === 200;
  const shared = typeof b.principal === 'string' && b.principal.startsWith('svc-');
  const why = BACKEND_WHY.find(([text]) => String(b.outcome).includes(text));
  return [
    person(a),
    { layer: 'agent', product: 'lab simulated agent tool', step: 'agent-ask', outcome: 'info', cause: '-', who: a.actor, at: a.at,
      message: `The simulated agent asked for ${r.agentView.asked} on behalf of ${a.actor}. It holds no credential and was shown ${r.agentView.sees}. It is a simulated tool: there is no OBO token behind it.`,
      detail: { asked: r.agentView.asked, holdsCredential: false, audit: a.id } },
    { layer: 'gateway', product: 'lab simulated gateway', step: 'injection', outcome: 'info', cause: perUser ? 'own-vault' : 'shared-account', who: a.actor, at: a.at,
      message: `The simulated gateway took ${perUser ? `${a.actor}'s own vault entry ${a.resource}` : 'the application\'s shared service account'} and injected ${names.join(', ')} into the call to ${b.target}. An injection is not a decision, and the value is never shown.`,
      detail: { as: g.as, shape: g.shape, headers: names, ...(perUser ? { entry: a.resource } : {}), audit: a.id } },
    { layer: 'resource', product: 'lab simulated backend', step: 'backend', outcome: served ? 'allowed' : 'refused', cause: served ? (shared ? 'shared-identity' : 'caller-identity') : (why ? why[1] : 'other'), who: a.actor, at: a.at,
      message: served
        ? `The simulated backend ${b.target} logged who actually acted: ${b.principal}${shared ? ' (the shared service account: the same identity for every caller)' : ''}, status 200.`
        : `The simulated backend ${b.target} turned the call away with status ${b.status} (${b.outcome}) and logged no principal.`,
      detail: { target: b.target, status: b.status, principal: b.principal, backendLog: b.logLine, audit: a.id } },
  ];
}

function turnedAway(a) {
  const [cause, text] = CALL_TURNED_AWAY[a.code] || DEFAULT_TURN_AWAY;
  return [
    person(a),
    { layer: 'gateway', product: 'lab simulated gateway', step: 'call-turned-away', outcome: 'refused', cause, who: a.actor, at: a.at,
      message: `The simulated gateway turned the call away: ${text}.`, detail: { code: a.code, audit: a.id } },
  ];
}

function grantEvent(a) {
  const verb = a.action.slice('store.'.length);
  const right = verb === 'read' ? 'read' : 'write';
  const where = a.resource.endsWith(':-') ? `that location in ${a.resource.slice(0, -2)}` : a.resource;
  const base = { layer: 'privilege', product: 'lab grant table', step: 'grant-check', who: a.actor, at: a.at, detail: { action: verb, right, resource: a.resource, audit: a.id } };
  if (a.outcome === 'allowed') return { ...base, outcome: 'allowed', cause: 'granted', message: `The grant table allowed ${a.actor} to ${verb} ${where}: a ${right} grant covers it.` };
  if (a.code === 'no_grant') return { ...base, outcome: 'refused', cause: GRANT_CAUSE.no_grant, message: `The grant table has no grant for ${a.actor} on ${where}, so it refuses (default deny). The caller is told it does not exist.` };
  return { ...base, outcome: 'refused', cause: GRANT_CAUSE[a.code], message: `${a.actor} holds a grant on ${where} but not the ${right} grant, so the grant table refuses: read and write are separate grants.` };
}

const editEvent = (a) => ({
  layer: 'privilege', product: 'lab grant table', step: 'grant-edit', outcome: 'info', cause: '-', who: a.actor, at: a.at,
  message: `${a.actor} (${a.role}) ${a.action === 'policy.grant' ? 'added' : 'removed'} grant ${a.resource} in the grant table. An edit is not a decision about an access.`,
  detail: { action: a.action, grant: a.resource, audit: a.id },
});

// The state to remember before an action runs: the audit entries after it are the action's.
export const mark = (e) => ({ audit: e.s.audit.length });

// The events ONE action produced, in the order the engine wrote them. `outcome` is what perform() answered ({ ok, result } or { ok: false, ... }).
export function observeAction(e, { outcome, before }) {
  const out = [];
  for (const a of e.s.audit.slice(before.audit)) {
    if (a.action === 'gateway.call' && outcome.ok) out.push(...callEvents(a, outcome.result));
    else if (a.action === 'gatewayCall') out.push(...turnedAway(a)); // the engine audits a refused op under the op's own name
    else if (STORE_ACTION.test(a.action) && (a.outcome === 'allowed' || (a.outcome === 'denied' && GRANT_CODES.has(a.code)))) out.push(grantEvent(a));
    else if ((a.action === 'policy.grant' || a.action === 'policy.revoke') && a.outcome === 'allowed') out.push(editEvent(a));
  }
  return out;
}

// What a table keeps of an event: the row, not the words of the stdout line.
export const tableEvent = (ev, seq) => ({ seq, at: ev.at, layer: ev.layer, product: ev.product, outcome: ev.outcome, message: ev.message, detail: ev.detail });

// ---- Stdout lines ---------------------------------------------------------------------------------------------------------------------------
export function decisionLine(ev, at, runId, keep = null) {
  const result = ev.noReply ? 'no-reply' : RESULT[ev.outcome];
  return `${at} ${SERVICE} decision step=${lineValue(ev.step)} layer=${lineValue(ev.layer, 12)} actor=${field(ev.who, keep)} result=${result} cause=${lineValue(ev.cause)}${ev.labtime ? ` labtime=${lineValue(ev.labtime, 30)}` : ''} run=${lineValue(runId)}`;
}

// ---- What the lab receives from the Privilege gateway (Real) ----------------------------------------------------------------------------------
const NO_REPLY = /^MCP HTTP request (?:unreachable|timed out)/;
const UNREAD = /^(?:reply larger than|reply is not JSON)/;
const RECEIVED = 'This is the reply the lab received, not a gateway log line.';
const STEP_TEXT = { 'tools/list': 'tools/list', probe: 'the refusal probe (a tool nothing grants)' };

// One call's answer -> an event, or null when there was no reply (a call that did not connect or timed out). Only the answer in hand is read: nothing
// from an earlier call. The gateway's own words are never copied into a row (they are on the page's gateway card, scrubbed of keys).
export function replyOf(step, r) {
  if (!r || typeof r !== 'object') return null;
  const what = STEP_TEXT[step];
  const done = (outcome, cause, message, detail) => ({ outcome, cause, message: `${message} ${RECEIVED}`, detail: { step, ...detail } });
  if (r.ok === true) {
    if (step === 'tools/list') {
      const n = Array.isArray(r.tools) ? r.tools.length : 0;
      return n > 0
        ? done('allowed', 'tools-listed', `The gateway answered ${what} with ${n} tools for the agent key.`, { tools: n, ms: r.ms })
        : done('info', 'empty-list', `The gateway answered ${what} with no tools, so there is no usable tool list to count as a pass.`, { tools: 0, ms: r.ms });
    }
    if (r.isError === true) return done('refused', 'tool-error', `The gateway answered ${what} with a tool error (isError): the call was not carried out.`, { ms: r.ms });
    return typeof r.text === 'string' && r.text.length > 0
      ? done('allowed', 'tool-ran', `The gateway let ${what} through and returned a tool result. A tool nothing grants should be refused: check the gateway policy.`, { ms: r.ms })
      : done('info', 'no-content', `The gateway answered ${what} with no content, so the lab cannot read it as a tool result.`, { ms: r.ms });
  }
  const f = r.refusal && typeof r.refusal === 'object' ? r.refusal : {};
  const status = Number.isInteger(f.status) ? f.status : null;
  if (status === 401) return done('refused', 'status-401', `The gateway answered ${what} with HTTP 401: it did not accept the agent key.`, { status, ms: r.ms });
  if (status === 403) return done('refused', 'status-403', `The gateway answered ${what} with HTTP 403${step === 'probe' ? ', which is what the probe expects' : ''}.`, { status, ms: r.ms });
  if (status !== null) return done('info', `status-${status}`, `The gateway answered ${what} with HTTP ${status}. That status is not a policy verdict, so it is counted as information.`, { status, ms: r.ms });
  const text = String(f.message ?? '');
  if (NO_REPLY.test(text)) return null;
  if (UNREAD.test(text)) return done('info', 'unreadable', `The gateway's answer to ${what} could not be read as a tool result, so it is counted as information.`, { ms: r.ms });
  return done('refused', 'jsonrpc-error', `The gateway answered ${what} with a JSON-RPC error inside a successful HTTP reply: the lab reads that as a refusal.`, { ms: r.ms });
}

// ---- The run log ------------------------------------------------------------------------------------------------------------------------------
// Live: one run per action, lines only (the page's Real record is the gateway hop). Real: one run per gateway check, kept when it ends.
export function createRunLog({ write = (line) => process.stdout.write(`${line}\n`), clock = () => Date.now() } = {}) {
  const part = crypto.randomBytes(3).toString('hex'); // so an id never repeats after a restart, a Reset or in another workspace
  let made = 0;
  let runs = [];
  const stamp = () => iso(clock());

  return {
    // The engine events of one Live action: one line each, stamped when written.
    live(events) {
      if (!events.length) return;
      const id = `act-${part}-${++made}`;
      for (const ev of events) write(decisionLine({ ...ev, labtime: ev.at }, stamp(), id));
    },
    // One gateway check. reply() stamps the moment the lab had the answer, writes its line and keeps the event; end() stores the run.
    beginCheck(caller) {
      const run = { id: `gw-${part}-${++made}`, source: 'real', caller, startedAt: stamp(), endedAt: null, events: [], notes: [] };
      const keep = keepPattern({ actClientId: caller });
      return {
        id: run.id,
        reply(step, result) {
          const at = stamp();
          const r = replyOf(step, result);
          if (!r) {
            run.notes.push(`The ${step === 'probe' ? 'refusal probe' : 'tools/list call'} got no reply (it did not connect, or it timed out), so it has no row.`);
            write(decisionLine({ step: step === 'probe' ? 'gateway-probe' : 'gateway-list', layer: 'gateway', who: caller, noReply: true, cause: 'no-reply' }, at, run.id, keep));
            return;
          }
          const ev = { ...r, at, layer: 'gateway', product: 'Privilege gateway reply', step: step === 'probe' ? 'gateway-probe' : 'gateway-list', who: caller };
          run.events.push(ev);
          write(decisionLine(ev, at, run.id, keep));
        },
        skipped(note) { run.notes.push(note); },
        end() { run.endedAt = stamp(); runs = [...runs, run].slice(-KEEP_RUNS); },
      };
    },
    // The run with this id (when it is still one of the last few), or the newest.
    get: (id) => (id === undefined ? runs.at(-1) : runs.find((r) => r.id === id)) ?? null,
  };
}

// ---- The records -------------------------------------------------------------------------------------------------------------------------------
const WHY_MOCK = {
  person: 'No call was made as a person in this scenario. The lab has no sign-in: a person is only a name chosen in the header.',
  agent: 'The simulated agent made no call in this scenario.',
  authorize: 'This lab does not call PingOne Authorize. The grant table decides, and is shown under Privilege.',
  privilege: 'No store action reached the grant table in this scenario (the vault is self-service and has no grant check).',
  gateway: 'No call went through the simulated gateway in this scenario.',
  resource: 'The simulated backend was not reached in this scenario.',
};
const WHY_REAL = {
  person: 'The lab calls the gateway with an agent access key, not as a person, and it has no sign-in. Nothing here is a person\'s sign-in.',
  agent: 'The caller is an agent access key (a non-human identity), not an OBO token. The gateway\'s own log of that key is not read by this lab.',
  authorize: 'This lab does not call PingOne Authorize.',
  privilege: 'Privilege\'s policy log (its SIEM index and console activity log) is not read by this lab. The vault, the grant table and the backend stay in the lab\'s own engine in Real too: their decisions are on the Governance tab, not in this record.',
  gateway: 'The lab received no reply from the gateway.',
  resource: 'The tool behind the gateway wrote no log the lab can read. The lab\'s own backend is local and is not part of the Real call.',
};

// Ties (the lab clock moves only when the visitor moves it) are put back in the order the events were written; ids are renumbered to match.
function inEventOrder(rec) {
  const stamped = rec.rows.filter((r) => r.at !== null).sort((a, b) => Date.parse(a.at) - Date.parse(b.at) || a.detail.eventSeq - b.detail.eventSeq);
  return { ...rec, rows: [...stamped.map((r, i) => ({ ...r, id: `r${i + 1}` })), ...rec.rows.filter((r) => r.at === null)] };
}

// Mock: the events the engine wrote when the table was generated, for one scenario. null when the vertical has no such scenario.
export async function mockRecord(table, vertical, scenarioId, { clock = Date.now } = {}) {
  const v = table.verticals[vertical];
  const sc = (typeof scenarioId === 'string' && v.scenarios.find((s) => s.id === scenarioId)) || v.scenarios[0];
  const events = Array.isArray(sc.events) ? sc.events : [];
  const first = events[0]?.at ?? sc.state.clock;
  const last = events.at(-1)?.at ?? sc.state.clock;
  const rec = await createRunObservability({ clock }).collectRun({
    runId: `table-${vertical}-${sc.id}`, startedAt: first, endedAt: last, source: 'mock',
    layers: LAYERS.map((layer) => ({
      layer, products: [], reason: WHY_MOCK[layer],
      simulated: events.filter((e) => e.layer === layer).map((e) => ({ at: e.at, product: e.product, outcome: e.outcome, message: e.message, detail: { ...e.detail, eventSeq: e.seq } })),
    })),
  }); // no correlation: nothing is matched against logs here, so no id is declared and names stay readable
  return inEventOrder(rec);
}

// Real: what the lab received from the gateway on one check, as `response` rows. The layers the lab's own engine covers say so.
export async function realRecord(run, { clock = Date.now } = {}) {
  const rec = await createRunObservability({ clock }).collectRun({
    runId: run.id, startedAt: run.startedAt, endedAt: run.endedAt ?? run.startedAt, source: 'real',
    correlation: { actClientId: run.caller },
    layers: LAYERS.map((layer) => ({
      layer, products: [], reason: layer === 'gateway' ? (run.notes.join(' ') || WHY_REAL.gateway) : WHY_REAL[layer],
      responses: layer === 'gateway' ? run.events.map((e, i) => ({ at: e.at, product: e.product, outcome: e.outcome, message: e.message, detail: { ...e.detail, eventSeq: i } })) : [],
    })),
  });
  // A layer that has rows shows no reason of its own, so a call that got no reply or was not sent is named here.
  const note = run.notes.join(' ');
  const out = inEventOrder(rec);
  if (note && run.events.length) out.reasons = { ...out.reasons, gateway: note };
  return out;
}
