import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { DEFAULT_CAST, VERTICALS } from '../src/cast.js';
import { buildStory, renderTalkTrackMarkdown } from '../src/story.js';
import { BANNER, CLAIM_LABEL, CLAIMS, FIELD_SOURCES, TALK_TRACK, WHY } from '../src/data.js';
import { maskDeep } from '../src/mask.js';
import { DIAGRAM_NAMES, buildDiagram, loadDiagram, rawDiagram } from '../src/diagramData.js';
import { validateDiagram } from '../src/diagramStudioValidate.js';

test('the banner says it is simulated and a Ping claim UNVERIFIED on our tenant, and names its mode', () => {
  for (const [mode, re] of [['mock', /MOCK mode/], ['live', /LIVE mode/]]) {
    assert.match(BANNER[mode], /SIMULATED/); assert.match(BANNER[mode], re); assert.match(BANNER[mode], /UNVERIFIED on our tenant/);
  }
  assert.equal(CLAIM_LABEL, 'Ping release claim, UNVERIFIED on our tenant');
});

test('every field is tagged: deck claim, lab reading or lab-invented (and this lab cites no console swagger name)', () => {
  assert.ok(FIELD_SOURCES.length >= 15);
  for (const f of FIELD_SOURCES) { assert.ok(['deck', 'reading', 'invented'].includes(f.source), f.field); assert.ok(f.note.length > 30); }
  const story = buildStory(DEFAULT_CAST, 'finance');
  assert.ok(story.fieldSources.every((f) => f.sourceLabel));
  assert.ok(story.fieldSources.some((f) => f.sourceLabel === 'deck claim') && story.fieldSources.some((f) => f.sourceLabel === 'lab-invented'));
});

test('the story is the deck\'s claims (slides 42, 43 and the read-only 36), never says "door", and links slide 36 in text only', () => {
  const s = buildStory(DEFAULT_CAST, 'finance');
  assert.ok(!/\bdoor\b/i.test(JSON.stringify(s)));
  assert.deepEqual([...new Set(CLAIMS.map((c) => c.slide))].sort(), [36, 42, 43]);
  assert.equal(s.claims.filter((c) => c.slide === 42).length, 5); assert.equal(s.claims.filter((c) => c.slide === 43).length, 4);
  const modes = s.claims.find((c) => c.id === 'modes').claim; for (const w of ['none', 'static token', 'User Vault', 'second OAuth flow', 'token pass-through']) assert.ok(modes.includes(w), w);
  assert.equal(s.providers.length, 5); assert.equal(s.shapes.length, 4);
  assert.ok(s.notDemonstrated.some((n) => /slide 36/.test(n)));
});

test('the talk track has the two Why it matters entries (challenge, technical, business), marked as Ping claims', () => {
  for (const id of ['why-user-vault', 'why-secret-store']) {
    const t = TALK_TRACK.find((x) => x.id === id);
    for (const part of ['Challenge:', 'Technical:', 'Business:']) assert.match(t.say, new RegExp(part));
    assert.match(t.say, /Ping claims, unverified on our tenant/);
  }
  assert.match(WHY.vault.technical, /own credential injected at request time/); assert.match(WHY.stores.challenge, /five secret managers/);
});

test('docs/talk-track.md is exactly what the generator makes (no drift)', () => {
  const file = new URL('../../docs/talk-track.md', import.meta.url);
  assert.equal(fs.readFileSync(file, 'utf8'), renderTalkTrackMarkdown(DEFAULT_CAST));
  assert.ok(!/\{\{/.test(fs.readFileSync(file, 'utf8')));
});

test('the response mask leaves every vertical\'s story untouched (it must only change credential-shaped values)', () => {
  for (const [v, c] of Object.entries(VERTICALS)) { const s = buildStory(c, v); assert.deepEqual(maskDeep(s), s, v); }
});

test('the diagrams are diagram-studio/1 data, valid, loaded by name, with no overlapping node positions', () => {
  assert.deepEqual(DIAGRAM_NAMES, ['vault-request-time', 'secret-store-no-copy']);
  for (const n of DIAGRAM_NAMES) {
    assert.deepEqual(validateDiagram(loadDiagram(n)), []);
    const d = rawDiagram(n);
    assert.equal(d.schema, 'diagram-studio/1');
    const boxes = d.nodes.map((x) => ({ x: x.x, y: x.y }));
    for (let i = 0; i < boxes.length; i++) for (let j = i + 1; j < boxes.length; j++) assert.ok(Math.abs(boxes[i].x - boxes[j].x) >= 260 || Math.abs(boxes[i].y - boxes[j].y) >= 130, `${n}: ${d.nodes[i].id} and ${d.nodes[j].id} overlap`);
    assert.equal(d.steps.length, d.edges.length, 'every edge is a step');
    const b = buildDiagram(DEFAULT_CAST, n);
    assert.ok(b.steps.every((s) => s.label.length <= 24), 'edge labels are short enough not to collide');
    assert.ok(!/\{\{/.test(JSON.stringify(b)));
  }
  assert.equal(buildDiagram(DEFAULT_CAST, 'nope').name, 'vault-request-time', 'an unknown name falls back');
  assert.ok(validateDiagram({ ...rawDiagram('vault-request-time'), schema: 'x' }).length > 0);
});
