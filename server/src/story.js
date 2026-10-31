import { fillDeep, VERTICALS } from './cast.js';
import { BANNER, CLAIMS, CLAIM_LABEL, FIELD_SOURCES, FIELD_SOURCE_NAMES, INTRO, LIMITS_TEXT, NOT_DEMONSTRATED, RELEASE, TALK_TRACK, TITLE, WHY } from './data.js';
import { LIMITS, ADVANCE_MAX_MIN, NIGHTLY_HOUR_UTC, PURGE_AFTER_MS } from './engine.js';
import { SHAPES, SHAPE_TEXT } from './gateway.js';
import { PROVIDERS, PROVIDER_IDS } from './stores.js';
import { scenarioList } from './scenarios.js';

export const rawStory = () => ({ title: TITLE, intro: INTRO, banner: BANNER, claims: CLAIMS, talkTrack: TALK_TRACK, why: WHY });

// The story with the cast filled in.
export function buildStory(cast, vertical) {
  const s = fillDeep(rawStory(), cast);
  return {
    title: s.title, intro: s.intro, release: RELEASE, claimLabel: CLAIM_LABEL, banner: s.banner, claims: s.claims, why: s.why, notDemonstrated: NOT_DEMONSTRATED,
    fieldSources: FIELD_SOURCES.map((f) => ({ ...f, sourceLabel: FIELD_SOURCE_NAMES[f.source] })), limitsText: LIMITS_TEXT,
    limits: { ...LIMITS, advanceMaxMin: ADVANCE_MAX_MIN, purgeAfterMs: PURGE_AFTER_MS, nightlyHourUtc: NIGHTLY_HOUR_UTC },
    shapes: SHAPES.map((id) => ({ id, text: SHAPE_TEXT[id] })),
    providers: PROVIDER_IDS.map((id) => ({ id, name: PROVIDERS[id].name, structure: PROVIDERS[id].structure, softDelete: PROVIDERS[id].softDelete, purge: PROVIDERS[id].purge, fileFields: PROVIDERS[id].fileFields })),
    scenarios: scenarioList(cast).map((sc) => ({ id: sc.id, title: sc.title, say: sc.say })),
    talkTrack: s.talkTrack, cast, vertical, verticals: Object.keys(VERTICALS),
  };
}

// docs/talk-track.md is generated from the same data the UI reads (`npm run talk-track`); a test fails if they drift.
export function renderTalkTrackMarkdown(cast) {
  const s = buildStory(cast, 'finance');
  const parts = ['# Talk track', '', '<!-- Generated from server/src/data.js by `npm run talk-track`. Do not edit by hand. -->', '', `> ${s.claimLabel}: every product claim here comes from the Ping ID4AI Workforce H2 2026 deck, slides 42 and 43 (and 36, 35), release ${s.release}.`, ''];
  for (const t of s.talkTrack) parts.push(`## ${t.title}`, '', t.say, '');
  parts.push('## The seven scripted scenarios (Mock mode)', '');
  s.scenarios.forEach((sc, i) => parts.push(`${i + 1}. **${sc.title}.** ${sc.say}`));
  parts.push('', '## Not demonstrated', '');
  for (const n of s.notDemonstrated) parts.push(`- ${n}`);
  return `${parts.join('\n')}\n`;
}
