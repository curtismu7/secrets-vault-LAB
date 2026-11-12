import { useCallback, useEffect, useRef, useState } from "react";
import ShelfLink from "./components/ShelfLink";
import TopMenu, { applyFontSize } from "./top-menu/TopMenu.jsx";
import VaultTab from "./components/VaultTab";
import InjectionTab from "./components/InjectionTab";
import StoresTab from "./components/StoresTab";
import GovernanceTab from "./components/GovernanceTab";
import DiagramTab from "./components/DiagramTab";
import TalkTrack from "./components/TalkTrack";
import LastAction from "./components/LastAction";
import ClockBar from "./components/ClockBar";
import ScenarioBar from "./components/ScenarioBar";
import ErrorBoundary from "./components/ErrorBoundary";
import useLab from "./hooks/useLab";
import { getJson, resetWorkspace, setMode } from "./api";
import { setActor } from "./workspace";

export const TABS = [
  { id: "vault", label: "User Vault" },
  { id: "injection", label: "Request-time injection" },
  { id: "stores", label: "Secret Stores" },
  { id: "governance", label: "Governance" },
  { id: "diagram", label: "Diagram" },
  { id: "talk", label: "Talk track" },
];
// The banner is never blank and never claims one mode before it knows: until the story answers it says both, honestly.
const TAIL = "Every product claim is a Ping release claim, UNVERIFIED on our tenant (release 2026-11-02). Nothing here calls a real secret manager, key service, gateway, backend or tenant, and every credential is a lab mock.";
export const BANNER_UNKNOWN = `SIMULATED, MOCK or LIVE mode (loopback only, no outbound network). ${TAIL}`;
const PRESENTER_TALK = { vault: ["say-first", "own-vault", "no-override", "encrypted", "safe-editing", "staged-delete", "bounded"], injection: ["request-time", "slide-36"], stores: ["stores"], governance: ["governed", "no-copy", "resync"], diagram: ["why-user-vault", "why-secret-store"] };
const MODE_KEY = "svl.mode";
const THEME_KEY = "svl.theme";
const THEMES = ["auto", "light", "dark"];
function initialTheme() {
  try { const t = localStorage.getItem(THEME_KEY); if (THEMES.includes(t)) return t; } catch { /* storage blocked */ }
  return "auto";
}
const FONT_KEY = "svl.font";
function initialFontStep() {
  try { const f = localStorage.getItem(FONT_KEY); return ["S", "M", "L"].includes(f) ? f : "M"; } catch { return "M"; }
}
const LIVE_TABS = ["vault", "injection", "stores", "governance"];

const tabFromHash = () => { const h = window.location.hash.replace("#", ""); return TABS.some((t) => t.id === h) ? h : "vault"; };
const savedMode = () => { try { const m = window.localStorage.getItem(MODE_KEY); return m === "live" || m === "mock" ? m : null; } catch { return null; } };
const rosterOf = (c) => [[c.castUser, "user"], [c.castUser2, "user"], [c.castAdmin, "admin"], [c.castAuditor, "auditor"], [c.castSupport, "support"]];

export default function App() {
  const [vertical, setVertical] = useState("finance");
  const [story, setStory] = useState(null);
  const [mode, setModeState] = useState(null);
  const [scenarioId, setScenarioId] = useState(null);
  const [actor, setActorState] = useState(null);
  const [error, setError] = useState(null);
  const [tab, setTab] = useState(tabFromHash());
  const [presenter, setPresenter] = useState(false);
  const [resetSignal, setResetSignal] = useState(0);
  const [resetMsg, setResetMsg] = useState("");
  const [theme, setTheme] = useState(initialTheme);
  const [fontStep, setFontStep] = useState(initialFontStep);
  const [infoVersion, setInfoVersion] = useState(null);
  const tabsRef = useRef(null);

  useEffect(() => { getJson("/api/info").then((i) => setInfoVersion(i.version || null)).catch(() => setInfoVersion(null)); }, []);

  useEffect(() => { if (theme === "auto") delete document.documentElement.dataset.theme; else document.documentElement.dataset.theme = theme; }, [theme]);
  useEffect(() => {
    applyFontSize(fontStep);
    try { localStorage.setItem(FONT_KEY, fontStep); } catch { /* not remembered */ }
  }, [fontStep]);
  // Nothing is loaded in Live until the person belongs to the roster of the vertical being shown: a stale person from the previous vertical would be a
  // spurious 401 (and a flash of an error). The story of the new vertical sets the person, and only then does the first request go out.
  const storyReady = !!story && story.vertical === vertical;
  const actorOk = storyReady && rosterOf(story.cast).some(([id]) => id === actor);
  setActor(mode === "live" && actorOk ? actor : null);
  const lab = useLab({ mode, vertical, scenario: scenarioId, actor: actorOk ? actor : null });

  useEffect(() => { getJson("/api/info").then((i) => setModeState((m) => m || savedMode() || i.mode), () => setModeState((m) => m || savedMode() || "mock")); }, []);
  useEffect(() => {
    let live = true; // a late story for a vertical the visitor has already left is dropped
    getJson(`/api/story?vertical=${encodeURIComponent(vertical)}`).then((j) => { if (live) { setStory(j); setError(null); setActorState((a) => (rosterOf(j.cast).some(([id]) => id === a) ? a : j.cast.castUser)); } }, (e) => { if (live) setError(e.message); });
    return () => { live = false; };
  }, [vertical]);
  useEffect(() => {
    const on = () => setTab(tabFromHash());
    window.addEventListener("hashchange", on);
    return () => window.removeEventListener("hashchange", on);
  }, []);
  const applyMode = (m) => { setModeState(m); try { window.localStorage.setItem(MODE_KEY, m); } catch { /* storage blocked */ } };
  // Rule 19: the Mock/Real toggle POSTs the source to the server's runtime mode, then reloads the page's data.
  // A refusal (the 409 body) is data, not an exception; it is shown where the reset note is shown.
  const switchSource = useCallback(async (source) => {
    const next = source === "real" ? "live" : "mock";
    if (next === mode) return;
    const r = await setMode(source);
    if (!r.ok) { setResetMsg(r.body?.detail || r.body?.message || `Could not switch to ${source}.`); return; }
    applyMode(next);
    setResetSignal((n) => n + 1);
    await lab.reload(next === "real" ? "live" : "mock");
  }, [mode, lab.reload]); // eslint-disable-line react-hooks/exhaustive-deps
  const pickTheme = (next) => {
    try { if (next === "auto") localStorage.removeItem(THEME_KEY); else localStorage.setItem(THEME_KEY, next); } catch { /* not remembered */ }
    setTheme(next);
  };
  const select = (id) => { setTab(id); try { window.history.replaceState(null, "", `#${id}`); } catch { /* ignore */ } };

  // Keep the active tab fully in view in the scrolling tab strip (375px).
  useEffect(() => {
    const strip = tabsRef.current; const el = document.getElementById(`tab-${tab}`);
    if (!strip || !el) return;
    const left = el.offsetLeft - strip.offsetLeft;
    if (left < strip.scrollLeft || left + el.offsetWidth > strip.scrollLeft + strip.clientWidth) strip.scrollLeft = Math.max(0, left - 8);
  }, [tab]);

  useEffect(() => {
    const on = (e) => {
      if (e.target && /^(INPUT|TEXTAREA|SELECT)$/.test(e.target.tagName)) return;
      if (e.key === "p" || e.key === "P") setPresenter((v) => !v);
      else if (e.key === "Escape") setPresenter(false);
    };
    window.addEventListener("keydown", on);
    return () => window.removeEventListener("keydown", on);
  }, []);

  // Reset: the server clears this workspace's engines (vault, inventory, providers, audit and the clock); the diagram goes back in place; the view reloads.
  const reset = useCallback(async () => {
    const ok = await resetWorkspace().catch(() => false);
    setResetSignal((n) => n + 1);
    await lab.reload();
    setResetMsg(ok ? "Reset: your workspace's vault, secret inventory, grants, audit trail and the lab clock are back to the start, and the diagram is back in place." : "Reset failed on the server; the view was reloaded.");
  }, [lab.reload]); // eslint-disable-line react-hooks/exhaustive-deps

  const onKeyTab = (e, i) => {
    if (e.key !== "ArrowRight" && e.key !== "ArrowLeft") return;
    const next = TABS[(i + (e.key === "ArrowRight" ? 1 : TABS.length - 1)) % TABS.length];
    select(next.id);
    document.getElementById(`tab-${next.id}`)?.focus();
  };

  const banner = story && mode ? story.banner[mode] : BANNER_UNKNOWN;
  const ready = story && mode && lab.state;
  const props = { story, mode, vertical, lab };
  const roster = story ? rosterOf(story.cast) : [];
  return (
    <div className={`app${presenter ? " app--presenter" : ""}`}>
      <header>
        <p className="banner" role="status" data-state={mode === "live" ? "live" : "mock"} data-testid="banner">{banner}</p>
        <div className="head">
          <div>
            <h1 className="head__title">Secrets Vault LAB</h1>
            {!presenter && story && <p className="head__intro">{story.intro}</p>}
          </div>
          <div className="head__tools">
            <TopMenu
              mode={{ value: mode === "live" || mode === "real" ? "real" : "mock", onChange: switchSource, realAvailable: true }}
              vertical={{ value: vertical, onChange: setVertical, options: story ? story.verticals : ["finance"] }}
              theme={{ value: theme, onChange: pickTheme }}
              fontSize={{ value: fontStep, onChange: setFontStep }}
              present={{ active: presenter, onToggle: () => setPresenter((v) => !v), label: "Presenter (P)" }}
              help={{ href: "https://github.com/curtismu7/secrets-vault-LAB#readme" }}
              version={infoVersion}
              onReset={reset}
            >
              <ShelfLink />
            </TopMenu>
            <span className="chip" data-testid="mode">Mode: {mode || "..."}{mode === "live" ? " (local engine, loopback)" : mode === "mock" ? " (tables)" : ""}</span>
            {!presenter && story && (
              <label className="inline">Acting as{" "}
                <select value={mode === "live" ? (actorOk ? actor : "") : lab.scenario?.actor || ""} disabled={mode !== "live" || !actorOk} onChange={(e) => setActorState(e.target.value)} data-testid="actor">
                  {(mode === "live" ? roster : roster.filter(([id]) => id === lab.scenario?.actor)).map(([id, role]) => <option key={id} value={id}>{id} ({role})</option>)}
                </select>
              </label>
            )}
          </div>
        </div>
      </header>
      <main>
        <p className="sr-only" role="status" aria-live="polite">{resetMsg}</p>
        <div role="tablist" aria-label="Lab sections" className="tabs" ref={tabsRef}>
          {TABS.map((t, i) => (
            <button key={t.id} id={`tab-${t.id}`} role="tab" type="button" aria-selected={tab === t.id} aria-controls={`panel-${t.id}`} tabIndex={tab === t.id ? 0 : -1}
              onClick={() => select(t.id)} onKeyDown={(e) => onKeyTab(e, i)}>{t.label}</button>
          ))}
        </div>
        <div id={`panel-${tab}`} role="tabpanel" aria-labelledby={`tab-${tab}`}>
          {error || lab.error ? <p className="app-error" role="alert">Could not load the lab ({error || lab.error}). Is the server running?</p> : !ready ? <p className="muted">Loading...</p> : (
            <ErrorBoundary key={`${vertical}|${mode}|${actorOk ? actor : "-"}|${tab}`}>
              {mode === "mock" && LIVE_TABS.includes(tab) && <ScenarioBar lab={lab} scenarioId={scenarioId} setScenarioId={setScenarioId} />}
              {mode === "live" && LIVE_TABS.includes(tab) && <ClockBar state={lab.state} lab={lab} />}
              {presenter && tab !== "talk" && (
                <aside className="presenter-say" data-testid="presenter-say" aria-label="Talk track">
                  {story.talkTrack.filter((t) => (PRESENTER_TALK[tab] || []).includes(t.id)).map((t) => <p key={t.id}><strong>{t.title}.</strong> {t.say}</p>)}
                </aside>
              )}
              {tab === "vault" && <VaultTab {...props} />}
              {tab === "injection" && <InjectionTab {...props} />}
              {tab === "stores" && <StoresTab {...props} />}
              {tab === "governance" && <GovernanceTab {...props} />}
              {tab === "diagram" && <DiagramTab vertical={vertical} resetSignal={resetSignal} />}
              {tab === "talk" && <TalkTrack talk={story.talkTrack} />}
              {mode === "live" && LIVE_TABS.includes(tab) && <LastAction last={lab.last} />}
            </ErrorBoundary>
          )}
        </div>
      </main>
    </div>
  );
}
