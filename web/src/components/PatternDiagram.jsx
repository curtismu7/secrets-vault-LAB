import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Background, BackgroundVariant, Controls, Handle, MarkerType, Position, ReactFlow, ReactFlowProvider } from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { useDiagramStepper, STEP_TIME_OPTIONS } from "../hooks/useDiagramStepper";
import { REFIT_EVENT, useFitOnResize } from "../hooks/useFitOnResize";
import { ClaimTag } from "./Bits";
import { ArrowNoLabel, EdgeLabels, FitOpen, Passport, PassportActions } from "../diagram-kit/DiagramKit.jsx";
import { boxPassport, sidePoint } from "../diagram-kit/diagramKit.js";
import "../diagram-kit/diagram-kit.css";

const FIT = { padding: 0.08 };
const HANDLES = [["t", Position.Top], ["b", Position.Bottom], ["l", Position.Left], ["r", Position.Right]];

function Box({ data }) {
  return (
    <div className={`pat-node${data.passport ? " dk-open" : ""}`} data-kind={data.kind} data-on={data.on ? "true" : "false"} data-testid={`pat-node-${data.id}`}>
      {HANDLES.map(([k, pos]) => (
        <span key={k}>
          <Handle id={`s-${k}`} type="source" position={pos} className="pat-handle" />
          <Handle id={`t-${k}`} type="target" position={pos} className="pat-handle" />
        </span>
      ))}
      {data.label}
      {data.passport && <Passport p={data.passport} />}
    </div>
  );
}
const nodeTypes = { box: Box };

// The arrow draws the curve only: every label is drawn by EdgeLabels, above the boxes, placed clear of the other labels and the boxes.
const edgeTypes = { arrow: ArrowNoLabel };

// Steps that run along the same pair of boxes in opposite directions get opposite nudges (-16 and +16 px).
export function labelOffsets(steps) {
  return steps.map((s, i) => {
    if (steps.slice(0, i).some((o) => o.from === s.to && o.to === s.from)) return 16;
    return steps.slice(i + 1).some((o) => o.from === s.to && o.to === s.from) ? -16 : 0;
  });
}

// Pick the sides of the two boxes that face each other, so an arrow leaves toward its target.
function sides(a, b) {
  const dx = b.x - a.x, dy = b.y - a.y;
  return Math.abs(dx) > Math.abs(dy) ? (dx > 0 ? ["r", "l"] : ["l", "r"]) : (dy > 0 ? ["b", "t"] : ["t", "b"]);
}

function Canvas({ pattern, graph, positions, onMove, stepper, open, setOpen }) {
  const ref = useRef(null);
  const fit = FIT; // the whole diagram is always fitted; at phone width the canvas is wider than the screen and scrolls sideways inside its own box (see .pat-scroll)
  useFitOnResize(ref, fit);
  const active = stepper.step >= 0 ? pattern.steps[stepper.step] : null;
  const nodes = pattern.nodes.map((n) => ({
    id: n.id, type: "box", position: positions[n.id], draggable: true, zIndex: n.id === open ? 10 : undefined, // an expanded box sits above its neighbours
    data: { id: n.id, label: n.label, kind: n.kind, on: !!active && (active.from === n.id || active.to === n.id), passport: n.id === open ? boxPassport(graph, n.id) : null },
  }));
  const offs = labelOffsets(pattern.steps);
  const edges = pattern.steps.map((s, i) => {
    let [a, b] = sides(positions[s.from], positions[s.to]);
    if (pattern.steps.slice(0, i).some((o) => o.from === s.to && o.to === s.from)) [a, b] = a === "l" || a === "r" ? ["b", "b"] : ["r", "r"];
    const now = stepper.step === i;
    const seen = stepper.step >= 0 && i <= stepper.step;
    return {
      id: `e${i}`, source: s.from, target: s.to, sourceHandle: `s-${a}`, targetHandle: `t-${b}`, type: "arrow",
      animated: now,
      className: `pat-edge${now ? " pat-edge--now" : ""}${stepper.step >= 0 && !seen ? " pat-edge--dim" : ""}`,
      markerEnd: { type: MarkerType.ArrowClosed },
    };
  });
  // One label per arrow, in a layer above the boxes. A reply along the same pair of boxes starts a little above or below its partner (labelOffsets).
  const labels = pattern.steps.map((s, i) => ({
    id: `e${i}`, text: `${i + 1}. ${s.label}`, source: s.from, target: s.to, sourceHandle: edges[i].sourceHandle, targetHandle: edges[i].targetHandle,
    active: stepper.step === i, dim: stepper.step >= 0 && !(i <= stepper.step), prefer: offs[i],
  }));
  // What an expanded box can do: open the box at the far end of an arrow, close itself, and make a link that opens this page with the box expanded.
  const actions = useMemo(() => ({
    open: (id) => setOpen(id), close: () => setOpen(null),
    link: (id) => { const u = new URL(window.location.href); u.searchParams.set("box", id); return u.toString(); },
  }), [setOpen]);
  return (
    <div ref={ref} className="pat-canvas" data-testid="pattern-canvas">
      <PassportActions.Provider value={actions}>
        <ReactFlow nodes={nodes} edges={edges} nodeTypes={nodeTypes} edgeTypes={edgeTypes} fitView fitViewOptions={fit} nodesConnectable={false} minZoom={0.3}
          onNodeClick={(_, n) => setOpen((o) => (o === n.id ? null : n.id))} onPaneClick={() => setOpen(null)}
          onNodeDragStop={(_, n) => onMove(n.id, n.position)} onNodeDrag={(_, n) => onMove(n.id, n.position)} proOptions={{ hideAttribution: true }}>
          <Background variant={BackgroundVariant.Dots} gap={18} />
          <Controls showInteractive={false} />
          <EdgeLabels items={labels} pointFor={(box, handle) => sidePoint(box, String(handle).split("-")[1])} fallback={{ w: 150, h: 56 }} />
          <FitOpen open={open} closePadding={FIT.padding} />
        </ReactFlow>
      </PassportActions.Provider>
    </div>
  );
}

// Simulate, pause, step, speed, stop; and Reset (positions and walkthrough).
function Controls2({ stepper, onReset, caption }) {
  const { step, total, active, paused } = stepper;
  return (
    <div className="dstep" data-testid="pattern-step-bar">
      <div className="dstep__row">
        <label className="inline">Step time{" "}
          <select value={stepper.stepMs} onChange={(e) => stepper.setStepMs(Number(e.target.value))} disabled={active && !paused} data-testid="speed">
            {STEP_TIME_OPTIONS.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
          </select>
        </label>
        {!active ? <button type="button" className="primary" onClick={stepper.simulate} data-testid="simulate">Simulate</button> : (
          <>
            <button type="button" onClick={stepper.prev} disabled={!paused}>Prev</button>
            {paused ? <button type="button" onClick={stepper.resume}>Resume</button> : <button type="button" onClick={stepper.pause}>Pause</button>}
            <button type="button" onClick={stepper.next} disabled={!paused}>Next</button>
            <button type="button" onClick={stepper.stop}>Stop</button>
          </>
        )}
        <button type="button" onClick={onReset} data-testid="pattern-reset">Reset positions and walkthrough</button>
      </div>
      <p className="dstep__caption" aria-live="polite">{active ? <><strong>Step {step + 1} of {total}</strong>{caption ? ` : ${caption}` : ""}</> : `Simulate walks the ${total} arrows in order.`}</p>
    </div>
  );
}

export default function PatternDiagram({ pattern, resetSignal = 0 }) {
  const initial = useMemo(() => Object.fromEntries(pattern.nodes.map((n) => [n.id, { x: n.x, y: n.y }])), [pattern]);
  const [positions, setPositions] = useState(initial);
  const stepper = useDiagramStepper(pattern.steps.length);
  // The pattern as a graph (boxes and arrows) for the box details; a box's kind is its group.
  const graph = useMemo(() => ({ nodes: pattern.nodes.map((n) => ({ id: n.id, label: n.label, group: n.kind })), edges: pattern.steps.map((st, i) => ({ source: st.from, target: st.to, label: `${i + 1}. ${st.label}` })) }), [pattern]);
  const [open, setOpen] = useState(() => { const box = new URLSearchParams(window.location.search).get("box"); return box && pattern.nodes.some((n) => n.id === box) ? box : null; }); // a shared link's box
  const onMove = useCallback((id, p) => setPositions((cur) => ({ ...cur, [id]: { x: p.x, y: p.y } })), []);
  const step = stepper.step >= 0 ? pattern.steps[stepper.step] : null;
  // Reset restores box positions as well as the walkthrough and the view. The page-level Reset raises resetSignal.
  const reset = useCallback(() => { stepper.stop(); setPositions(initial); setOpen(null); setTimeout(() => window.dispatchEvent(new Event(REFIT_EVENT)), 0); }, [stepper.stop, initial]); // eslint-disable-line react-hooks/exhaustive-deps
  const seen = useRef(resetSignal);
  useEffect(() => { if (seen.current !== resetSignal) { seen.current = resetSignal; reset(); } }, [resetSignal, reset]);
  return (
    <section className="pat" aria-label={pattern.title}>
      <h2 className="pat__title">{pattern.title} <ClaimTag /></h2>
      <p className="muted">{pattern.intro}</p>
      <Controls2 stepper={stepper} onReset={reset} caption={step ? step.label : ""} />
      {step && (
        <article className="panel" data-testid="pattern-now">
          <h3 className="panel__sub">Step {stepper.step + 1}: {step.label}</h3>
          <p>{step.say}</p>
        </article>
      )}
      <div className="pat-scroll" data-testid="pattern-scroll">
        <ReactFlowProvider>
          <Canvas pattern={pattern} graph={graph} positions={positions} onMove={onMove} stepper={stepper} open={open} setOpen={setOpen} />
        </ReactFlowProvider>
      </div>
      <p className="muted">Drag any box; drag the background to pan (on a phone the picture scrolls sideways). Simulated; hosts are examples; Ping release claims UNVERIFIED on our tenant. Moved: {Object.keys(positions).filter((k) => positions[k].x !== initial[k].x || positions[k].y !== initial[k].y).length} box(es).</p>
    </section>
  );
}
