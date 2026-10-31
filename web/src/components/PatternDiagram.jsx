import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Background, BackgroundVariant, BaseEdge, Controls, EdgeLabelRenderer, getBezierPath, Handle, MarkerType, Position, ReactFlow, ReactFlowProvider } from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { useDiagramStepper, STEP_TIME_OPTIONS } from "../hooks/useDiagramStepper";
import { REFIT_EVENT, useFitOnResize } from "../hooks/useFitOnResize";
import { ClaimTag } from "./Bits";

const FIT = { padding: 0.08 };
// At phone width fitting the whole wide diagram makes the text unreadable, so the view is held at 0.8 on the first two boxes (node text is enlarged in app.css);
// drag the canvas to pan, drag a box to move it.
const narrow = () => typeof window !== "undefined" && typeof window.matchMedia === "function" && window.matchMedia("(max-width: 600px)").matches;
const HANDLES = [["t", Position.Top], ["b", Position.Bottom], ["l", Position.Left], ["r", Position.Right]];

function Box({ data }) {
  return (
    <div className="pat-node" data-kind={data.kind} data-on={data.on ? "true" : "false"}>
      {HANDLES.map(([k, pos]) => (
        <span key={k}>
          <Handle id={`s-${k}`} type="source" position={pos} className="pat-handle" />
          <Handle id={`t-${k}`} type="target" position={pos} className="pat-handle" />
        </span>
      ))}
      {data.label}
    </div>
  );
}
const nodeTypes = { box: Box };

// An edge that draws its own label, so a reply along the same pair of boxes can sit above or below its partner instead of on top of it.
function LabelEdge({ id, sourceX, sourceY, targetX, targetY, sourcePosition, targetPosition, markerEnd, data }) {
  const [path, lx, ly] = getBezierPath({ sourceX, sourceY, targetX, targetY, sourcePosition, targetPosition });
  return (
    <>
      <BaseEdge id={id} path={path} markerEnd={markerEnd} />
      <EdgeLabelRenderer>
        <div className="pat-elabel" data-now={data.now ? "true" : "false"} data-dim={data.dim ? "true" : "false"} data-testid="edge-label"
          style={{ transform: `translate(-50%, -50%) translate(${lx}px, ${ly + data.dy}px)` }}>{data.text}</div>
      </EdgeLabelRenderer>
    </>
  );
}
const edgeTypes = { label: LabelEdge };

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

function Canvas({ pattern, positions, onMove, stepper }) {
  const ref = useRef(null);
  const fit = useMemo(() => (narrow() ? { padding: 0.1, minZoom: 0.8, maxZoom: 0.8, nodes: pattern.nodes.slice(0, 2).map((n) => ({ id: n.id })) } : FIT), [pattern]);
  useFitOnResize(ref, fit);
  const active = stepper.step >= 0 ? pattern.steps[stepper.step] : null;
  const nodes = pattern.nodes.map((n) => ({
    id: n.id, type: "box", position: positions[n.id], draggable: true,
    data: { label: n.label, kind: n.kind, on: !!active && (active.from === n.id || active.to === n.id) },
  }));
  const offs = labelOffsets(pattern.steps);
  const edges = pattern.steps.map((s, i) => {
    let [a, b] = sides(positions[s.from], positions[s.to]);
    if (pattern.steps.slice(0, i).some((o) => o.from === s.to && o.to === s.from)) [a, b] = a === "l" || a === "r" ? ["b", "b"] : ["r", "r"];
    const now = stepper.step === i;
    const seen = stepper.step >= 0 && i <= stepper.step;
    return {
      id: `e${i}`, source: s.from, target: s.to, sourceHandle: `s-${a}`, targetHandle: `t-${b}`, type: "label",
      animated: now, data: { text: `${i + 1}. ${s.label}`, dy: offs[i], now, dim: stepper.step >= 0 && !seen },
      className: `pat-edge${now ? " pat-edge--now" : ""}${stepper.step >= 0 && !seen ? " pat-edge--dim" : ""}`,
      markerEnd: { type: MarkerType.ArrowClosed },
    };
  });
  return (
    <div ref={ref} className="pat-canvas" data-testid="pattern-canvas">
      <ReactFlow nodes={nodes} edges={edges} nodeTypes={nodeTypes} edgeTypes={edgeTypes} fitView fitViewOptions={fit} nodesConnectable={false} minZoom={0.3}
        onNodeDragStop={(_, n) => onMove(n.id, n.position)} onNodeDrag={(_, n) => onMove(n.id, n.position)} proOptions={{ hideAttribution: true }}>
        <Background variant={BackgroundVariant.Dots} gap={18} />
        <Controls showInteractive={false} />
      </ReactFlow>
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
        {!active ? <button type="button" onClick={stepper.simulate} data-testid="simulate">Simulate</button> : (
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
  const onMove = useCallback((id, p) => setPositions((cur) => ({ ...cur, [id]: { x: p.x, y: p.y } })), []);
  const step = stepper.step >= 0 ? pattern.steps[stepper.step] : null;
  // Reset restores box positions as well as the walkthrough and the view. The page-level Reset raises resetSignal.
  const reset = useCallback(() => { stepper.stop(); setPositions(initial); setTimeout(() => window.dispatchEvent(new Event(REFIT_EVENT)), 0); }, [stepper.stop, initial]); // eslint-disable-line react-hooks/exhaustive-deps
  const seen = useRef(resetSignal);
  useEffect(() => { if (seen.current !== resetSignal) { seen.current = resetSignal; reset(); } }, [resetSignal, reset]);
  return (
    <section className="pat" aria-label={pattern.title}>
      <h2 className="pat__title">{pattern.title} <ClaimTag /></h2>
      <p className="head__intro">{pattern.intro}</p>
      <Controls2 stepper={stepper} onReset={reset} caption={step ? step.label : ""} />
      {step && (
        <article className="panel" data-testid="pattern-now">
          <h3 className="panel__sub">Step {stepper.step + 1}: {step.label}</h3>
          <p>{step.say}</p>
        </article>
      )}
      <ReactFlowProvider>
        <Canvas pattern={pattern} positions={positions} onMove={onMove} stepper={stepper} />
      </ReactFlowProvider>
      <p className="muted">Drag any box; drag the background to pan. Simulated; hosts are examples; Ping release claims UNVERIFIED on our tenant. Moved: {Object.keys(positions).filter((k) => positions[k].x !== initial[k].x || positions[k].y !== initial[k].y).length} box(es).</p>
    </section>
  );
}
