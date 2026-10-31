import { useCallback, useEffect, useState } from "react";
export const DEFAULT_STEP_MS = 2500;
export const STEP_TIME_OPTIONS = [
  { value: 800, label: "0.8s (fast)" },
  { value: 1500, label: "1.5s" },
  { value: 2500, label: "2.5s (default)" },
  { value: 4000, label: "4s" },
  { value: 6000, label: "6s (slow)" },
];

/**
 * Step state for a React Flow diagram that walks its arrows in order. step === -1 means the walkthrough is off and the diagram looks as it
 * always did; 0..total-1 is the arrow in focus.
 *
 * The shape matches DiagramControls: Simulate starts it playing, Pause/Resume
 * toggle auto-advance, Prev/Next work while paused, Stop returns to off.
 */
export function useDiagramStepper(total) {
  const [step, setStep] = useState(-1);
  const [paused, setPaused] = useState(false);
  const [stepMs, setStepMs] = useState(DEFAULT_STEP_MS);
  const last = total - 1;

  useEffect(() => {
    if (step < 0 || paused) return undefined;
    if (step >= last) {
      setPaused(true);
      return undefined;
    }
    const id = setTimeout(() => setStep((s) => s + 1), stepMs);
    return () => clearTimeout(id);
  }, [step, paused, stepMs, last]);

  useEffect(() => {
    if (step > last) setStep(-1);
  }, [step, last]);

  const simulate = useCallback(() => {
    if (total < 1) return;
    setPaused(false);
    setStep(0);
  }, [total]);
  const resume = useCallback(() => {
    if (step >= last) setStep(0);
    setPaused(false);
  }, [step, last]);
  const next = useCallback(() => setStep((s) => Math.min(s + 1, last)), [last]);
  const prev = useCallback(() => setStep((s) => Math.max(s - 1, 0)), []);
  // jump straight to a step (a click on the movie reel) and stop auto-advance there
  const goTo = useCallback(
    (i) => {
      setPaused(true);
      setStep(Math.max(0, Math.min(i, last)));
    },
    [last],
  );
  const pause = useCallback(() => setPaused(true), []);
  const stop = useCallback(() => {
    setStep(-1);
    setPaused(false);
  }, []);

  return {
    step,
    total,
    active: step >= 0,
    paused,
    stepMs,
    setStepMs,
    simulate,
    resume,
    next,
    prev,
    goTo,
    pause,
    stop,
  };
}

