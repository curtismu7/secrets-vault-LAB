// Lab-clock times are ISO strings in UTC; the page shows them as "2026-11-02 09:05" and says UTC once, at the clock.
export const t = (iso) => (iso ? String(iso).slice(0, 16).replace("T", " ") : "-");
export const left = (m) => { const h = Math.floor(m / 60); const r = m % 60; return h ? `${h} h ${r} min` : `${r} min`; };
export const idOf = (s) => String(s).replace(/[^A-Za-z0-9]+/g, "-");
