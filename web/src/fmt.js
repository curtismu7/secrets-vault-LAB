// Lab-clock times are ISO strings in UTC; the page shows them as "2026-11-02 09:05" and says UTC once, at the clock.
export const t = (iso) => (iso ? String(iso).slice(0, 16).replace("T", " ") : "-");
export const mins = (m) => (m % 1440 === 0 ? `${m / 1440} d` : m % 60 === 0 ? `${m / 60} h` : `${m} min`);
